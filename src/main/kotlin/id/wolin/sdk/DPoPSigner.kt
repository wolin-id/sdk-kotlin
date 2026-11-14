package id.wolin.sdk

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.time.Instant
import java.util.Base64
import java.util.UUID

/**
 * Public EC (`P-256`) JSON Web Key representation (RFC 7517 / RFC 7638).
 * Never contains private key material (`d`).
 */
data class PublicEcJwk(
    val kty: String = "EC",
    val crv: String = "P-256",
    val x: String,
    val y: String,
) {
    init {
        require(kty == "EC") { "PublicEcJwk requires kty='EC'" }
        require(crv == "P-256") { "PublicEcJwk requires crv='P-256'" }
        require(DPoPSigner.base64UrlDecode(x).size == DPoPSigner.P256_COMPONENT_BYTES) {
            "P-256 JWK 'x' coordinate must decode to 32 bytes"
        }
        require(DPoPSigner.base64UrlDecode(y).size == DPoPSigner.P256_COMPONENT_BYTES) {
            "P-256 JWK 'y' coordinate must decode to 32 bytes"
        }
    }

    /** Serializes the public JWK object for embedding in the DPoP JWT header. */
    fun toJson(): String =
        buildString(128) {
            append("{\"kty\":\"").append(DPoPSigner.escapeJson(kty))
            append("\",\"crv\":\"").append(DPoPSigner.escapeJson(crv))
            append("\",\"x\":\"").append(DPoPSigner.escapeJson(x))
            append("\",\"y\":\"").append(DPoPSigner.escapeJson(y))
            append("\"}")
        }

    /**
     * Computes the RFC 7638 §3.1 canonical SHA-256 JWK Thumbprint (`jkt`) encoded as unpadded Base64URL.
     * Required member order for `EC`: `crv`, `kty`, `x`, `y`.
     */
    fun thumbprintSha256(): String = DPoPSigner.computeJwkThumbprint(crv = crv, x = x, y = y)
}

/**
 * RFC 9449 OAuth 2.0 Demonstrating Proof-of-Possession (`DPoP`) ES256 JWT Signer.
 *
 * Uses pure JDK `java.security.Signature` (`SHA256withECDSA` over NIST `secp256r1` / `P-256`)
 * and converts ASN.1 DER `(r, s)` signatures into fixed-width 64-byte IEEE P1363 (`R || S`) format
 * required by RFC 7518 §3.4 (`ES256`).
 */
class DPoPSigner(
    val keyPair: KeyPair,
    private val secureRandom: SecureRandom = SecureRandom(),
    private val clock: () -> Long = { Instant.now().epochSecond },
) {
    val publicKey: ECPublicKey
    private val privateKey: ECPrivateKey
    val publicJwk: PublicEcJwk

    /** RFC 7638 SHA-256 JWK thumbprint (`jkt`) of the public P-256 key. */
    val jwkThumbprint: String

    init {
        val pub = keyPair.public as? ECPublicKey
            ?: throw WolinException("DPoPSigner requires an ECPublicKey (got ${keyPair.public?.javaClass?.name})")
        val priv = keyPair.private as? ECPrivateKey
            ?: throw WolinException("DPoPSigner requires an ECPrivateKey (got ${keyPair.private?.javaClass?.name})")

        validateP256PublicKey(pub)
        validateP256CurveParams(priv.params.curve.field as? ECFieldFp, priv.params.curve.a, priv.params.curve.b)

        this.publicKey = pub
        this.privateKey = priv

        val point = pub.w
        val xBytes = bigIntToUnsignedFixed(point.affineX, P256_COMPONENT_BYTES)
        val yBytes = bigIntToUnsignedFixed(point.affineY, P256_COMPONENT_BYTES)

        this.publicJwk = PublicEcJwk(
            kty = "EC",
            crv = "P-256",
            x = base64UrlEncode(xBytes),
            y = base64UrlEncode(yBytes),
        )
        this.jwkThumbprint = publicJwk.thumbprintSha256()
    }

    /**
     * Generates a fresh request-bound RFC 9449 DPoP proof JWT (`typ = "dpop+jwt"`, `alg = "ES256"`).
     *
     * @param htm HTTP method (e.g., `"GET"`, `"PUT"`, `"DELETE"`).
     * @param htu Target HTTP(S) URI (query and fragment components are stripped per RFC 9449 §4.2).
     * @param accessToken Optional OIDC/OAuth2 access token; when provided, binds `"ath"` (`SHA-256` Base64URL).
     * @param nonce Optional server-issued `DPoP-Nonce` challenge value (RFC 9449 §8).
     * @param jti Unique token identifier (defaults to random UUIDv4).
     * @param iat Issued-at UNIX timestamp in seconds.
     */
    fun signProof(
        htm: String,
        htu: String,
        accessToken: String? = null,
        nonce: String? = null,
        jti: String = UUID.randomUUID().toString(),
        iat: Long = clock(),
    ): String {
        val normalizedMethod = htm.trim().uppercase()
        if (normalizedMethod.isEmpty() || normalizedMethod.any { !it.isLetter() }) {
            throw WolinException("Invalid HTTP method '$htm' for DPoP 'htm' claim")
        }
        if (jti.isBlank() || jti.length > 256 || jti.any { it.code < 0x20 || it.code == 0x7F }) {
            throw WolinException("Invalid DPoP 'jti' claim")
        }

        val normalizedHtu = normalizeHtu(htu)

        val headerJson = buildString(192) {
            append("{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":")
            append(publicJwk.toJson())
            append('}')
        }

        val payloadJson = buildString(256) {
            append("{\"jti\":\"").append(escapeJson(jti)).append('"')
            append(",\"htm\":\"").append(escapeJson(normalizedMethod)).append('"')
            append(",\"htu\":\"").append(escapeJson(normalizedHtu)).append('"')
            append(",\"iat\":").append(iat)
            if (!accessToken.isNullOrEmpty()) {
                require(accessToken.isNotBlank()) { "Access token for DPoP 'ath' binding must not be blank" }
                val ath = computeAccessTokenHash(accessToken)
                append(",\"ath\":\"").append(ath).append('"')
            }
            if (!nonce.isNullOrEmpty()) {
                append(",\"nonce\":\"").append(escapeJson(nonce)).append('"')
            }
            append('}')
        }

        val headerB64 = base64UrlEncode(headerJson.toByteArray(StandardCharsets.UTF_8))
        val payloadB64 = base64UrlEncode(payloadJson.toByteArray(StandardCharsets.UTF_8))
        val signingInput = "$headerB64.$payloadB64"

        val derSignature = signSha256WithEcdsaDer(signingInput.toByteArray(StandardCharsets.US_ASCII))
        val p1363Signature = derToP1363(derSignature, P256_COMPONENT_BYTES)
        val sigB64 = base64UrlEncode(p1363Signature)

        return "$signingInput.$sigB64"
    }

    private fun signSha256WithEcdsaDer(signingInput: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey, secureRandom)
        signature.update(signingInput)
        return signature.sign()
    }

    companion object {
        const val P256_COMPONENT_BYTES: Int = 32
        const val ES256_SIGNATURE_BYTES: Int = 64

        // NIST P-256 (secp256r1 / prime256v1) domain parameters (FIPS 186-4)
        private val P256_P = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
        private val P256_A = BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16)
        private val P256_B = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)

        /**
         * Generates a fresh ephemeral NIST P-256 (`secp256r1`) keypair and returns a [DPoPSigner].
         */
        @JvmStatic
        @JvmOverloads
        fun generate(
            secureRandom: SecureRandom = SecureRandom(),
            clock: () -> Long = { Instant.now().epochSecond },
        ): DPoPSigner {
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"), secureRandom)
            return DPoPSigner(kpg.generateKeyPair(), secureRandom, clock)
        }

        /**
         * Converts an ASN.1 DER-encoded ECDSA signature (`SEQUENCE { r INTEGER, s INTEGER }`)
         * emitted by `SHA256withECDSA` into fixed-width IEEE P1363 (`R || S`) format (64 bytes for ES256).
         */
        @JvmStatic
        @JvmOverloads
        fun derToP1363(der: ByteArray, componentSize: Int = P256_COMPONENT_BYTES): ByteArray {
            require(componentSize > 0) { "componentSize must be positive" }
            if (der.size < 8 || der[0] != 0x30.toByte()) {
                throw WolinException("Invalid ASN.1 DER ECDSA signature: missing SEQUENCE tag (0x30)")
            }

            var pos = 1
            val firstLen = der[pos++].toInt() and 0xFF
            val seqLen = when {
                firstLen < 0x80 -> firstLen
                firstLen == 0x81 -> {
                    if (pos >= der.size) {
                        throw WolinException("Truncated ASN.1 DER sequence length")
                    }
                    val len = der[pos++].toInt() and 0xFF
                    if (len < 0x80) {
                        throw WolinException("Non-minimal ASN.1 DER sequence length encoding")
                    }
                    len
                }
                else -> throw WolinException("Unsupported ASN.1 DER sequence length prefix: 0x${firstLen.toString(16)}")
            }

            if (pos + seqLen != der.size) {
                throw WolinException("ASN.1 DER sequence length ($seqLen) does not match remaining bytes (${der.size - pos})")
            }

            val output = ByteArray(componentSize * 2)
            pos = readDerPositiveIntegerInto(der, pos, output, 0, componentSize)
            pos = readDerPositiveIntegerInto(der, pos, output, componentSize, componentSize)

            if (pos != der.size) {
                throw WolinException("Trailing bytes after ASN.1 DER ECDSA signature components")
            }
            return output
        }

        private fun readDerPositiveIntegerInto(
            der: ByteArray,
            startOffset: Int,
            target: ByteArray,
            targetOffset: Int,
            componentSize: Int,
        ): Int {
            var pos = startOffset
            if (pos + 2 > der.size || der[pos++] != 0x02.toByte()) {
                throw WolinException("Invalid ASN.1 DER ECDSA signature: expected INTEGER tag (0x02)")
            }
            val intLen = der[pos++].toInt() and 0xFF
            if (intLen == 0 || intLen >= 0x80 || pos + intLen > der.size) {
                throw WolinException("Invalid ASN.1 DER INTEGER length: $intLen")
            }
            if ((der[pos].toInt() and 0x80) != 0) {
                throw WolinException("Negative ECDSA signature component in ASN.1 DER")
            }
            if (intLen > 1 && der[pos] == 0x00.toByte() && (der[pos + 1].toInt() and 0x80) == 0) {
                throw WolinException("Non-minimal leading zero in ASN.1 DER INTEGER")
            }

            val valueStart = if (intLen > 1 && der[pos] == 0x00.toByte()) pos + 1 else pos
            val valueLen = (pos + intLen) - valueStart
            if (valueLen > componentSize) {
                throw WolinException("ECDSA component length ($valueLen) exceeds $componentSize bytes")
            }

            var allZero = true
            for (i in valueStart until (pos + intLen)) {
                if (der[i] != 0.toByte()) {
                    allZero = false
                    break
                }
            }
            if (allZero) {
                throw WolinException("Zero ECDSA signature component is invalid")
            }

            System.arraycopy(der, valueStart, target, targetOffset + (componentSize - valueLen), valueLen)
            return pos + intLen
        }

        /**
         * Converts a fixed-width IEEE P1363 (`R || S`) ECDSA signature into minimal ASN.1 DER format.
         */
        @JvmStatic
        @JvmOverloads
        fun p1363ToDer(p1363: ByteArray, componentSize: Int = P256_COMPONENT_BYTES): ByteArray {
            if (p1363.size != componentSize * 2) {
                throw WolinException("Expected ${componentSize * 2}-byte IEEE P1363 signature, got ${p1363.size} bytes")
            }
            val rDer = encodeDerPositiveInteger(p1363.copyOfRange(0, componentSize))
            val sDer = encodeDerPositiveInteger(p1363.copyOfRange(componentSize, componentSize * 2))
            val seqLen = rDer.size + sDer.size

            val out = ByteArrayOutputStream(seqLen + 4)
            out.write(0x30)
            if (seqLen < 0x80) {
                out.write(seqLen)
            } else {
                out.write(0x81)
                out.write(seqLen)
            }
            out.write(rDer)
            out.write(sDer)
            return out.toByteArray()
        }

        private fun encodeDerPositiveInteger(fixedBytes: ByteArray): ByteArray {
            var firstNonZero = 0
            while (firstNonZero < fixedBytes.size && fixedBytes[firstNonZero] == 0.toByte()) {
                firstNonZero++
            }
            if (firstNonZero == fixedBytes.size) {
                throw WolinException("Zero ECDSA signature component is invalid")
            }

            val needsSignPad = (fixedBytes[firstNonZero].toInt() and 0x80) != 0
            val significantLen = fixedBytes.size - firstNonZero
            val derLen = significantLen + if (needsSignPad) 1 else 0

            val encoded = ByteArray(2 + derLen)
            encoded[0] = 0x02
            encoded[1] = derLen.toByte()
            var writePos = 2
            if (needsSignPad) {
                encoded[writePos++] = 0x00
            }
            System.arraycopy(fixedBytes, firstNonZero, encoded, writePos, significantLen)
            return encoded
        }

        /**
         * Verifies an IEEE P1363 `ES256` signature over [signingInput] using `SHA256withECDSA`.
         */
        @JvmStatic
        fun verifyEs256Signature(
            publicKey: ECPublicKey,
            signingInput: ByteArray,
            p1363Signature: ByteArray,
        ): Boolean {
            validateP256PublicKey(publicKey)
            if (p1363Signature.size != ES256_SIGNATURE_BYTES) return false
            val derSig = try {
                p1363ToDer(p1363Signature, P256_COMPONENT_BYTES)
            } catch (_: WolinException) {
                return false
            }
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(publicKey)
            verifier.update(signingInput)
            return verifier.verify(derSig)
        }

        /**
         * Computes RFC 7638 §3.1 canonical SHA-256 JWK Thumbprint (`{"crv":...,"kty":"EC","x":...,"y":...}`).
         */
        @JvmStatic
        fun computeJwkThumbprint(crv: String, x: String, y: String): String {
            if (crv.isBlank() || x.isBlank() || y.isBlank()) {
                throw WolinException("JWK thumbprint parameters 'crv', 'x', and 'y' must not be blank")
            }
            val _x = base64UrlDecode(x)
            val _y = base64UrlDecode(y)
            if (_x.isEmpty() || _y.isEmpty()) {
                throw WolinException("JWK coordinates 'x' and 'y' must not decode to empty bytes")
            }
            val canonicalJson = buildString(128) {
                append("{\"crv\":\"").append(escapeJson(crv))
                append("\",\"kty\":\"EC\",\"x\":\"").append(escapeJson(x))
                append("\",\"y\":\"").append(escapeJson(y)).append("\"}")
            }
            return sha256Base64Url(canonicalJson.toByteArray(StandardCharsets.UTF_8))
        }

        /**
         * Computes RFC 9449 §4.2 `ath` claim: unpadded Base64URL of `SHA-256(ASCII(access_token))`.
         */
        @JvmStatic
        fun computeAccessTokenHash(accessToken: String): String =
            sha256Base64Url(accessToken.toByteArray(StandardCharsets.US_ASCII))

        /**
         * Normalizes an HTTP target URI for the RFC 9449 `htu` claim (strips query and fragment,
         * lowercases scheme & host, strips default ports 80/443, and ensures a non-empty path).
         */
        @JvmStatic
        fun normalizeHtu(rawUri: String): String {
            val parsed: URI = HeaderUtils.validateHttpUri(rawUri)
            val scheme = parsed.scheme.lowercase()
            val host = parsed.host.lowercase()
            val port = parsed.port
            val isDefaultPort = port == -1 ||
                (scheme == "http" && port == 80) ||
                (scheme == "https" && port == 443)
            val authority = if (isDefaultPort) host else "$host:$port"
            val path = parsed.rawPath.let { if (it.isNullOrEmpty()) "/" else it }
            return "$scheme://$authority$path"
        }

        @JvmStatic
        fun sha256Base64Url(data: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(data)
            return base64UrlEncode(digest)
        }

        @JvmStatic
        fun base64UrlEncode(bytes: ByteArray): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        @JvmStatic
        fun base64UrlDecode(encoded: String): ByteArray =
            try {
                Base64.getUrlDecoder().decode(encoded)
            } catch (e: IllegalArgumentException) {
                throw WolinException("Invalid Base64URL segment: ${e.message}", e)
            }

        internal fun bigIntToUnsignedFixed(value: BigInteger, byteLen: Int): ByteArray {
            if (value.signum() < 0) {
                throw WolinException("EC coordinate must be non-negative")
            }
            val raw = value.toByteArray()
            var offset = 0
            while (offset < raw.size - byteLen) {
                if (raw[offset] != 0.toByte()) {
                    throw WolinException("EC integer exceeds $byteLen bytes")
                }
                offset++
            }
            val significant = raw.size - offset
            if (significant > byteLen) {
                throw WolinException("EC integer exceeds $byteLen bytes")
            }
            val out = ByteArray(byteLen)
            System.arraycopy(raw, offset, out, byteLen - significant, significant)
            return out
        }

        private fun validateP256PublicKey(pub: ECPublicKey) {
            if (pub.w == ECPoint.POINT_INFINITY) {
                throw WolinException("Invalid EC public key: point at infinity")
            }
            val curve = pub.params.curve
            validateP256CurveParams(curve.field as? ECFieldFp, curve.a, curve.b)
        }

        private fun validateP256CurveParams(field: ECFieldFp?, a: BigInteger, b: BigInteger) {
            if (field == null || field.p != P256_P || a != P256_A || b != P256_B) {
                throw WolinException("DPoPSigner ES256 requires NIST P-256 (secp256r1) curve parameters")
            }
        }

        internal fun escapeJson(value: String): String {
            val sb = StringBuilder(value.length + 8)
            for (ch in value) {
                when (ch) {
                    '"' -> sb.append("\\\"")
                    '\\' -> sb.append("\\\\")
                    '\b' -> sb.append("\\b")
                    '\u000C' -> sb.append("\\f")
                    '\n' -> sb.append("\\n")
                    '\r' -> sb.append("\\r")
                    '\t' -> sb.append("\\t")
                    else -> if (ch.code < 0x20) {
                        sb.append("\\u")
                        sb.append(ch.code.toString(16).padStart(4, '0'))
                    } else {
                        sb.append(ch)
                    }
                }
            }
            return sb.toString()
        }
    }
}
