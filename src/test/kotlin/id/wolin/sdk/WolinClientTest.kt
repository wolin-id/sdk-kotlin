package id.wolin.sdk

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.math.BigInteger
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

class WolinClientTest {
    private lateinit var server: HttpServer
    private lateinit var baseUrl: String

    private data class StoredEntry(
        val body: ByteArray,
        val contentType: String,
        val etag: String,
    )

    private val store = ConcurrentHashMap<String, StoredEntry>()
    private val seenDpopJtis: MutableSet<String> = Collections.synchronizedSet(HashSet())
    @Volatile
    private var requireServerNonce: String? = null
    @Volatile
    private var expectedToken: String = "solid-oidc-access-token-xyz"
    @Volatile
    private var expectedJkt: String = ""

    @BeforeEach
    fun setUp() {
        store.clear()
        seenDpopJtis.clear()
        requireServerNonce = null

        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.executor = Executors.newCachedThreadPool()
        val port = server.address.port
        baseUrl = "http://127.0.0.1:$port"

        server.createContext("/") { exchange ->
            try {
                handleExchange(exchange)
            } catch (t: Throwable) {
                val msg = (t.message ?: "Internal Server Error").toByteArray(StandardCharsets.UTF_8)
                exchange.sendResponseHeaders(500, msg.size.toLong())
                exchange.responseBody.use { it.write(msg) }
            }
        }
        server.start()
    }

    @AfterEach
    fun tearDown() {
        server.stop(0)
    }

    @Test
    fun `DPoPSigner generates valid P-256 JWK thumbprint and verifies ES256 proof cryptographically`() {
        val fixedNow = 1_763_500_000L
        val signer = DPoPSigner.generate(clock = { fixedNow })

        assertEquals("EC", signer.publicJwk.kty)
        assertEquals("P-256", signer.publicJwk.crv)
        assertFalse(signer.publicJwk.toJson().contains("\"d\""))
        assertEquals(32, DPoPSigner.base64UrlDecode(signer.publicJwk.x).size)
        assertEquals(32, DPoPSigner.base64UrlDecode(signer.publicJwk.y).size)

        // Known-answer RFC 7638 vector check on canonical ordering {"crv":"P-256","kty":"EC","x":...,"y":...}
        val expectedCanonical =
            "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"${signer.publicJwk.x}\",\"y\":\"${signer.publicJwk.y}\"}"
        val expectedThumbprint = DPoPSigner.sha256Base64Url(expectedCanonical.toByteArray(StandardCharsets.UTF_8))
        assertEquals(expectedThumbprint, signer.jwkThumbprint)

        val token = "eyJhbGciOiJFUzI1NiJ9.payload.sig"
        val proof = signer.signProof(
            htm = "put",
            htu = "HTTPS://Alice.Wolin.ID:443/pod/notes/todo.ttl?draft=1#top",
            accessToken = token,
            nonce = "srv-nonce-1",
            jti = "fixed-jti-001",
        )

        val parts = proof.split('.')
        assertEquals(3, parts.size)
        val headerJson = String(DPoPSigner.base64UrlDecode(parts[0]), StandardCharsets.UTF_8)
        val payloadJson = String(DPoPSigner.base64UrlDecode(parts[1]), StandardCharsets.UTF_8)
        val sigBytes = DPoPSigner.base64UrlDecode(parts[2])

        assertEquals(64, sigBytes.size, "ES256 IEEE P1363 signature must be 64 bytes")
        assertTrue(headerJson.contains("\"typ\":\"dpop+jwt\""))
        assertTrue(headerJson.contains("\"alg\":\"ES256\""))
        assertTrue(payloadJson.contains("\"jti\":\"fixed-jti-001\""))
        assertTrue(payloadJson.contains("\"htm\":\"PUT\""))
        assertTrue(payloadJson.contains("\"htu\":\"https://alice.wolin.id/pod/notes/todo.ttl\""))
        assertTrue(payloadJson.contains("\"iat\":$fixedNow"))
        assertTrue(payloadJson.contains("\"ath\":\"${DPoPSigner.computeAccessTokenHash(token)}\""))
        assertTrue(payloadJson.contains("\"nonce\":\"srv-nonce-1\""))

        val reconstructedPub = reconstructP256PublicKey(signer.publicJwk.x, signer.publicJwk.y)
        val signingInput = "${parts[0]}.${parts[1]}".toByteArray(StandardCharsets.US_ASCII)
        assertTrue(DPoPSigner.verifyEs256Signature(reconstructedPub, signingInput, sigBytes))

        // Tampering any byte of payload must fail verification
        val tamperedInput = "${parts[0]}x.${parts[1]}".toByteArray(StandardCharsets.US_ASCII)
        assertFalse(DPoPSigner.verifyEs256Signature(reconstructedPub, tamperedInput, sigBytes))
    }

    @Test
    fun `DER to IEEE P1363 converter handles leading sign pad, short integers, and rejects malformed DER`() {
        // 33-byte r (leading 0x00 because MSB 0x89 >= 0x80) and 29-byte s (3 leading zero bytes)
        val rRaw = ByteArray(32) { idx -> if (idx == 0) 0x89.toByte() else (idx + 1).toByte() }
        val sShort = ByteArray(29) { idx -> (0x21 + idx).toByte() }
        val sExpected = ByteArray(32).apply {
            System.arraycopy(sShort, 0, this, 3, sShort.size)
        }

        val der = ByteArray(2 + (2 + 33) + (2 + 29))
        var p = 0
        der[p++] = 0x30
        der[p++] = (35 + 31).toByte()
        der[p++] = 0x02
        der[p++] = 33
        der[p++] = 0x00
        System.arraycopy(rRaw, 0, der, p, 32)
        p += 32
        der[p++] = 0x02
        der[p++] = 29
        System.arraycopy(sShort, 0, der, p, 29)

        val p1363 = DPoPSigner.derToP1363(der)
        assertEquals(64, p1363.size)
        assertArrayEquals(rRaw, p1363.copyOfRange(0, 32))
        assertArrayEquals(sExpected, p1363.copyOfRange(32, 64))

        val reEncodedDer = DPoPSigner.p1363ToDer(p1363)
        assertArrayEquals(der, reEncodedDer)

        // Reject non-minimal zero padding (0x00 followed by 0x12 < 0x80)
        val nonMinimal = byteArrayOf(0x30, 0x07, 0x02, 0x02, 0x00, 0x12, 0x02, 0x01, 0x05)
        assertThrows<WolinException> { DPoPSigner.derToP1363(nonMinimal) }

        // Reject trailing bytes
        assertThrows<WolinException> { DPoPSigner.derToP1363(der + byteArrayOf(0x00)) }

        // Reject non-P256 EC curve (secp384r1)
        val kpg384 = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp384r1"))
        }
        assertThrows<WolinException> { DPoPSigner(kpg384.generateKeyPair()) }
    }

    @Test
    fun `WebIdParser parses Turtle directives, relative IRIs, blank nodes, literals, and Solid predicates`() {
        val webId = "https://alice.wolin.id/profile/card#me"
        val turtle = """
            # Wolin Sovereign WebID Profile
            @prefix foaf: <http://xmlns.com/foaf/0.1/> .
            @prefix solid: <http://www.w3.org/ns/solid/terms#> .
            @prefix pim: <http://www.w3.org/ns/pim/space#> .
            PREFIX ldp: <http://www.w3.org/ns/ldp#>

            <> a foaf:PersonalProfileDocument ;
               foaf:primaryTopic <#me> .

            <#me> a foaf:Person ;
                foaf:name "Alice \"Wolin\" Lee"@en , '''Alice
            Multiline ; pim:storage <https://fake.example/> .''' ;
                solid:oidcIssuer <https://auth.wolin.id> , <https://login.inrupt.com> ;
                solid:account [
                    a solid:Account ;
                    foaf:mbox <mailto:alice@wolin.id>
                ] ;
                ldp:inbox </inbox/> ;
                pim:storage <https://alice.wolin.id/> .
        """.trimIndent()

        val profile = WebIdParser.parseTurtle(turtle, webId)
        assertEquals(webId, profile.webId)
        assertEquals("https://alice.wolin.id/", profile.primaryStorage)
        assertEquals(listOf("https://alice.wolin.id/"), profile.storages)
        assertEquals(listOf("https://auth.wolin.id", "https://login.inrupt.com"), profile.oidcIssuers)
        assertEquals(listOf("https://alice.wolin.id/inbox/"), profile.inboxes)
        assertEquals(listOf("http://xmlns.com/foaf/0.1/Person"), profile.types)
        assertTrue(profile.verifyOidcIssuer("https://auth.wolin.id"))
        assertFalse(profile.verifyOidcIssuer("https://evil.idp.example"))
    }

    @Test
    fun `WolinClient executes Solid-OIDC DPoP auth, WebID discovery, and LDP CRUD with ETag preconditions`() {
        val signer = DPoPSigner.generate()
        expectedJkt = signer.jwkThumbprint
        requireServerNonce = "wolin-nonce-epoch-1"

        val client = WolinClient(
            accessToken = expectedToken,
            dpopSigner = signer,
        )

        // 1. Discover Pod storage from WebID Profile (simultaneously testing DPoP-Nonce challenge retry)
        val webId = "$baseUrl/alice/profile/card#me"
        val storageRoot = client.discoverStorage(webId)
        assertEquals("$baseUrl/alice/pod/", storageRoot)

        val profile = client.fetchWebIdProfile(webId)
        assertTrue(profile.verifyOidcIssuer("https://auth.wolin.id"))

        // 2. Resolve safe resource URL and reject path traversal
        val noteUrl = client.resolveResourceUrl(storageRoot, "notes/meeting.ttl")
        assertEquals("$baseUrl/alice/pod/notes/meeting.ttl", noteUrl)
        assertThrows<WolinException> {
            client.resolveResourceUrl(storageRoot, "../../secret.ttl")
        }

        // 3. Create resource with If-None-Match: *
        val v1Body = "<#note> <http://purl.org/dc/terms/title> \"Initial Note\" .\n"
        val created = client.createIfAbsent(noteUrl, v1Body)
        assertEquals(201, created.statusCode)
        assertTrue(created.created)
        assertNotNull(created.etag)
        val etag1 = created.etag!!

        // Duplicate createIfAbsent must fail with 412 Precondition Failed
        val duplicateErr = assertThrows<WolinHttpException> {
            client.createIfAbsent(noteUrl, v1Body)
        }
        assertTrue(duplicateErr.isPreconditionFailed)
        assertEquals(412, duplicateErr.statusCode)

        // 4. GET resource & verify content, ETag, and Link headers
        val fetched1 = client.get(noteUrl)
        assertEquals(200, fetched1.statusCode)
        assertEquals(v1Body, fetched1.text)
        assertEquals(etag1, fetched1.etag)
        assertEquals("$noteUrl.acl", fetched1.aclUrl)

        // Conditional GET with matching ETag returns null (304 Not Modified)
        assertNull(client.getIfModified(noteUrl, etag1))

        // 5. PUT update with stale ETag must fail with 412
        val v2Body = "<#note> <http://purl.org/dc/terms/title> \"Updated Note v2\" .\n"
        val stalePutErr = assertThrows<WolinHttpException> {
            client.put(noteUrl, v2Body, ifMatch = "\"stale-etag\"")
        }
        assertTrue(stalePutErr.isPreconditionFailed)

        // PUT update with matching ETag succeeds (204 No Content) and rotates ETag
        val updated = client.put(noteUrl, v2Body, ifMatch = etag1)
        assertEquals(204, updated.statusCode)
        val etag2 = updated.etag!!
        assertNotEquals(etag1, etag2)

        // Conditional GET with old etag1 now returns updated resource
        val modified = client.getIfModified(noteUrl, etag1)
        assertNotNull(modified)
        assertEquals(v2Body, modified!!.text)
        assertEquals(etag2, modified.etag)

        // 6. DELETE with stale ETag fails (412); DELETE with current ETag succeeds (204)
        val staleDelErr = assertThrows<WolinHttpException> {
            client.delete(noteUrl, ifMatch = etag1)
        }
        assertTrue(staleDelErr.isPreconditionFailed)

        client.delete(noteUrl, ifMatch = etag2)

        // Subsequent GET returns 404 Not Found
        val missingErr = assertThrows<WolinHttpException> {
            client.get(noteUrl)
        }
        assertTrue(missingErr.isNotFound)
        assertEquals(404, missingErr.statusCode)
    }

    @Test
    fun `WolinClient falls back to Link pim Storage header discovery when WebID omits pim storage triple`() {
        val signer = DPoPSigner.generate()
        expectedJkt = signer.jwkThumbprint
        val client = WolinClient(accessToken = expectedToken, dpopSigner = signer)

        val storage = client.discoverStorage("$baseUrl/bob/profile/card#me")
        assertEquals("$baseUrl/bob/", storage)
    }

    @Test
    fun `validatePodId enforces 3 to 32 lowercase characters, no double hyphens, and reserved blocklist`() {
        assertEquals("https://auth.wolin.id", WolinClient.DEFAULT_AUTH_URL)
        assertEquals("https://pod.wolin.id", WolinClient.DEFAULT_POD_URL)

        for (valid in listOf("bob", "alice", "alice-01", "a".repeat(32), "team-alpha-2026")) {
            assertTrue(WolinClient.isValidPodId(valid), valid)
            assertEquals(valid, WolinClient.validatePodId(valid))
        }

        for (invalid in listOf(
            "", "a", "ab", "a".repeat(33), "Alice", "-alice", "alice-",
            "alice--dev", "xn--p1ai", "alice_01", "alice.dev",
            "auth", "pod", "pods", "api", "admin", "wolin", "www",
        )) {
            assertFalse(WolinClient.isValidPodId(invalid), invalid)
            assertThrows<WolinException> { WolinClient.validatePodId(invalid) }
        }
    }

    @Test
    fun `WolinClient follows 302 signed asset redirect without leaking Authorization or DPoP headers`() {
        val offloadedBytes = "wolin-signed-r2-binary-asset-payload".toByteArray(StandardCharsets.UTF_8)
        var cdnSawAuthHeader = false
        var cdnSawDpopHeader = false

        val cdnServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        cdnServer.executor = Executors.newCachedThreadPool()
        val cdnBaseUrl = "http://127.0.0.1:${cdnServer.address.port}"
        cdnServer.createContext("/assets/alice/media/clip.bin") { ex ->
            cdnSawAuthHeader = ex.requestHeaders.containsKey("Authorization")
            cdnSawDpopHeader = ex.requestHeaders.containsKey("DPoP")
            if (cdnSawAuthHeader || cdnSawDpopHeader) {
                sendPlain(ex, 400, "Leaked Authorization or DPoP header to external asset CDN")
                return@createContext
            }
            if (ex.requestURI.query != "exp=1763500060&sig=ok") {
                sendPlain(ex, 403, "Invalid signed query")
                return@createContext
            }
            ex.responseHeaders.set("Content-Type", "application/octet-stream")
            ex.sendResponseHeaders(200, offloadedBytes.size.toLong())
            ex.responseBody.use { it.write(offloadedBytes) }
        }
        cdnServer.start()

        try {
            server.createContext("/alice/pod/media/clip.bin") { ex ->
                if (!verifyDpopAuth(ex, "GET", "$baseUrl/alice/pod/media/clip.bin")) {
                    return@createContext
                }
                ex.responseHeaders.set("Location", "$cdnBaseUrl/assets/alice/media/clip.bin?exp=1763500060&sig=ok")
                ex.responseHeaders.set("ETag", computeEtag(offloadedBytes))
                ex.responseHeaders.add(
                    "Link",
                    "<${PodResource.LDP_NON_RDF_SOURCE}>; rel=\"type\", <$baseUrl/alice/pod/media/clip.bin.acl>; rel=\"acl\"",
                )
                ex.responseHeaders.set("Cache-Control", "private, no-store")
                ex.sendResponseHeaders(302, -1)
                ex.close()
            }

            val signer = DPoPSigner.generate()
            expectedJkt = signer.jwkThumbprint
            val client = WolinClient(accessToken = expectedToken, dpopSigner = signer)

            val asset = client.get("$baseUrl/alice/pod/media/clip.bin")
            assertEquals(200, asset.statusCode)
            assertArrayEquals(offloadedBytes, asset.body)
            assertEquals(computeEtag(offloadedBytes), asset.etag)
            assertTrue(asset.linkTypes.contains(PodResource.LDP_NON_RDF_SOURCE))
            assertEquals("$baseUrl/alice/pod/media/clip.bin.acl", asset.aclUrl)
            assertFalse(cdnSawAuthHeader)
            assertFalse(cdnSawDpopHeader)
        } finally {
            cdnServer.stop(0)
        }
    }

    // --- Embedded Solid-OIDC + DPoP + LDP Verification Server ---

    private fun handleExchange(exchange: HttpExchange) {
        val method = exchange.requestMethod.uppercase()
        val path = exchange.requestURI.path

        if (!verifyDpopAuth(exchange, method, "$baseUrl$path")) {
            return
        }

        // Built-in WebID Profile endpoints
        if (path == "/alice/profile/card" && method == "GET") {
            val ttl = """
                @prefix foaf: <http://xmlns.com/foaf/0.1/> .
                @prefix solid: <http://www.w3.org/ns/solid/terms#> .
                @prefix pim: <http://www.w3.org/ns/pim/space#> .
                <#me> a foaf:Person ;
                    solid:oidcIssuer <https://auth.wolin.id> ;
                    pim:storage <$baseUrl/alice/pod/> .
            """.trimIndent().toByteArray(StandardCharsets.UTF_8)
            exchange.responseHeaders.set("Content-Type", "text/turtle")
            exchange.responseHeaders.set("ETag", computeEtag(ttl))
            exchange.sendResponseHeaders(200, ttl.size.toLong())
            exchange.responseBody.use { it.write(ttl) }
            return
        }

        if (path == "/bob/profile/card" && method == "GET") {
            val ttl = """
                @prefix foaf: <http://xmlns.com/foaf/0.1/> .
                @prefix solid: <http://www.w3.org/ns/solid/terms#> .
                <#me> a foaf:Person ;
                    solid:oidcIssuer <https://auth.wolin.id> .
            """.trimIndent().toByteArray(StandardCharsets.UTF_8)
            exchange.responseHeaders.set("Content-Type", "text/turtle")
            exchange.sendResponseHeaders(200, ttl.size.toLong())
            exchange.responseBody.use { it.write(ttl) }
            return
        }

        if (path == "/bob/" && method == "HEAD") {
            exchange.responseHeaders.add(
                "Link",
                "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\", <http://www.w3.org/ns/pim/space#Storage>; rel=\"type\"",
            )
            exchange.sendResponseHeaders(200, -1)
            exchange.close()
            return
        }

        if (path == "/bob/profile/" && method == "HEAD") {
            exchange.responseHeaders.add("Link", "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"")
            exchange.sendResponseHeaders(200, -1)
            exchange.close()
            return
        }

        // Solid LDP CRUD handlers
        val ifMatch = exchange.requestHeaders.getFirst("If-Match")
        val ifNoneMatch = exchange.requestHeaders.getFirst("If-None-Match")

        when (method) {
            "GET", "HEAD" -> {
                val entry = store[path]
                if (entry == null) {
                    sendPlain(exchange, 404, "Resource not found")
                    return
                }
                if (ifNoneMatch != null && (ifNoneMatch == "*" || ifNoneMatch == entry.etag)) {
                    exchange.responseHeaders.set("ETag", entry.etag)
                    exchange.sendResponseHeaders(304, -1)
                    exchange.close()
                    return
                }
                if (ifMatch != null && ifMatch != "*" && ifMatch != entry.etag) {
                    sendPlain(exchange, 412, "If-Match precondition failed")
                    return
                }
                exchange.responseHeaders.set("Content-Type", entry.contentType)
                exchange.responseHeaders.set("ETag", entry.etag)
                exchange.responseHeaders.add(
                    "Link",
                    "<http://www.w3.org/ns/ldp#Resource>; rel=\"type\", <$baseUrl$path.acl>; rel=\"acl\"",
                )
                if (method == "HEAD") {
                    exchange.sendResponseHeaders(200, -1)
                    exchange.close()
                } else {
                    exchange.sendResponseHeaders(200, entry.body.size.toLong())
                    exchange.responseBody.use { it.write(entry.body) }
                }
            }
            "PUT" -> {
                val body = exchange.requestBody.use { it.readAllBytes() }
                val existing = store[path]
                if (ifNoneMatch == "*" && existing != null) {
                    sendPlain(exchange, 412, "Resource already exists")
                    return
                }
                if (ifMatch != null) {
                    if (existing == null || (ifMatch != "*" && existing.etag != ifMatch)) {
                        sendPlain(exchange, 412, "ETag mismatch")
                        return
                    }
                }
                val ct = exchange.requestHeaders.getFirst("Content-Type") ?: "application/octet-stream"
                val newEtag = computeEtag(body)
                store[path] = StoredEntry(body = body, contentType = ct, etag = newEtag)
                exchange.responseHeaders.set("ETag", newEtag)
                exchange.responseHeaders.add("Link", "<$baseUrl$path.acl>; rel=\"acl\"")
                if (existing == null) {
                    exchange.responseHeaders.set("Location", "$baseUrl$path")
                    exchange.sendResponseHeaders(201, -1)
                } else {
                    exchange.sendResponseHeaders(204, -1)
                }
                exchange.close()
            }
            "DELETE" -> {
                val existing = store[path]
                if (existing == null) {
                    sendPlain(exchange, 404, "Resource not found")
                    return
                }
                if (ifMatch != null && ifMatch != "*" && existing.etag != ifMatch) {
                    sendPlain(exchange, 412, "ETag mismatch on DELETE")
                    return
                }
                store.remove(path)
                exchange.sendResponseHeaders(204, -1)
                exchange.close()
            }
            else -> sendPlain(exchange, 405, "Method not allowed")
        }
    }

    private fun verifyDpopAuth(exchange: HttpExchange, expectedHtm: String, expectedHtu: String): Boolean {
        val authHeader = exchange.requestHeaders.getFirst("Authorization")
        val dpopHeader = exchange.requestHeaders.getFirst("DPoP")
        if (authHeader != "DPoP $expectedToken" || dpopHeader.isNullOrBlank()) {
            sendPlain(exchange, 401, "Missing DPoP Authorization or proof")
            return false
        }

        val segments = dpopHeader.split('.')
        if (segments.size != 3) {
            sendPlain(exchange, 401, "Malformed DPoP JWT")
            return false
        }

        val headerJson = String(DPoPSigner.base64UrlDecode(segments[0]), StandardCharsets.UTF_8)
        val payloadJson = String(DPoPSigner.base64UrlDecode(segments[1]), StandardCharsets.UTF_8)
        val sigBytes = DPoPSigner.base64UrlDecode(segments[2])

        val x = extractJsonString(headerJson, "x") ?: run {
            sendPlain(exchange, 401, "Missing JWK x")
            return false
        }
        val y = extractJsonString(headerJson, "y") ?: run {
            sendPlain(exchange, 401, "Missing JWK y")
            return false
        }

        val jkt = DPoPSigner.computeJwkThumbprint("P-256", x, y)
        if (expectedJkt.isNotEmpty() && jkt != expectedJkt) {
            sendPlain(exchange, 401, "DPoP JWK thumbprint mismatch")
            return false
        }

        val pubKey = reconstructP256PublicKey(x, y)
        val signingInput = "${segments[0]}.${segments[1]}".toByteArray(StandardCharsets.US_ASCII)
        if (!DPoPSigner.verifyEs256Signature(pubKey, signingInput, sigBytes)) {
            sendPlain(exchange, 401, "Invalid ES256 DPoP signature")
            return false
        }

        val htm = extractJsonString(payloadJson, "htm")
        val htu = extractJsonString(payloadJson, "htu")
        val ath = extractJsonString(payloadJson, "ath")
        val jti = extractJsonString(payloadJson, "jti")
        val nonce = extractJsonString(payloadJson, "nonce")

        if (htm != expectedHtm || htu != expectedHtu) {
            sendPlain(exchange, 401, "DPoP htm/htu mismatch")
            return false
        }
        if (ath != DPoPSigner.computeAccessTokenHash(expectedToken)) {
            sendPlain(exchange, 401, "DPoP ath mismatch")
            return false
        }
        if (jti.isNullOrBlank() || !seenDpopJtis.add("$jkt:$jti")) {
            sendPlain(exchange, 401, "DPoP jti replay detected")
            return false
        }

        val requiredNonce = requireServerNonce
        if (requiredNonce != null && nonce != requiredNonce) {
            exchange.responseHeaders.set("DPoP-Nonce", requiredNonce)
            sendPlain(exchange, 401, "use_dpop_nonce")
            return false
        }
        return true
    }

    private fun reconstructP256PublicKey(xB64: String, yB64: String): ECPublicKey {
        val x = BigInteger(1, DPoPSigner.base64UrlDecode(xB64))
        val y = BigInteger(1, DPoPSigner.base64UrlDecode(yB64))
        val params = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }
        val ecSpec = params.getParameterSpec(ECParameterSpec::class.java)
        return KeyFactory.getInstance("EC")
            .generatePublic(ECPublicKeySpec(ECPoint(x, y), ecSpec)) as ECPublicKey
    }

    private fun extractJsonString(json: String, key: String): String? {
        val regex = Regex("\"${Regex.escape(key)}\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"")
        return regex.find(json)?.groupValues?.get(1)
    }

    private fun computeEtag(bytes: ByteArray): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(bytes)
        val hex = hash.take(16).joinToString("") { "%02x".format(it) }
        return "\"$hex\""
    }

    private fun sendPlain(exchange: HttpExchange, status: Int, text: String) {
        val bytes = text.toByteArray(StandardCharsets.UTF_8)
        exchange.responseHeaders.set("Content-Type", "text/plain; charset=utf-8")
        exchange.sendResponseHeaders(status, bytes.size.toLong())
        exchange.responseBody.use { it.write(bytes) }
    }
}
