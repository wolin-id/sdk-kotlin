package id.wolin.sdk

import java.net.URI
import java.nio.charset.StandardCharsets

/**
 * Base runtime exception for all Wolin SDK errors (cryptographic, RDF parsing, URI validation, or HTTP).
 */
open class WolinException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * Exception raised when a Solid Pod server returns a non-success HTTP status code.
 */
class WolinHttpException(
    val statusCode: Int,
    val url: String,
    val responseBody: String,
    val headers: Map<String, List<String>> = emptyMap(),
    message: String = "Solid LDP HTTP $statusCode for $url" +
        if (responseBody.isNotBlank()) ": ${responseBody.take(240)}" else "",
) : WolinException(message) {
    val isUnauthorized: Boolean get() = statusCode == 401
    val isForbidden: Boolean get() = statusCode == 403
    val isNotFound: Boolean get() = statusCode == 404
    val isConflict: Boolean get() = statusCode == 409
    val isPreconditionFailed: Boolean get() = statusCode == 412

    /** RFC 9449 §8 `DPoP-Nonce` challenge header, if supplied by the server. */
    val dpopNonce: String?
        get() = HeaderUtils.firstHeader(headers, "dpop-nonce")
}

/**
 * Parsed RFC 8288 HTTP `Link` header entry (`<target>; rel="..."`).
 */
data class LinkRelation(
    val target: String,
    val rel: String,
    val params: Map<String, String> = emptyMap(),
)

/**
 * Immutable representation of a W3C Solid LDP Resource (`RDFSource`, `NonRDFSource`, or `BasicContainer`).
 */
data class PodResource(
    val url: String,
    val body: ByteArray,
    val contentType: String?,
    val etag: String?,
    val statusCode: Int,
    val headers: Map<String, List<String>> = emptyMap(),
) {
    /** Decodes [body] as UTF-8 text (e.g., `text/turtle` or `application/ld+json`). */
    val text: String
        get() = body.toString(StandardCharsets.UTF_8)

    /** True when the resource was newly created (`201 Created`). */
    val created: Boolean
        get() = statusCode == 201

    /** Resolved `Location` response header if present. */
    val location: String?
        get() = HeaderUtils.firstHeader(headers, "location")

    /** All RFC 8288 `Link` relations returned on this resource. */
    val links: List<LinkRelation>
        get() = HeaderUtils.parseLinkHeaders(headers, url)

    /** Set of `rel="type"` IRIs advertised via HTTP `Link` headers. */
    val linkTypes: Set<String>
        get() = links.filter { it.rel.equals("type", ignoreCase = true) }.mapTo(linkedSetOf()) { it.target }

    /** Auxiliary WAC `.acl` URL advertised via `Link: <...>; rel="acl"`, if present. */
    val aclUrl: String?
        get() = links.firstOrNull { it.rel.equals("acl", ignoreCase = true) }?.target

    /** True when this resource is an LDP Container (`ldp:BasicContainer` / `ldp:Container` or trailing `/`). */
    val isContainer: Boolean
        get() = linkTypes.contains(LDP_BASIC_CONTAINER) ||
            linkTypes.contains(LDP_CONTAINER) ||
            url.substringBefore('?').substringBefore('#').endsWith('/')

    /** True when this resource advertises `<http://www.w3.org/ns/pim/space#Storage>; rel="type"`. */
    val isStorageRoot: Boolean
        get() = linkTypes.contains(PIM_STORAGE_CLASS)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PodResource) return false
        return url == other.url &&
            body.contentEquals(other.body) &&
            contentType == other.contentType &&
            etag == other.etag &&
            statusCode == other.statusCode &&
            headers == other.headers
    }

    override fun hashCode(): Int {
        var result = url.hashCode()
        result = 31 * result + body.contentHashCode()
        result = 31 * result + (contentType?.hashCode() ?: 0)
        result = 31 * result + (etag?.hashCode() ?: 0)
        result = 31 * result + statusCode
        result = 31 * result + headers.hashCode()
        return result
    }

    companion object {
        const val LDP_CONTAINER = "http://www.w3.org/ns/ldp#Container"
        const val LDP_BASIC_CONTAINER = "http://www.w3.org/ns/ldp#BasicContainer"
        const val LDP_RDF_SOURCE = "http://www.w3.org/ns/ldp#RDFSource"
        const val LDP_NON_RDF_SOURCE = "http://www.w3.org/ns/ldp#NonRDFSource"
        const val PIM_STORAGE_CLASS = "http://www.w3.org/ns/pim/space#Storage"
    }
}

internal object HeaderUtils {
    fun firstHeader(headers: Map<String, List<String>>, name: String): String? =
        headers.entries
            .firstOrNull { it.key.equals(name, ignoreCase = true) }
            ?.value
            ?.firstOrNull { it.isNotBlank() }
            ?.trim()

    fun allHeaders(headers: Map<String, List<String>>, name: String): List<String> =
        headers.entries
            .filter { it.key.equals(name, ignoreCase = true) }
            .flatMap { it.value }

    /**
     * Parses RFC 8288 `Link` headers, supporting multiple comma-separated link-values per header line.
     */
    fun parseLinkHeaders(headers: Map<String, List<String>>, baseUrl: String? = null): List<LinkRelation> {
        val rawHeaders = allHeaders(headers, "link")
        if (rawHeaders.isEmpty()) return emptyList()

        val results = mutableListOf<LinkRelation>()
        for (headerLine in rawHeaders) {
            for (entry in splitLinkEntries(headerLine)) {
                val trimmed = entry.trim()
                if (!trimmed.startsWith('<')) continue
                val closeIdx = trimmed.indexOf('>')
                if (closeIdx <= 1) continue

                val rawTarget = trimmed.substring(1, closeIdx).trim()
                val resolvedTarget = if (baseUrl != null) {
                    runCatching { WebIdParser.resolveIri(rawTarget, baseUrl) }.getOrDefault(rawTarget)
                } else {
                    rawTarget
                }

                val params = linkedMapOf<String, String>()
                val rest = trimmed.substring(closeIdx + 1)
                for (paramPart in splitSemicolonParams(rest)) {
                    val eqIdx = paramPart.indexOf('=')
                    if (eqIdx <= 0) continue
                    val key = paramPart.substring(0, eqIdx).trim().lowercase()
                    var value = paramPart.substring(eqIdx + 1).trim()
                    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
                        value = value.substring(1, value.length - 1).replace("\\\"", "\"")
                    }
                    params[key] = value
                }

                val relField = params["rel"] ?: continue
                for (relToken in relField.split(' ').filter { it.isNotBlank() }) {
                    results.add(LinkRelation(target = resolvedTarget, rel = relToken, params = params))
                }
            }
        }
        return results
    }

    private fun splitLinkEntries(line: String): List<String> {
        val parts = mutableListOf<String>()
        var start = 0
        var inAngle = false
        var inQuotes = false
        var i = 0
        while (i < line.length) {
            val c = line[i]
            when {
                c == '\\' && inQuotes -> i++
                c == '"' && !inAngle -> inQuotes = !inQuotes
                c == '<' && !inQuotes -> inAngle = true
                c == '>' && !inQuotes -> inAngle = false
                c == ',' && !inAngle && !inQuotes -> {
                    parts.add(line.substring(start, i))
                    start = i + 1
                }
            }
            i++
        }
        if (start <= line.length) {
            parts.add(line.substring(start))
        }
        return parts
    }

    private fun splitSemicolonParams(segment: String): List<String> {
        val parts = mutableListOf<String>()
        var start = 0
        var inQuotes = false
        var i = 0
        while (i < segment.length) {
            val c = segment[i]
            when {
                c == '\\' && inQuotes -> i++
                c == '"' -> inQuotes = !inQuotes
                c == ';' && !inQuotes -> {
                    if (i > start) parts.add(segment.substring(start, i))
                    start = i + 1
                }
            }
            i++
        }
        if (start < segment.length) {
            parts.add(segment.substring(start))
        }
        return parts
    }

    fun validateHttpUri(rawUrl: String): URI {
        val trimmed = rawUrl.trim()
        if (trimmed.isEmpty()) {
            throw WolinException("URI must not be empty")
        }
        val uri = try {
            URI(trimmed)
        } catch (e: Exception) {
            throw WolinException("Malformed URI '$rawUrl': ${e.message}", e)
        }
        val scheme = uri.scheme?.lowercase()
        if (scheme != "http" && scheme != "https") {
            throw WolinException("Unsupported URI scheme '${uri.scheme}': expected 'http' or 'https'")
        }
        if (uri.rawUserInfo != null) {
            throw WolinException("Userinfo credentials are forbidden in Solid URIs")
        }
        if (uri.host.isNullOrBlank()) {
            throw WolinException("URI '$rawUrl' is missing a valid host")
        }
        return uri
    }
}
