package id.wolin.sdk

import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.atomic.AtomicReference

/**
 * Official Wolin Sovereign Solid Pod Client for Kotlin, Android, and JVM.
 *
 * Implements:
 * - **Solid-OIDC + RFC 9449 DPoP (`ES256`)** proof-of-possession request signing & `DPoP-Nonce` challenge retry
 * - **WebID Profile dereferencing** & **`pim:storage` root discovery** (Turtle triples + RFC 8288 `Link` fallback)
 * - **W3C Solid LDP CRUD (`HEAD` / `GET` / `PUT` / `DELETE`)** with **`ETag` / `If-Match` / `If-None-Match`** optimistic concurrency
 */
class WolinClient @JvmOverloads constructor(
    val accessToken: String? = null,
    val dpopSigner: DPoPSigner = DPoPSigner.generate(),
    private val httpClient: HttpClient = defaultHttpClient(),
    private val requestTimeout: Duration = DEFAULT_REQUEST_TIMEOUT,
    private val userAgent: String = DEFAULT_USER_AGENT,
) {
    private val cachedDpopNonce = AtomicReference<String?>(null)

    init {
        if (accessToken != null && accessToken.isBlank()) {
            throw WolinException("accessToken must be null (unauthenticated) or a non-blank token")
        }
    }

    /**
     * Returns a shallow copy of this client bound to a new [accessToken] (and optional [dpopSigner]).
     */
    @JvmOverloads
    fun withCredentials(
        accessToken: String?,
        dpopSigner: DPoPSigner = this.dpopSigner,
    ): WolinClient = WolinClient(
        accessToken = accessToken,
        dpopSigner = dpopSigner,
        httpClient = httpClient,
        requestTimeout = requestTimeout,
        userAgent = userAgent,
    )

    /**
     * Dereferences a Solid WebID URI (`https://.../profile/card#me`) and parses its Turtle profile graph.
     */
    fun fetchWebIdProfile(webId: String): WebIdProfile {
        HeaderUtils.validateHttpUri(webId)
        val documentUrl = webId.substringBefore('#')
        val response = get(url = documentUrl, accept = PROFILE_ACCEPT)
        return WebIdParser.parseTurtle(
            turtle = response.text,
            webId = webId,
            baseIri = documentUrl,
        )
    }

    /**
     * Discovers the user's Solid Pod `pim:storage` root URL for [webId].
     *
     * 1. Dereferences the WebID Profile RDF document and checks `<webId> pim:storage <storageUrl>`.
     * 2. Falls back to W3C Solid Protocol §4.1 container hierarchy traversal inspecting
     *    `Link: <http://www.w3.org/ns/pim/space#Storage>; rel="type"` headers.
     */
    fun discoverStorage(webId: String): String {
        val profile = fetchWebIdProfile(webId)
        profile.primaryStorage?.let { return ensureTrailingSlash(it) }

        val docUri = HeaderUtils.validateHttpUri(webId.substringBefore('#'))
        for (candidate in ancestorContainers(docUri)) {
            val probe = try {
                head(candidate)
            } catch (_: WolinException) {
                continue
            }
            if (probe.isStorageRoot) {
                return ensureTrailingSlash(candidate)
            }
        }

        throw WolinException("No pim:storage root discovered for WebID '$webId'")
    }

    /**
     * Resolves a relative path safely within a Pod [storageRoot], rejecting path-traversal escapes (`..`)
     * outside the storage root.
     */
    fun resolveResourceUrl(storageRoot: String, relativePath: String): String {
        val normalizedRoot = ensureTrailingSlash(storageRoot)
        val rootUri = HeaderUtils.validateHttpUri(normalizedRoot)
        val cleanRel = relativePath.trim().trimStart('/')
        if (cleanRel.isEmpty()) return normalizedRoot

        val resolved = try {
            rootUri.resolve(cleanRel).normalize()
        } catch (e: Exception) {
            throw WolinException("Invalid relative resource path '$relativePath': ${e.message}", e)
        }
        val resolvedStr = resolved.toString()
        if (!resolvedStr.startsWith(normalizedRoot)) {
            throw WolinException("Relative path '$relativePath' escapes Pod storage root '$normalizedRoot'")
        }
        return resolvedStr
    }

    /**
     * Executes an HTTP `HEAD` request against a Solid LDP resource to inspect `ETag` and `Link` metadata.
     */
    fun head(url: String): PodResource =
        sendLdpRequest(
            method = "HEAD",
            url = url,
            headers = mapOf("Accept" to DEFAULT_ACCEPT),
            body = null,
            expectedStatuses = SUCCESS_STATUSES,
        )

    /**
     * Fetches a Solid LDP resource via `GET`, returning its payload, `Content-Type`, and `ETag`.
     *
     * @param ifMatch Optional `If-Match` precondition (raises [WolinHttpException] with status 412 on mismatch).
     */
    @JvmOverloads
    fun get(
        url: String,
        accept: String = DEFAULT_ACCEPT,
        ifMatch: String? = null,
    ): PodResource {
        val headers = linkedMapOf("Accept" to accept)
        if (!ifMatch.isNullOrBlank()) {
            headers["If-Match"] = ifMatch
        }
        return sendLdpRequest(
            method = "GET",
            url = url,
            headers = headers,
            body = null,
            expectedStatuses = SUCCESS_STATUSES,
        )
    }

    /**
     * Performs a conditional `GET` with `If-None-Match: <etag>`.
     *
     * @return Updated [PodResource] if modified (`200 OK`), or `null` if unchanged (`304 Not Modified`).
     */
    @JvmOverloads
    fun getIfModified(
        url: String,
        etag: String,
        accept: String = DEFAULT_ACCEPT,
    ): PodResource? {
        require(etag.isNotBlank()) { "etag for getIfModified must not be blank" }
        val response = sendRawWithAuthRetry(
            method = "GET",
            uri = HeaderUtils.validateHttpUri(url),
            headers = mapOf(
                "Accept" to accept,
                "If-None-Match" to etag,
            ),
            body = null,
        )
        return when (val status = response.statusCode()) {
            304 -> null
            in 200..299 -> toPodResource(url, response)
            else -> throw toHttpException(url, response)
        }
    }

    /**
     * Creates or replaces a Solid LDP resource via `PUT` with optional optimistic concurrency headers.
     *
     * @param ifMatch Optimistic concurrency guard (`If-Match: "<etag>"`) for safe read-modify-write updates.
     * @param ifNoneMatch Precondition guard (e.g., `If-None-Match: *` to prevent overwriting an existing resource).
     * @param linkTypes Optional LDP type IRIs sent as `Link: <iri>; rel="type"`.
     */
    @JvmOverloads
    fun put(
        url: String,
        body: ByteArray,
        contentType: String = TURTLE_CONTENT_TYPE,
        ifMatch: String? = null,
        ifNoneMatch: String? = null,
        linkTypes: List<String> = emptyList(),
    ): PodResource {
        require(contentType.isNotBlank()) { "contentType must not be blank" }
        val headers = linkedMapOf("Content-Type" to contentType)
        if (!ifMatch.isNullOrBlank()) {
            headers["If-Match"] = ifMatch
        }
        if (!ifNoneMatch.isNullOrBlank()) {
            headers["If-None-Match"] = ifNoneMatch
        }
        if (linkTypes.isNotEmpty()) {
            headers["Link"] = linkTypes.joinToString(", ") { "<$it>; rel=\"type\"" }
        }
        return sendLdpRequest(
            method = "PUT",
            url = url,
            headers = headers,
            body = body,
            expectedStatuses = SUCCESS_STATUSES,
        )
    }

    /**
     * UTF-8 string overload of [put] (defaults to `Content-Type: text/turtle`).
     */
    @JvmOverloads
    fun put(
        url: String,
        body: String,
        contentType: String = TURTLE_CONTENT_TYPE,
        ifMatch: String? = null,
        ifNoneMatch: String? = null,
        linkTypes: List<String> = emptyList(),
    ): PodResource = put(
        url = url,
        body = body.toByteArray(StandardCharsets.UTF_8),
        contentType = contentType,
        ifMatch = ifMatch,
        ifNoneMatch = ifNoneMatch,
        linkTypes = linkTypes,
    )

    /**
     * Creates a Solid LDP resource only if it does not already exist (`If-None-Match: *`).
     * Throws [WolinHttpException] (`412 Precondition Failed`) if the resource already exists.
     */
    @JvmOverloads
    fun createIfAbsent(
        url: String,
        body: String,
        contentType: String = TURTLE_CONTENT_TYPE,
    ): PodResource = put(
        url = url,
        body = body.toByteArray(StandardCharsets.UTF_8),
        contentType = contentType,
        ifNoneMatch = "*",
    )

    /**
     * Binary overload of [createIfAbsent] (`If-None-Match: *`).
     */
    fun createIfAbsent(
        url: String,
        body: ByteArray,
        contentType: String,
    ): PodResource = put(
        url = url,
        body = body,
        contentType = contentType,
        ifNoneMatch = "*",
    )

    /**
     * Deletes a Solid LDP resource via `DELETE` with optional `If-Match` ETag guard.
     */
    @JvmOverloads
    fun delete(
        url: String,
        ifMatch: String? = null,
    ) {
        val headers = linkedMapOf<String, String>()
        if (!ifMatch.isNullOrBlank()) {
            headers["If-Match"] = ifMatch
        }
        sendLdpRequest(
            method = "DELETE",
            url = url,
            headers = headers,
            body = null,
            expectedStatuses = SUCCESS_STATUSES,
        )
    }

    private fun sendLdpRequest(
        method: String,
        url: String,
        headers: Map<String, String>,
        body: ByteArray?,
        expectedStatuses: IntRange,
    ): PodResource {
        val uri = HeaderUtils.validateHttpUri(url)
        val response = sendRawWithAuthRetry(method, uri, headers, body)
        if (response.statusCode() !in expectedStatuses) {
            throw toHttpException(url, response)
        }
        return toPodResource(url, response)
    }

    private fun sendRawWithAuthRetry(
        method: String,
        uri: URI,
        headers: Map<String, String>,
        body: ByteArray?,
    ): HttpResponse<ByteArray> {
        val initialNonce = cachedDpopNonce.get()
        val firstResponse = executeOnce(method, uri, headers, body, initialNonce)
        val serverNonce = HeaderUtils.firstHeader(firstResponse.headers().map(), "dpop-nonce")
        if (!serverNonce.isNullOrBlank()) {
            cachedDpopNonce.set(serverNonce)
        }

        // RFC 9449 §8: retry once with fresh DPoP proof when server issues a new DPoP-Nonce on 401/400
        if (accessToken != null &&
            (firstResponse.statusCode() == 401 || firstResponse.statusCode() == 400) &&
            !serverNonce.isNullOrBlank() &&
            serverNonce != initialNonce
        ) {
            return executeOnce(method, uri, headers, body, serverNonce)
        }
        return firstResponse
    }

    private fun executeOnce(
        method: String,
        uri: URI,
        headers: Map<String, String>,
        body: ByteArray?,
        dpopNonce: String?,
    ): HttpResponse<ByteArray> {
        val reqBuilder = HttpRequest.newBuilder(uri)
            .timeout(requestTimeout)
            .header("User-Agent", userAgent)

        for ((name, value) in headers) {
            reqBuilder.header(name, value)
        }

        if (accessToken != null) {
            val proof = dpopSigner.signProof(
                htm = method,
                htu = uri.toString(),
                accessToken = accessToken,
                nonce = dpopNonce,
            )
            reqBuilder.header("Authorization", "DPoP $accessToken")
            reqBuilder.header("DPoP", proof)
        }

        val publisher = if (body != null) {
            HttpRequest.BodyPublishers.ofByteArray(body)
        } else {
            HttpRequest.BodyPublishers.noBody()
        }
        reqBuilder.method(method, publisher)

        return try {
            httpClient.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofByteArray())
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw WolinException("Interrupted during Solid HTTP $method $uri", e)
        } catch (e: IOException) {
            throw WolinException("Network I/O error during Solid HTTP $method $uri: ${e.message}", e)
        }
    }

    private fun toPodResource(requestUrl: String, response: HttpResponse<ByteArray>): PodResource {
        val headerMap = response.headers().map()
        return PodResource(
            url = requestUrl,
            body = response.body() ?: ByteArray(0),
            contentType = HeaderUtils.firstHeader(headerMap, "content-type"),
            etag = HeaderUtils.firstHeader(headerMap, "etag"),
            statusCode = response.statusCode(),
            headers = headerMap,
        )
    }

    private fun toHttpException(requestUrl: String, response: HttpResponse<ByteArray>): WolinHttpException {
        val bodyText = response.body()?.toString(StandardCharsets.UTF_8).orEmpty()
        return WolinHttpException(
            statusCode = response.statusCode(),
            url = requestUrl,
            responseBody = bodyText,
            headers = response.headers().map(),
        )
    }

    private fun ensureTrailingSlash(url: String): String =
        if (url.endsWith('/')) url else "$url/"

    private fun ancestorContainers(uri: URI): List<String> {
        val scheme = uri.scheme.lowercase()
        val authority = uri.rawAuthority
        val origin = "$scheme://$authority"
        val segments = (uri.rawPath ?: "/")
            .split('/')
            .filter { it.isNotEmpty() }

        val containers = ArrayList<String>(segments.size + 1)
        val dropCount = if ((uri.rawPath ?: "/").endsWith('/')) 0 else 1
        val startDepth = (segments.size - dropCount).coerceAtLeast(0)
        for (depth in startDepth downTo 1) {
            containers.add("$origin/${segments.subList(0, depth).joinToString("/")}/")
        }
        containers.add("$origin/")
        return containers.distinct()
    }

    /**
     * Fluent builder for Java & Android interoperability.
     */
    class Builder {
        private var accessToken: String? = null
        private var dpopSigner: DPoPSigner? = null
        private var httpClient: HttpClient? = null
        private var requestTimeout: Duration = DEFAULT_REQUEST_TIMEOUT
        private var userAgent: String = DEFAULT_USER_AGENT

        fun accessToken(accessToken: String?) = apply { this.accessToken = accessToken }
        fun dpopSigner(dpopSigner: DPoPSigner) = apply { this.dpopSigner = dpopSigner }
        fun httpClient(httpClient: HttpClient) = apply { this.httpClient = httpClient }
        fun requestTimeout(requestTimeout: Duration) = apply { this.requestTimeout = requestTimeout }
        fun userAgent(userAgent: String) = apply { this.userAgent = userAgent }

        fun build(): WolinClient = WolinClient(
            accessToken = accessToken,
            dpopSigner = dpopSigner ?: DPoPSigner.generate(),
            httpClient = httpClient ?: defaultHttpClient(),
            requestTimeout = requestTimeout,
            userAgent = userAgent,
        )
    }

    companion object {
        const val TURTLE_CONTENT_TYPE = "text/turtle"
        const val DEFAULT_ACCEPT = "text/turtle, application/ld+json;q=0.9, */*;q=0.8"
        const val PROFILE_ACCEPT = "text/turtle, application/n-triples;q=0.9, text/n3;q=0.8"
        const val DEFAULT_USER_AGENT = "wolin-sdk-kotlin/0.1.0 (+https://wolin.id)"

        private val DEFAULT_REQUEST_TIMEOUT: Duration = Duration.ofSeconds(30)
        private val SUCCESS_STATUSES: IntRange = 200..299

        @JvmStatic
        fun builder(): Builder = Builder()

        /**
         * Creates a hardened default [HttpClient] with `Redirect.NEVER` so DPoP `Authorization`
         * and `DPoP` headers are never forwarded across origins or mismatched `htu` targets.
         */
        @JvmStatic
        fun defaultHttpClient(connectTimeout: Duration = Duration.ofSeconds(15)): HttpClient =
            HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(connectTimeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build()
    }
}
