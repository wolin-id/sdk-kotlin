<div align="center">

# Wolin Kotlin SDK (`id.wolin:sdk-kotlin`)

**Official Zero-Dependency Kotlin, Android & JVM SDK for Wolin Sovereign Solid Pods**

[![CI](https://github.com/wolin-id/sdk-kotlin/actions/workflows/ci.yml/badge.svg)](https://github.com/wolin-id/sdk-kotlin/actions/workflows/ci.yml)
[![Kotlin](https://img.shields.io/badge/Kotlin-2.1%2B-7F52FF.svg)](https://kotlinlang.org)
[![JVM](https://img.shields.io/badge/JVM-17%2B-orange.svg)](https://openjdk.org/projects/jdk/17/)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

</div>

---

`id.wolin:sdk-kotlin` is the official client library for **[Wolin (月印千江)](https://wolin.id)** and any standards-compliant **W3C Solid 0.11** Pod server (including Wolin Engine, Inrupt ESS, and Community Solid Server).

Built purely on the **Kotlin standard library**, `java.net.http.HttpClient`, and `java.security.Signature` — with **zero third-party runtime dependencies**.

## Features

- **RFC 9449 DPoP (`ES256`) Proof-of-Possession**: Ephemeral or persistent NIST `P-256` (`secp256r1`) keypair signing using `SHA256withECDSA` with strict ASN.1 DER-to-IEEE-P1363 (64-byte `R || S`) conversion, `ath` access-token hash binding, and automatic `DPoP-Nonce` challenge retry.
- **RFC 7638 JWK Thumbprints (`jkt`)**: Canonical SHA-256 EC public JWK thumbprint calculation matching Solid-OIDC `cnf.jkt` token bindings.
- **WebID Profile & `pim:storage` Discovery**: Pure-stdlib W3C Turtle / N-Triples parser extracting `pim:storage`, `solid:oidcIssuer`, `ldp:inbox`, and `rdf:type` triples with RFC 8288 `Link: <http://www.w3.org/ns/pim/space#Storage>; rel="type"` container fallback.
- **Solid LDP CRUD + Optimistic Concurrency**: `HEAD`, `GET`, `PUT`, and `DELETE` operations with `ETag`, `If-Match`, and `If-None-Match` (`createIfAbsent` / `getIfModified`) guards.

---

## Installation

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("id.wolin:sdk-kotlin:0.1.0")
}
```

---

## Quickstart

```kotlin
import id.wolin.sdk.DPoPSigner
import id.wolin.sdk.WolinClient

fun main() {
    // 1. Generate (or load) the P-256 DPoP keypair bound to your Solid-OIDC access token
    val signer = DPoPSigner.generate()
    println("Client JWK Thumbprint (cnf.jkt): ${signer.jwkThumbprint}")

    val client = WolinClient(
        accessToken = "<solid-oidc-dpop-bound-access-token>",
        dpopSigner = signer,
    )

    // 2. Dereference WebID Profile & discover Sovereign Pod pim:storage root
    val webId = "https://alice.wolin.id/profile/card#me"
    val storageRoot = client.discoverStorage(webId)

    // 3. Create an RDF resource with If-None-Match: *
    val noteUrl = client.resolveResourceUrl(storageRoot, "notes/hello.ttl")
    val created = client.createIfAbsent(
        url = noteUrl,
        body = """
            @prefix dct: <http://purl.org/dc/terms/> .
            <#it> dct:title "Hello from Wolin Kotlin SDK" .
        """.trimIndent(),
    )

    // 4. Read & perform optimistic-concurrency update via ETag (If-Match)
    val current = client.get(noteUrl)
    val updated = client.put(
        url = noteUrl,
        body = """
            @prefix dct: <http://purl.org/dc/terms/> .
            <#it> dct:title "Updated atomically with If-Match" .
        """.trimIndent(),
        ifMatch = current.etag,
    )

    // 5. Conditional DELETE with latest ETag
    client.delete(noteUrl, ifMatch = updated.etag)
}
```

---

## Package Layout

| Source File | Responsibility |
| :--- | :--- |
| `id.wolin.sdk.WolinClient` | Solid-OIDC + DPoP HTTP client, `DPoP-Nonce` retry, WebID discovery, and LDP `HEAD`/`GET`/`PUT`/`DELETE` |
| `id.wolin.sdk.DPoPSigner` | NIST P-256 `SHA256withECDSA` signer, ASN.1 DER ↔ IEEE P1363 converter, RFC 9449 proofs, RFC 7638 `jkt` |
| `id.wolin.sdk.WebIdParser` | Pure-stdlib W3C Turtle & N-Triples lexer/parser for Solid WebID profiles and `pim:storage` discovery |
| `id.wolin.sdk.PodResource` | Immutable LDP resource representation, RFC 8288 `Link` parser, and typed `WolinHttpException` errors |

---

## Building & Testing

Requires JDK 17+ (produces strict JVM 17 bytecode via `-Xjdk-release=17` and `--release 17`):

```bash
./gradlew check
```

---

## License

Copyright (c) 2026 [Entropy Paradox, Inc.](https://wolin.id)

Dual-licensed under either of:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
