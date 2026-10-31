# `nimper` — Nim Wrapper for `curl-impersonate`

A complete, idiomatic Nim module wrapping [`libcurl-impersonate`](https://github.com/lexiforest/curl-impersonate) (v2.3.x / `curl 8.23.0-IMPERSONATE`), enabling Nim applications to perform HTTP/1.1, HTTP/2, HTTP/3 (QUIC), and WebSocket requests with authentic browser TLS (BoringSSL), HTTP/2, and HTTP/3 fingerprints (Chrome, Firefox, Safari, Edge, and Tor).

---

## Features

- **Full Low-Level C ABI (`nimper/abi`)**:
  - `curl_easy_impersonate` and all `curl-impersonate` custom `CURLOPT_*` (`1000..1041`) and `CURLINFO_*` (`CURLINFO_COOKIECHANGES`, `CURLINFO_REDIRECT_HISTORY`, `CURLFOLLOW_SAFE`, `CURLWS_PERMESSAGE_DEFLATE`).
  - Complete bindings for `easy`, `multi`, `share`, `mime`, `url` (`CURLU`), `header` (`curl_easy_header`), `options` (`curl_easy_option_*`), and `websockets` (`curl_ws_*`).
  - Drop-in backwards compatibility with Nim's standard `libcurl` package (`PCurl`, `Option`, `Code`, `INFO`, `easy_init`, `easy_setopt`, `easy_perform`, etc.).
- **Strongly-Typed Browser Targets (`nimper/targets`)**:
  - Enum (`ImpersonateTarget`) and metadata (`TargetInfo`) for all 47+ browser profiles (`chrome99`..`chrome152_macos`, `firefox133`..`firefox155`, `safari153`..`safari270_ios`, `edge99`..`edge101`, `tor145`), plus convenient aliases (`"chrome"`, `"firefox"`, `"safari"`, `"edge"`, `"tor"`).
- **High-Level Ergonomic HTTP Client & Sessions (`nimper/client`)**:
  - One-liner `get`, `post`, `put`, `patch`, `delete`, `head`, and `fetch` procs with browser impersonation.
  - Persistent `ImpersonateSession` for connection pooling, TLS session ticket reuse, DNS caching, and automatic cookie management.
  - Native support for `CURLINFO_REDIRECT_HISTORY` (`response.redirectHistory`), `CURLINFO_COOKIECHANGES` (`response.cookieChanges`), SSRF-safe redirects (`safeRedirects = true`), multipart MIME uploads (`MimePartSpec`), and fine-grained TLS/H2/H3/QUIC fingerprint overrides (`FingerprintConfig`).
- **BoringSSL WebCrypto Primitives (`nimper/webcrypto`)**:
  - Wraps `<curl-impersonate/webcrypto.h>` (`bssl_webcrypto_*`) for SHA-1/256/384/512, HMAC, HKDF, PBKDF2, AES-GCM/CBC/CTR/KW, RSA, ECDSA (P-256/P-384/P-521), and ECDH using the exact BoringSSL instance linked into `libcurl-impersonate`.

---

## Quick Start

### 1. High-Level Requests

```nim
import nimper

# Impersonate Chrome 152 (with default browser headers & automatic br/zstd/gzip decompression)
let resp = get("https://tls.browserleaks.com/json", target = itChrome152)
echo "Status: ", resp.statusCode
echo "Body: ", resp.body

# Impersonate Firefox 155 with custom headers
let ffResp = post(
  "https://httpbin.org/post",
  body = """{"hello": "nim"}""",
  target = itFirefox155,
  headers = {"Content-Type": "application/json"}
)
echo ffResp.body
```

### 2. Persistent Session with Cookies & Redirect History

```nim
import nimper

let session = newImpersonateSession(target = itSafari270)
defer: session.close()

let r1 = session.get("https://httpbin.org/cookies/set/token/xyz987")
for change in r1.cookieChanges:
  echo "Cookie mutation: ", change.action, " ", change.name, "=", change.value

for hop in r1.redirectHistory:
  echo "Redirected from: ", hop.statusCode, " -> ", hop.url
```

### 3. Low-Level `libcurl-impersonate` C API

```nim
import nimper

let curl = easy_init()
defer: easy_cleanup(curl)

discard easy_impersonate(curl, "chrome152", 1)
discard easy_setopt(curl, OPT_URL, "https://example.com".cstring)
let res = easy_perform(curl)
if res != E_OK:
  echo "Error: ", easy_strerror(res)
```

### 4. Custom Library Path

By default, `nimper` searches `~/.local/lib`, `/usr/local/lib`, and system library paths for `libcurl-impersonate.so`. You can override the library name/path at compile time with `-d:curlImpLib=/path/to/libcurl-impersonate.so`.
