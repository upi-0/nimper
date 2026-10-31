#
#          curl-impersonate Wrapper for Nim
#        Main Module Entry Point
#

## `nimper` is a comprehensive Nim wrapper for `libcurl-impersonate` (v2.3.x / curl 8.23.0-IMPERSONATE).
##
## It provides:
## - **`nimper/abi`**: Full low-level C API bindings (`easy_impersonate`, `easy_*`, `multi_*`, `share_*`,
##   `mime_*`, `url_*`, `ws_*`, `easy_header`, `easy_option_*`, plus all `OPT_*` and `INFO_*` constants,
##   and drop-in compatibility with Nim's `libcurl` module).
## - **`nimper/targets`**: Browser impersonation target enum (`ImpersonateTarget`), metadata (`TargetInfo`),
##   and target name/alias resolution (`parseImpersonateTarget`).
## - **`nimper/webcrypto`**: BoringSSL WebCrypto bindings (`<curl-impersonate/webcrypto.h>`) for SHA, HMAC,
##   HKDF, PBKDF2, AES-GCM/CBC/CTR/KW, RSA, ECDSA, and ECDH.
## - **`nimper/client`**: High-level ergonomic HTTP/HTTPS client & persistent session API (`ImpersonateSession`,
##   `Request`, `Response`, `get`, `post`, `put`, `patch`, `delete`, `head`, `fetch`, redirect history, cookie changes,
##   SSRF-safe redirects, and custom TLS/HTTP2/HTTP3/QUIC fingerprint overrides).

import nimper/[abi, targets, webcrypto, client]
export abi, targets, webcrypto, client
