#
#          curl-impersonate Wrapper for Nim
#        High-Level Ergonomic HTTP/HTTPS/H2/H3/WebSocket Client & Session API
#

## High-level, idiomatic Nim HTTP/HTTPS/WebSocket client powered by `libcurl-impersonate`.
##
## Features:
## - One-call browser impersonation (`target = itChrome152`, `itFirefox155`, `itSafari270`, etc. or string names)
## - Automatic response decompression (`gzip`, `deflate`, `br` / Brotli, `zstd`) handled natively by `libcurl-impersonate`
## - Persistent `ImpersonateSession` reusing connections, TLS session tickets, DNS cache, and cookies across requests
## - Full support for `curl-impersonate` advanced options:
##   - SSRF-safe redirects (`safeRedirects = true` -> `CURLFOLLOW_SAFE`)
##   - Redirect history inspection (`response.redirectHistory` via `CURLINFO_REDIRECT_HISTORY`)
##   - Server cookie mutation tracking (`response.cookieChanges` via `CURLINFO_COOKIECHANGES`)
##   - Custom TLS / HTTP2 / HTTP3 / QUIC fingerprint overrides (`FingerprintConfig`)
##   - Multipart MIME form uploads (`MimePartSpec`)

import std/[strutils, httpcore, tables, locks]
import ./[abi, targets]

type
  CurlImpersonateError* = object of IOError
    code*: Code

  RedirectHop* = object
    ## A single redirect response recorded by `CURLINFO_REDIRECT_HISTORY`.
    statusCode*: int
    url*: string
    raw*: string

  CookieChange* = object
    ## A server cookie mutation recorded by `CURLINFO_COOKIECHANGES`.
    action*: string  ## e.g. "SET" or "DELETE"
    domain*: string
    includeSubdomains*: bool
    path*: string
    secure*: bool
    expires*: int64
    name*: string
    value*: string
    raw*: string

  MimePartSpec* = object
    ## Represents a single part in a `multipart/form-data` request.
    name*: string
    content*: string
    filename*: string
    contentType*: string
    isFile*: bool  ## If true, `content` is treated as a local file path to stream via `curl_mime_filedata`.

  FingerprintConfig* = object
    ## Optional fine-grained overrides for TLS, HTTP/2, HTTP/3, and QUIC fingerprints
    ## applied after `curl_easy_impersonate`.
    ciphers*: string
    tls13Ciphers*: string
    curves*: string
    sigHashAlgs*: string
    certCompression*: string
    tlsExtensionOrder*: string
    tlsDelegatedCredentials*: string
    tlsTrustAnchors*: string
    tlsRecordSizeLimit*: int
    tlsKeySharesLimit*: int
    tlsGrease*: int               ## -1 = default, 0 = disable, 1 = enable
    tlsPermuteExtensions*: int    ## -1 = default, 0 = disable, 1 = enable
    tlsEnableAlps*: int           ## -1 = default, 0 = disable, 1 = enable
    tlsUseNewAlpsCodepoint*: int  ## -1 = default, 0 = disable, 1 = enable
    tlsEnableTicket*: int         ## -1 = default, 0 = disable, 1 = enable
    tlsSignedCertTimestamps*: int ## -1 = default, 0 = disable, 1 = enable
    tlsStatusRequest*: int        ## -1 = default, 0 = disable, 1 = enable
    http2PseudoHeadersOrder*: string
    http2Settings*: string
    http2WindowUpdate*: int
    http2Streams*: string
    http2NoPriority*: int         ## -1 = default, 0 = disable, 1 = enable
    http3PseudoHeadersOrder*: string
    http3Settings*: string
    http3SigHashAlgs*: string
    http3TlsExtensionOrder*: string
    http3Curves*: string
    http3PermuteExtensions*: int  ## -2 = unset, -1 = fallback, 0 = disable, 1 = enable
    quicTransportParameters*: string
    quicCidLength*: string
    quicInitialPacketNumber*: int ## 0 = unset, -1 = Firefox randomized, >0 = fixed
    httpHeaderOrder*: string
    splitCookies*: int            ## -1 = default, 0 = disable, 1 = enable
    formBoundary*: string

  Request* = object
    url*: string
    httpMethod*: string
    headers*: seq[(string, string)]
    body*: string
    mimeParts*: seq[MimePartSpec]
    target*: string
    defaultHeaders*: bool
    httpVersion*: abi.HTTP_VERSION
    timeoutMs*: int
    connectTimeoutMs*: int
    lowSpeedLimit*: int
    lowSpeedTimeSec*: int
    bufferSize*: int
    httpContentDecoding*: bool
    followRedirects*: bool
    safeRedirects*: bool
    maxRedirects*: int
    verifySsl*: bool
    caInfo*: string
    caPath*: string
    proxy*: string
    proxyAuth*: string
    cookie*: string
    cookieFile*: string
    cookieJar*: string
    acceptEncoding*: string
    share*: PSH
    fingerprint*: FingerprintConfig

  Response* = object
    statusCode*: int
    url*: string
    effectiveMethod*: string
    httpVersion*: int
    headers*: HttpHeaders
    rawHeaderLines*: seq[string]
    body*: string
    contentType*: string
    primaryIp*: string
    primaryPort*: int
    totalTime*: float64
    namelookupTime*: float64
    connectTime*: float64
    appconnectTime*: float64
    pretransferTime*: float64
    starttransferTime*: float64
    redirectTime*: float64
    redirectCount*: int
    redirectHistory*: seq[RedirectHop]
    cookies*: seq[string]
    cookieChanges*: seq[CookieChange]
    abortedByCallback*: bool

  StreamResponseHead* = object
    ## Metadata and headers delivered to `OnHeadersCallback` as soon as the final upstream
    ## HTTP header block is received (before body streaming begins).
    statusCode*: int
    httpVersion*: int
    url*: string
    effectiveMethod*: string
    headers*: HttpHeaders
    rawHeaderLines*: seq[string]
    redirectCount*: int

  OnHeadersCallback* = proc (head: StreamResponseHead): bool {.closure, gcsafe.}
    ## Invoked once when the final HTTP response header block completes.
    ## Return `false` to abort the transfer immediately.

  OnChunkCallback* = proc (data: pointer, len: int): bool {.closure, gcsafe.}
    ## Invoked for each chunk of response body data received from `libcurl-impersonate`.
    ## Return `false` to abort the transfer immediately (`CURLE_WRITE_ERROR`).

  OnProgressCallback* = proc (dlTotal, dlNow, ulTotal, ulNow: int64): bool {.closure, gcsafe.}
    ## Invoked periodically by `libcurl-impersonate` (`OPT_XFERINFOFUNCTION`).
    ## Return `false` to abort the transfer immediately (`CURLE_ABORTED_BY_CALLBACK`).

  ShareLocksBlock = object
    locks: array[ord(LOCK_DATA_LAST) + 1, Lock]

  ImpersonateShareObj = object
    handle*: PSH
    locksPtr: ptr ShareLocksBlock

  ImpersonateShare* = ref ImpersonateShareObj

  ImpersonateSessionObj = object
    handle*: PCurl
    target*: string
    defaultHeaders*: bool
    headers*: seq[(string, string)]
    timeoutMs*: int
    connectTimeoutMs*: int
    lowSpeedLimit*: int
    lowSpeedTimeSec*: int
    bufferSize*: int
    httpContentDecoding*: bool
    followRedirects*: bool
    safeRedirects*: bool
    maxRedirects*: int
    verifySsl*: bool
    proxy*: string
    cookieFile*: string
    cookieJar*: string
    httpVersion*: abi.HTTP_VERSION
    share*: PSH
    fingerprint*: FingerprintConfig

  ImpersonateSession* = ref ImpersonateSessionObj

  BufferWrap = object
    data: string

  StreamContext = object
    curl: PCurl
    followRedirects: bool
    maxRedirects: int
    headerLineBuf: string
    headers: HttpHeaders
    rawHeaderLines: seq[string]
    headersDelivered: bool
    abortedByCallback: bool
    onHeaders: OnHeadersCallback
    onChunk: OnChunkCallback
    onProgress: OnProgressCallback

var globalInitDone {.global.} = false

proc ensureGlobalInit*() =
  ## Ensures `curl_global_init(GLOBAL_DEFAULT)` has been called once.
  if not globalInitDone:
    let rc = global_init(GLOBAL_DEFAULT)
    if rc != E_OK:
      raise newException(CurlImpersonateError, "curl_global_init failed: " & $easy_strerror(rc))
    globalInitDone = true

proc initFingerprintConfig*(): FingerprintConfig =
  ## Returns a `FingerprintConfig` with all tri-state integer options set to unset (`-1` or `-2`).
  result.tlsGrease = -1
  result.tlsPermuteExtensions = -1
  result.tlsEnableAlps = -1
  result.tlsUseNewAlpsCodepoint = -1
  result.tlsEnableTicket = -1
  result.tlsSignedCertTimestamps = -1
  result.tlsStatusRequest = -1
  result.http2NoPriority = -1
  result.http3PermuteExtensions = -2
  result.splitCookies = -1

proc initRequest*(
  url: string,
  httpMethod: string = "GET",
  target: ImpersonateTarget | string = itChromeLatest,
  defaultHeaders: bool = true,
  headers: openArray[(string, string)] = [],
  body: string = "",
  timeoutMs: int = 30_000,
  connectTimeoutMs: int = 10_000,
  lowSpeedLimit: int = 0,
  lowSpeedTimeSec: int = 0,
  bufferSize: int = 0,
  httpContentDecoding: bool = true,
  followRedirects: bool = true,
  safeRedirects: bool = false,
  maxRedirects: int = 30,
  verifySsl: bool = true,
  proxy: string = "",
  httpVersion: abi.HTTP_VERSION = HTTP_VERSION_NONE,
  share: PSH = nil
): Request =
  ## Initializes a `Request` with sensible defaults for browser impersonation.
  result.url = url
  result.httpMethod = httpMethod.toUpperAscii()
  result.headers = @headers
  result.body = body
  when target is ImpersonateTarget:
    result.target = $target
  else:
    result.target = target
  result.defaultHeaders = defaultHeaders
  result.httpVersion = httpVersion
  result.timeoutMs = timeoutMs
  result.connectTimeoutMs = connectTimeoutMs
  result.lowSpeedLimit = lowSpeedLimit
  result.lowSpeedTimeSec = lowSpeedTimeSec
  result.bufferSize = bufferSize
  result.httpContentDecoding = httpContentDecoding
  result.followRedirects = followRedirects
  result.safeRedirects = safeRedirects
  result.maxRedirects = maxRedirects
  result.verifySsl = verifySsl
  result.proxy = proxy
  result.acceptEncoding = "" # Empty string tells libcurl to advertise all built-in encodings (gzip, deflate, br, zstd)
  result.share = share
  result.fingerprint = initFingerprintConfig()

{.push stackTrace: off.}
proc shareLockCallback(handle: PCurl, data: Lock_data, locktype: Lock_access, userptr: pointer) {.cdecl.} =
  if userptr != nil and ord(data) >= 0 and ord(data) <= ord(LOCK_DATA_LAST):
    let blk = cast[ptr ShareLocksBlock](userptr)
    acquire(blk.locks[ord(data)])

proc shareUnlockCallback(handle: PCurl, data: Lock_data, userptr: pointer) {.cdecl.} =
  if userptr != nil and ord(data) >= 0 and ord(data) <= ord(LOCK_DATA_LAST):
    let blk = cast[ptr ShareLocksBlock](userptr)
    release(blk.locks[ord(data)])
{.pop.}

proc cleanupShareObj(s: var ImpersonateShareObj) =
  if s.handle != nil:
    discard share_cleanup(s.handle)
    s.handle = nil
  if s.locksPtr != nil:
    for i in 0 .. ord(LOCK_DATA_LAST):
      deinitLock(s.locksPtr.locks[i])
    deallocShared(s.locksPtr)
    s.locksPtr = nil

when defined(gcDestructors):
  proc `=destroy`(s: var ImpersonateShareObj) =
    cleanupShareObj(s)

  proc `=destroy`(s: var ImpersonateSessionObj) =
    if s.handle != nil:
      easy_cleanup(s.handle)
      s.handle = nil

proc close*(share: ImpersonateShare) =
  ## Explicitly closes and cleans up the underlying `CURLSH*` handle and locks of `share`.
  if share != nil:
    cleanupShareObj(share[])

proc newImpersonateShare*(
  shareDns: bool = true,
  shareSslSession: bool = true,
  shareConnect: bool = true,
  shareCookies: bool = false
): ImpersonateShare =
  ## Creates a thread-safe `ImpersonateShare` (`CURLSH*`) that allows multiple `ImpersonateSession`
  ## or `Request` handles across worker threads to share DNS cache, TLS session tickets,
  ## and upstream TCP/TLS connection pools.
  ensureGlobalInit()
  let sh = share_init()
  if sh == nil:
    raise newException(CurlImpersonateError, "curl_share_init returned nil")

  let locksPtr = cast[ptr ShareLocksBlock](allocShared0(sizeof(ShareLocksBlock)))
  for i in 0 .. ord(LOCK_DATA_LAST):
    initLock(locksPtr.locks[i])

  new(result)
  result.handle = sh
  result.locksPtr = locksPtr

  discard share_setopt(sh, SHOPT_USERDATA, locksPtr)
  discard share_setopt(sh, SHOPT_LOCKFUNC, shareLockCallback)
  discard share_setopt(sh, SHOPT_UNLOCKFUNC, shareUnlockCallback)

  if shareDns:
    discard share_setopt(sh, SHOPT_SHARE, ord(LOCK_DATA_DNS).clong)
  if shareSslSession:
    discard share_setopt(sh, SHOPT_SHARE, ord(LOCK_DATA_SSL_SESSION).clong)
  if shareConnect:
    discard share_setopt(sh, SHOPT_SHARE, ord(LOCK_DATA_CONNECT).clong)
  if shareCookies:
    discard share_setopt(sh, SHOPT_SHARE, ord(LOCK_DATA_COOKIE).clong)

proc close*(session: ImpersonateSession) =
  ## Explicitly closes and cleans up the underlying `CURL*` handle of `session`.
  if session != nil and session.handle != nil:
    easy_cleanup(session.handle)
    session.handle = nil

proc newImpersonateSession*(
  target: ImpersonateTarget | string = itChromeLatest,
  defaultHeaders: bool = true,
  headers: openArray[(string, string)] = [],
  timeoutMs: int = 30_000,
  connectTimeoutMs: int = 10_000,
  lowSpeedLimit: int = 0,
  lowSpeedTimeSec: int = 0,
  bufferSize: int = 0,
  httpContentDecoding: bool = true,
  followRedirects: bool = true,
  safeRedirects: bool = false,
  maxRedirects: int = 30,
  verifySsl: bool = true,
  proxy: string = "",
  cookieFile: string = "",
  cookieJar: string = "",
  httpVersion: abi.HTTP_VERSION = HTTP_VERSION_NONE,
  share: PSH = nil
): ImpersonateSession =
  ## Creates a persistent `ImpersonateSession` that keeps a live `CURL*` handle
  ## for connection pooling, TLS session resumption, DNS caching, and in-memory cookie management.
  ensureGlobalInit()
  let h = easy_init()
  if h == nil:
    raise newException(CurlImpersonateError, "curl_easy_init returned nil")
  # Enable in-memory cookie engine by default (passing "" to CURLOPT_COOKIEFILE activates cookie engine without reading a file)
  discard easy_setopt(h, OPT_COOKIEFILE, cookieFile.cstring)
  if cookieJar.len > 0:
    discard easy_setopt(h, OPT_COOKIEJAR, cookieJar.cstring)
  if share != nil:
    discard easy_setopt(h, OPT_SHARE, share)

  new(result)
  result.handle = h
  when target is ImpersonateTarget:
    result.target = $target
  else:
    result.target = target
  result.defaultHeaders = defaultHeaders
  result.headers = @headers
  result.timeoutMs = timeoutMs
  result.connectTimeoutMs = connectTimeoutMs
  result.lowSpeedLimit = lowSpeedLimit
  result.lowSpeedTimeSec = lowSpeedTimeSec
  result.bufferSize = bufferSize
  result.httpContentDecoding = httpContentDecoding
  result.followRedirects = followRedirects
  result.safeRedirects = safeRedirects
  result.maxRedirects = maxRedirects
  result.verifySsl = verifySsl
  result.proxy = proxy
  result.cookieFile = cookieFile
  result.cookieJar = cookieJar
  result.httpVersion = httpVersion
  result.share = share
  result.fingerprint = initFingerprintConfig()

{.push stackTrace: off.}
proc writeCallback(buffer: cstring, size: int, nitems: int, outstream: pointer): int {.cdecl.} =
  let total = size * nitems
  if total > 0 and outstream != nil and buffer != nil:
    let wrap = cast[ptr BufferWrap](outstream)
    let oldLen = wrap.data.len
    wrap.data.setLen(oldLen + total)
    copyMem(addr wrap.data[oldLen], buffer, total)
  result = total
{.pop.}

proc buildStreamResponseHead(ctx: var StreamContext): StreamResponseHead =
  result.headers = newHttpHeaders()
  if ctx.headers != nil:
    for k, v in ctx.headers.pairs:
      result.headers.add(k, v)
  result.rawHeaderLines = ctx.rawHeaderLines

  var respCode: clong = 0
  if easy_getinfo(ctx.curl, INFO_RESPONSE_CODE, addr respCode) == E_OK:
    result.statusCode = int(respCode)

  var httpVer: clong = 0
  if easy_getinfo(ctx.curl, INFO_HTTP_VERSION, addr httpVer) == E_OK:
    result.httpVersion = int(httpVer)

  var effUrl: cstring = nil
  if easy_getinfo(ctx.curl, INFO_EFFECTIVE_URL, addr effUrl) == E_OK and effUrl != nil:
    result.url = $effUrl

  var effMethod: cstring = nil
  if easy_getinfo(ctx.curl, INFO_EFFECTIVE_METHOD, addr effMethod) == E_OK and effMethod != nil:
    result.effectiveMethod = $effMethod

  var redirCount: clong = 0
  if easy_getinfo(ctx.curl, INFO_REDIRECT_COUNT, addr redirCount) == E_OK:
    result.redirectCount = int(redirCount)

proc deliverHeadersIfNeeded(ctx: var StreamContext): bool =
  if ctx.headersDelivered:
    return true
  ctx.headersDelivered = true
  if ctx.onHeaders != nil:
    let head = buildStreamResponseHead(ctx)
    if not ctx.onHeaders(head):
      ctx.abortedByCallback = true
      return false
  return true

proc streamHeaderCallback(buffer: cstring, size: int, nitems: int, userdata: pointer): int {.cdecl.} =
  let total = size * nitems
  if total <= 0 or userdata == nil or buffer == nil:
    return total
  let ctx = cast[ptr StreamContext](userdata)
  var chunk = newString(total)
  copyMem(addr chunk[0], buffer, total)
  ctx.headerLineBuf.add(chunk)

  while true:
    let nlPos = ctx.headerLineBuf.find('\n')
    if nlPos < 0:
      break
    let rawLine = ctx.headerLineBuf[0 .. nlPos]
    if nlPos + 1 < ctx.headerLineBuf.len:
      ctx.headerLineBuf = ctx.headerLineBuf[nlPos + 1 .. ^1]
    else:
      ctx.headerLineBuf.setLen(0)

    let stripped = rawLine.strip()
    if stripped.len == 0:
      # End of an HTTP response header block
      var respCode: clong = 0
      discard easy_getinfo(ctx.curl, INFO_RESPONSE_CODE, addr respCode)
      let code = int(respCode)
      var redirCount: clong = 0
      discard easy_getinfo(ctx.curl, INFO_REDIRECT_COUNT, addr redirCount)

      let isInformational = (code >= 100 and code < 200 and code != 101)
      let isFollowedRedirect =
        ctx.followRedirects and
        code in [301, 302, 303, 307, 308] and
        ctx.headers != nil and ctx.headers.hasKey("location") and
        (ctx.maxRedirects < 0 or int(redirCount) < ctx.maxRedirects)

      if not isInformational and not isFollowedRedirect:
        if not deliverHeadersIfNeeded(ctx[]):
          return 0
    elif stripped.startsWith("HTTP/"):
      ctx.rawHeaderLines.add(stripped)
      if ctx.headers == nil:
        ctx.headers = newHttpHeaders()
      else:
        ctx.headers.clear()
    else:
      ctx.rawHeaderLines.add(stripped)
      let colonPos = stripped.find(':')
      if colonPos > 0:
        let key = stripped[0 ..< colonPos].strip()
        let val = stripped[colonPos + 1 .. ^1].strip()
        if ctx.headers == nil:
          ctx.headers = newHttpHeaders()
        ctx.headers.add(key, val)

  result = total

proc streamWriteCallback(buffer: cstring, size: int, nitems: int, outstream: pointer): int {.cdecl.} =
  let total = size * nitems
  if outstream == nil:
    return total
  let ctx = cast[ptr StreamContext](outstream)
  if not ctx.headersDelivered:
    if not deliverHeadersIfNeeded(ctx[]):
      return 0
  if total > 0 and buffer != nil and ctx.onChunk != nil:
    if not ctx.onChunk(buffer, total):
      ctx.abortedByCallback = true
      return 0
  result = total

proc streamXferInfoCallback(
  clientp: pointer,
  dltotal: CurlOffT,
  dlnow: CurlOffT,
  ultotal: CurlOffT,
  ulnow: CurlOffT
): int32 {.cdecl.} =
  if clientp == nil:
    return 0
  let ctx = cast[ptr StreamContext](clientp)
  if ctx.onProgress != nil:
    if not ctx.onProgress(int64(dltotal), int64(dlnow), int64(ultotal), int64(ulnow)):
      ctx.abortedByCallback = true
      return 1
  return 0

proc checkCode(code: Code, errBuf: cstring = nil) =
  if code != E_OK:
    var msg = $easy_strerror(code)
    if errBuf != nil and errBuf[0] != '\0':
      msg.add(" (" & $errBuf & ")")
    var exc = newException(CurlImpersonateError, msg)
    exc.code = code
    raise exc

proc parseRedirectHop*(line: string): RedirectHop =
  ## Parses a `CURLINFO_REDIRECT_HISTORY` entry formatted as `<status>\t<url>`.
  result.raw = line
  let tabIdx = line.find('\t')
  if tabIdx > 0:
    try:
      result.statusCode = parseInt(line[0 ..< tabIdx].strip())
    except ValueError:
      result.statusCode = 0
    result.url = line[tabIdx + 1 .. ^1]
  else:
    result.url = line

proc parseCookieChange*(line: string): CookieChange =
  ## Parses a `CURLINFO_COOKIECHANGES` entry formatted as `<SET|DELETE>\t<domain>\t<includeSubdomains>\t<path>\t<secure>\t<expires>\t<name>\t<value>`.
  result.raw = line
  let parts = line.split('\t')
  if parts.len >= 8:
    result.action = parts[0]
    result.domain = parts[1]
    result.includeSubdomains = cmpIgnoreCase(parts[2], "TRUE") == 0
    result.path = parts[3]
    result.secure = cmpIgnoreCase(parts[4], "TRUE") == 0
    try:
      result.expires = parseBiggestInt(parts[5])
    except ValueError:
      result.expires = 0
    result.name = parts[6]
    result.value = parts[7]
  elif parts.len >= 2:
    result.action = parts[0]
    result.name = parts[1]

proc applyFingerprintConfig(curl: PCurl, fp: FingerprintConfig) =
  if fp.ciphers.len > 0:
    checkCode easy_setopt(curl, OPT_SSL_CIPHER_LIST, fp.ciphers.cstring)
  if fp.tls13Ciphers.len > 0:
    checkCode easy_setopt(curl, OPT_TLS13_CIPHERS, fp.tls13Ciphers.cstring)
  if fp.curves.len > 0:
    checkCode easy_setopt(curl, OPT_SSL_EC_CURVES, fp.curves.cstring)
  if fp.sigHashAlgs.len > 0:
    checkCode easy_setopt(curl, OPT_SSL_SIGNATURE_ALGORITHMS, fp.sigHashAlgs.cstring)
  if fp.certCompression.len > 0:
    checkCode easy_setopt(curl, OPT_SSL_CERT_COMPRESSION, fp.certCompression.cstring)
  if fp.tlsExtensionOrder.len > 0:
    checkCode easy_setopt(curl, OPT_TLS_EXTENSION_ORDER, fp.tlsExtensionOrder.cstring)
  if fp.tlsDelegatedCredentials.len > 0:
    checkCode easy_setopt(curl, OPT_TLS_DELEGATED_CREDENTIALS, fp.tlsDelegatedCredentials.cstring)
  if fp.tlsTrustAnchors.len > 0:
    checkCode easy_setopt(curl, OPT_TLS_TRUST_ANCHORS, fp.tlsTrustAnchors.cstring)
  if fp.tlsRecordSizeLimit > 0:
    checkCode easy_setopt(curl, OPT_TLS_RECORD_SIZE_LIMIT, fp.tlsRecordSizeLimit.clong)
  if fp.tlsKeySharesLimit > 0:
    checkCode easy_setopt(curl, OPT_TLS_KEY_SHARES_LIMIT, fp.tlsKeySharesLimit.clong)
  if fp.tlsGrease >= 0:
    checkCode easy_setopt(curl, OPT_TLS_GREASE, fp.tlsGrease.clong)
  if fp.tlsPermuteExtensions >= 0:
    checkCode easy_setopt(curl, OPT_SSL_PERMUTE_EXTENSIONS, fp.tlsPermuteExtensions.clong)
  if fp.tlsEnableAlps >= 0:
    checkCode easy_setopt(curl, OPT_SSL_ENABLE_ALPS, fp.tlsEnableAlps.clong)
  if fp.tlsUseNewAlpsCodepoint >= 0:
    checkCode easy_setopt(curl, OPT_TLS_USE_NEW_ALPS_CODEPOINT, fp.tlsUseNewAlpsCodepoint.clong)
  if fp.tlsEnableTicket >= 0:
    checkCode easy_setopt(curl, OPT_SSL_ENABLE_TICKET, fp.tlsEnableTicket.clong)
  if fp.tlsSignedCertTimestamps >= 0:
    checkCode easy_setopt(curl, OPT_TLS_SIGNED_CERT_TIMESTAMPS, fp.tlsSignedCertTimestamps.clong)
  if fp.tlsStatusRequest >= 0:
    checkCode easy_setopt(curl, OPT_TLS_STATUS_REQUEST, fp.tlsStatusRequest.clong)
  if fp.http2PseudoHeadersOrder.len > 0:
    checkCode easy_setopt(curl, OPT_HTTP2_PSEUDO_HEADERS_ORDER, fp.http2PseudoHeadersOrder.cstring)
  if fp.http2Settings.len > 0:
    checkCode easy_setopt(curl, OPT_HTTP2_SETTINGS, fp.http2Settings.cstring)
  if fp.http2WindowUpdate > 0:
    checkCode easy_setopt(curl, OPT_HTTP2_WINDOW_UPDATE, fp.http2WindowUpdate.clong)
  if fp.http2Streams.len > 0:
    checkCode easy_setopt(curl, OPT_HTTP2_STREAMS, fp.http2Streams.cstring)
  if fp.http2NoPriority >= 0:
    checkCode easy_setopt(curl, OPT_HTTP2_NO_PRIORITY, fp.http2NoPriority.clong)
  if fp.http3PseudoHeadersOrder.len > 0:
    checkCode easy_setopt(curl, OPT_HTTP3_PSEUDO_HEADERS_ORDER, fp.http3PseudoHeadersOrder.cstring)
  if fp.http3Settings.len > 0:
    checkCode easy_setopt(curl, OPT_HTTP3_SETTINGS, fp.http3Settings.cstring)
  if fp.http3SigHashAlgs.len > 0:
    checkCode easy_setopt(curl, OPT_HTTP3_SIG_HASH_ALGS, fp.http3SigHashAlgs.cstring)
  if fp.http3TlsExtensionOrder.len > 0:
    checkCode easy_setopt(curl, OPT_HTTP3_TLS_EXTENSION_ORDER, fp.http3TlsExtensionOrder.cstring)
  if fp.http3Curves.len > 0:
    checkCode easy_setopt(curl, OPT_HTTP3_SSL_EC_CURVES, fp.http3Curves.cstring)
  if fp.http3PermuteExtensions >= -1:
    checkCode easy_setopt(curl, OPT_HTTP3_SSL_PERMUTE_EXTENSIONS, fp.http3PermuteExtensions.clong)
  if fp.quicTransportParameters.len > 0:
    checkCode easy_setopt(curl, OPT_QUIC_TRANSPORT_PARAMETERS, fp.quicTransportParameters.cstring)
  if fp.quicCidLength.len > 0:
    checkCode easy_setopt(curl, OPT_QUIC_CID_LENGTH, fp.quicCidLength.cstring)
  if fp.quicInitialPacketNumber != 0:
    checkCode easy_setopt(curl, OPT_QUIC_INITIAL_PACKET_NUMBER, fp.quicInitialPacketNumber.clong)
  if fp.httpHeaderOrder.len > 0:
    checkCode easy_setopt(curl, OPT_HTTPHEADER_ORDER, fp.httpHeaderOrder.cstring)
  if fp.splitCookies >= 0:
    checkCode easy_setopt(curl, OPT_SPLIT_COOKIES, fp.splitCookies.clong)
  if fp.formBoundary.len > 0:
    checkCode easy_setopt(curl, OPT_FORM_BOUNDARY, fp.formBoundary.cstring)

proc populateResponseMetadata(curl: PCurl, result: var Response) =
  var respCode: clong = 0
  if easy_getinfo(curl, INFO_RESPONSE_CODE, addr respCode) == E_OK:
    result.statusCode = int(respCode)

  var effUrl: cstring = nil
  if easy_getinfo(curl, INFO_EFFECTIVE_URL, addr effUrl) == E_OK and effUrl != nil:
    result.url = $effUrl

  var effMethod: cstring = nil
  if easy_getinfo(curl, INFO_EFFECTIVE_METHOD, addr effMethod) == E_OK and effMethod != nil:
    result.effectiveMethod = $effMethod

  var httpVer: clong = 0
  if easy_getinfo(curl, INFO_HTTP_VERSION, addr httpVer) == E_OK:
    result.httpVersion = int(httpVer)

  var ctype: cstring = nil
  if easy_getinfo(curl, INFO_CONTENT_TYPE, addr ctype) == E_OK and ctype != nil:
    result.contentType = $ctype

  var primIp: cstring = nil
  if easy_getinfo(curl, INFO_PRIMARY_IP, addr primIp) == E_OK and primIp != nil:
    result.primaryIp = $primIp

  var primPort: clong = 0
  if easy_getinfo(curl, INFO_PRIMARY_PORT, addr primPort) == E_OK:
    result.primaryPort = int(primPort)

  discard easy_getinfo(curl, INFO_TOTAL_TIME, addr result.totalTime)
  discard easy_getinfo(curl, INFO_NAMELOOKUP_TIME, addr result.namelookupTime)
  discard easy_getinfo(curl, INFO_CONNECT_TIME, addr result.connectTime)
  discard easy_getinfo(curl, INFO_APPCONNECT_TIME, addr result.appconnectTime)
  discard easy_getinfo(curl, INFO_PRETRANSFER_TIME, addr result.pretransferTime)
  discard easy_getinfo(curl, INFO_STARTTRANSFER_TIME, addr result.starttransferTime)
  discard easy_getinfo(curl, INFO_REDIRECT_TIME, addr result.redirectTime)

  var redirCount: clong = 0
  if easy_getinfo(curl, INFO_REDIRECT_COUNT, addr redirCount) == E_OK:
    result.redirectCount = int(redirCount)

  # Extract curl-impersonate CURLINFO_REDIRECT_HISTORY
  var redirSlist: Pslist = nil
  if easy_getinfo(curl, INFO_REDIRECT_HISTORY, addr redirSlist) == E_OK and redirSlist != nil:
    try:
      for item in slistToSeq(redirSlist):
        result.redirectHistory.add(parseRedirectHop(item))
    finally:
      slist_free_all(redirSlist)

  # Extract CURLINFO_COOKIELIST
  var cookieSlist: Pslist = nil
  if easy_getinfo(curl, INFO_COOKIELIST, addr cookieSlist) == E_OK and cookieSlist != nil:
    try:
      result.cookies = slistToSeq(cookieSlist)
    finally:
      slist_free_all(cookieSlist)

  # Extract curl-impersonate CURLINFO_COOKIECHANGES
  var cookieChangesSlist: Pslist = nil
  if easy_getinfo(curl, INFO_COOKIECHANGES, addr cookieChangesSlist) == E_OK and cookieChangesSlist != nil:
    try:
      for item in slistToSeq(cookieChangesSlist):
        result.cookieChanges.add(parseCookieChange(item))
    finally:
      slist_free_all(cookieChangesSlist)

proc executeOnHandle(
  curl: PCurl,
  req: Request,
  resetFirst: bool,
  streaming: bool = false,
  onHeaders: OnHeadersCallback = nil,
  onChunk: OnChunkCallback = nil,
  onProgress: OnProgressCallback = nil
): Response =
  if resetFirst:
    easy_reset(curl)

  var errBuf = newString(ERROR_SIZE + 1)
  discard easy_setopt(curl, OPT_ERRORBUFFER, errBuf.cstring)
  discard easy_setopt(curl, OPT_NOSIGNAL, 1.clong)

  if req.share != nil:
    checkCode(easy_setopt(curl, OPT_SHARE, req.share), errBuf.cstring)

  # 1. Apply HTTP version preference before impersonate so `_do_impersonate` respects `data->set.httpwant`
  if req.httpVersion != HTTP_VERSION_NONE:
    checkCode(easy_setopt(curl, OPT_HTTP_VERSION, ord(req.httpVersion).clong), errBuf.cstring)

  # 2. Apply browser impersonation
  if req.target.len > 0 and cmpIgnoreCase(req.target, "none") != 0:
    # Support short family aliases like "chrome", "firefox", "safari", "edge", "tor"
    var resolvedTarget = req.target
    try:
      let parsed = parseImpersonateTarget(req.target)
      if parsed != itNone:
        resolvedTarget = $parsed
    except ValueError:
      discard # Pass through custom target names directly to libcurl-impersonate

    let impCode = easy_impersonate(curl, resolvedTarget.cstring, if req.defaultHeaders: 1.cint else: 0.cint)
    checkCode(impCode, errBuf.cstring)

  # 3. Apply fine-grained fingerprint overrides (if any)
  applyFingerprintConfig(curl, req.fingerprint)

  # 4. URL, Method & Decoding
  checkCode(easy_setopt(curl, OPT_URL, req.url.cstring), errBuf.cstring)
  checkCode(easy_setopt(curl, OPT_ACCEPT_ENCODING, req.acceptEncoding.cstring), errBuf.cstring)
  checkCode(easy_setopt(curl, OPT_HTTP_CONTENT_DECODING, (if req.httpContentDecoding: 1.clong else: 0.clong)), errBuf.cstring)

  if req.bufferSize > 0:
    checkCode(easy_setopt(curl, OPT_BUFFERSIZE, req.bufferSize.clong), errBuf.cstring)

  let upperVerb = req.httpMethod.toUpperAscii()
  var mimeHandle: PCurlMime = nil
  var headerSlist: Pslist = nil

  try:
    if req.mimeParts.len > 0:
      mimeHandle = mime_init(curl)
      if mimeHandle == nil:
        raise newException(CurlImpersonateError, "curl_mime_init failed")
      for partSpec in req.mimeParts:
        let part = mime_addpart(mimeHandle)
        if partSpec.name.len > 0:
          checkCode(mime_name(part, partSpec.name.cstring), errBuf.cstring)
        if partSpec.isFile:
          checkCode(mime_filedata(part, partSpec.content.cstring), errBuf.cstring)
        else:
          if partSpec.content.len > 0:
            checkCode(mime_data(part, unsafeAddr partSpec.content[0], partSpec.content.len.csize_t), errBuf.cstring)
          else:
            checkCode(mime_data(part, "".cstring, 0.csize_t), errBuf.cstring)
        if partSpec.filename.len > 0:
          checkCode(mime_filename(part, partSpec.filename.cstring), errBuf.cstring)
        if partSpec.contentType.len > 0:
          checkCode(mime_type(part, partSpec.contentType.cstring), errBuf.cstring)
      checkCode(easy_setopt(curl, OPT_MIMEPOST, mimeHandle), errBuf.cstring)
      if upperVerb != "POST" and upperVerb.len > 0:
        checkCode(easy_setopt(curl, OPT_CUSTOMREQUEST, upperVerb.cstring), errBuf.cstring)
    elif upperVerb == "HEAD":
      checkCode(easy_setopt(curl, OPT_NOBODY, 1.clong), errBuf.cstring)
    elif upperVerb == "GET" and req.body.len == 0:
      checkCode(easy_setopt(curl, OPT_HTTPGET, 1.clong), errBuf.cstring)
    elif upperVerb == "POST":
      checkCode(easy_setopt(curl, OPT_POST, 1.clong), errBuf.cstring)
      checkCode(easy_setopt(curl, OPT_POSTFIELDSIZE_LARGE, req.body.len.CurlOffT), errBuf.cstring)
      checkCode(easy_setopt(curl, OPT_POSTFIELDS, req.body.cstring), errBuf.cstring)
    else:
      checkCode(easy_setopt(curl, OPT_CUSTOMREQUEST, upperVerb.cstring), errBuf.cstring)
      if req.body.len > 0:
        checkCode(easy_setopt(curl, OPT_POSTFIELDSIZE_LARGE, req.body.len.CurlOffT), errBuf.cstring)
        checkCode(easy_setopt(curl, OPT_POSTFIELDS, req.body.cstring), errBuf.cstring)

    # 5. Custom HTTP headers (merged with base browser headers by libcurl-impersonate)
    if req.headers.len > 0:
      for (k, v) in req.headers:
        let line = k & ": " & v
        headerSlist = slist_append(headerSlist, line.cstring)
      checkCode(easy_setopt(curl, OPT_HTTPHEADER, headerSlist), errBuf.cstring)

    # 6. Timeouts, Redirects, SSL, Proxy, Cookies
    if req.timeoutMs > 0:
      checkCode(easy_setopt(curl, OPT_TIMEOUT_MS, req.timeoutMs.clong), errBuf.cstring)
    else:
      checkCode(easy_setopt(curl, OPT_TIMEOUT_MS, 0.clong), errBuf.cstring)
    if req.connectTimeoutMs > 0:
      checkCode(easy_setopt(curl, OPT_CONNECTTIMEOUT_MS, req.connectTimeoutMs.clong), errBuf.cstring)
    if req.lowSpeedLimit > 0 and req.lowSpeedTimeSec > 0:
      checkCode(easy_setopt(curl, OPT_LOW_SPEED_LIMIT, req.lowSpeedLimit.clong), errBuf.cstring)
      checkCode(easy_setopt(curl, OPT_LOW_SPEED_TIME, req.lowSpeedTimeSec.clong), errBuf.cstring)

    if req.followRedirects:
      let followMode = if req.safeRedirects: CURLFOLLOW_SAFE.clong else: CURLFOLLOW_ALL.clong
      checkCode(easy_setopt(curl, OPT_FOLLOWLOCATION, followMode), errBuf.cstring)
      checkCode(easy_setopt(curl, OPT_MAXREDIRS, req.maxRedirects.clong), errBuf.cstring)
    else:
      checkCode(easy_setopt(curl, OPT_FOLLOWLOCATION, 0.clong), errBuf.cstring)

    if req.verifySsl:
      checkCode(easy_setopt(curl, OPT_SSL_VERIFYPEER, 1.clong), errBuf.cstring)
      checkCode(easy_setopt(curl, OPT_SSL_VERIFYHOST, 2.clong), errBuf.cstring)
    else:
      checkCode(easy_setopt(curl, OPT_SSL_VERIFYPEER, 0.clong), errBuf.cstring)
      checkCode(easy_setopt(curl, OPT_SSL_VERIFYHOST, 0.clong), errBuf.cstring)

    if req.caInfo.len > 0:
      checkCode(easy_setopt(curl, OPT_CAINFO, req.caInfo.cstring), errBuf.cstring)
    if req.caPath.len > 0:
      checkCode(easy_setopt(curl, OPT_CAPATH, req.caPath.cstring), errBuf.cstring)

    if req.proxy.len > 0:
      checkCode(easy_setopt(curl, OPT_PROXY, req.proxy.cstring), errBuf.cstring)
    if req.proxyAuth.len > 0:
      checkCode(easy_setopt(curl, OPT_PROXYUSERPWD, req.proxyAuth.cstring), errBuf.cstring)

    if req.cookie.len > 0:
      checkCode(easy_setopt(curl, OPT_COOKIE, req.cookie.cstring), errBuf.cstring)
    if req.cookieFile.len > 0:
      checkCode(easy_setopt(curl, OPT_COOKIEFILE, req.cookieFile.cstring), errBuf.cstring)
    else:
      # Activate cookie engine so CURLINFO_COOKIELIST and CURLINFO_COOKIECHANGES work out-of-the-box
      discard easy_setopt(curl, OPT_COOKIEFILE, "".cstring)
    if req.cookieJar.len > 0:
      checkCode(easy_setopt(curl, OPT_COOKIEJAR, req.cookieJar.cstring), errBuf.cstring)

    if streaming:
      var streamCtx = StreamContext(
        curl: curl,
        followRedirects: req.followRedirects,
        maxRedirects: req.maxRedirects,
        headers: newHttpHeaders(),
        onHeaders: onHeaders,
        onChunk: onChunk,
        onProgress: onProgress
      )
      checkCode(easy_setopt(curl, OPT_WRITEDATA, addr streamCtx), errBuf.cstring)
      checkCode(easy_setopt(curl, OPT_WRITEFUNCTION, streamWriteCallback), errBuf.cstring)
      checkCode(easy_setopt(curl, OPT_HEADERDATA, addr streamCtx), errBuf.cstring)
      checkCode(easy_setopt(curl, OPT_HEADERFUNCTION, streamHeaderCallback), errBuf.cstring)
      if onProgress != nil:
        checkCode(easy_setopt(curl, OPT_XFERINFODATA, addr streamCtx), errBuf.cstring)
        checkCode(easy_setopt(curl, OPT_XFERINFOFUNCTION, streamXferInfoCallback), errBuf.cstring)
        checkCode(easy_setopt(curl, OPT_NOPROGRESS, 0.clong), errBuf.cstring)
      else:
        checkCode(easy_setopt(curl, OPT_NOPROGRESS, 1.clong), errBuf.cstring)

      let performRes = easy_perform(curl)
      if streamCtx.abortedByCallback and performRes in [E_WRITE_ERROR, E_ABORTED_BY_CALLBACK]:
        result.abortedByCallback = true
      else:
        checkCode(performRes, errBuf.cstring)
        if not streamCtx.headersDelivered:
          if not deliverHeadersIfNeeded(streamCtx):
            result.abortedByCallback = true

      result.headers = streamCtx.headers
      result.rawHeaderLines = move(streamCtx.rawHeaderLines)
      populateResponseMetadata(curl, result)
    else:
      # 7. Response body & header buffers
      var bodyWrap, headerWrap: BufferWrap
      checkCode(easy_setopt(curl, OPT_WRITEDATA, addr bodyWrap), errBuf.cstring)
      checkCode(easy_setopt(curl, OPT_WRITEFUNCTION, writeCallback), errBuf.cstring)
      checkCode(easy_setopt(curl, OPT_HEADERDATA, addr headerWrap), errBuf.cstring)
      checkCode(easy_setopt(curl, OPT_HEADERFUNCTION, writeCallback), errBuf.cstring)

      # 8. Perform request
      let performRes = easy_perform(curl)
      checkCode(performRes, errBuf.cstring)

      # 9. Extract response metadata
      result.body = move(bodyWrap.data)
      result.headers = newHttpHeaders()

      # Parse headers from the final response block (in case of redirects or 100 Continue)
      let rawHeaders = headerWrap.data
      for line in rawHeaders.splitLines():
        let stripped = line.strip()
        if stripped.len == 0:
          continue
        result.rawHeaderLines.add(stripped)
        if stripped.startsWith("HTTP/"):
          # New HTTP response block (redirect hop or final response) -> clear previous hop headers
          result.headers.clear()
          continue
        let colonPos = stripped.find(':')
        if colonPos > 0:
          let key = stripped[0 ..< colonPos].strip()
          let val = stripped[colonPos + 1 .. ^1].strip()
          result.headers.add(key, val)

      populateResponseMetadata(curl, result)

  finally:
    if headerSlist != nil:
      slist_free_all(headerSlist)
    if mimeHandle != nil:
      mime_free(mimeHandle)
    discard easy_setopt(curl, OPT_ERRORBUFFER, nil)
    if streaming:
      discard easy_setopt(curl, OPT_NOPROGRESS, 1.clong)
      discard easy_setopt(curl, OPT_XFERINFOFUNCTION, nil)
      discard easy_setopt(curl, OPT_XFERINFODATA, nil)

proc perform*(req: Request): Response =
  ## Executes a one-shot `Request` using a fresh `libcurl-impersonate` handle.
  ensureGlobalInit()
  let curl = easy_init()
  if curl == nil:
    raise newException(CurlImpersonateError, "curl_easy_init returned nil")
  try:
    result = executeOnHandle(curl, req, resetFirst = false)
  finally:
    easy_cleanup(curl)

proc performStreaming*(
  req: Request,
  onHeaders: OnHeadersCallback,
  onChunk: OnChunkCallback,
  onProgress: OnProgressCallback = nil
): Response =
  ## Executes a streaming `Request` without buffering the response body in memory.
  ensureGlobalInit()
  let curl = easy_init()
  if curl == nil:
    raise newException(CurlImpersonateError, "curl_easy_init returned nil")
  try:
    result = executeOnHandle(
      curl,
      req,
      resetFirst = false,
      streaming = true,
      onHeaders = onHeaders,
      onChunk = onChunk,
      onProgress = onProgress
    )
  finally:
    easy_cleanup(curl)

proc requestStreaming*(
  session: ImpersonateSession,
  req: Request,
  onHeaders: OnHeadersCallback,
  onChunk: OnChunkCallback,
  onProgress: OnProgressCallback = nil
): Response =
  ## Executes a streaming `Request` on an existing `ImpersonateSession`, preserving
  ## pooled connections, cookies, TLS sessions, and shared `CURLSH*` state.
  if session == nil or session.handle == nil:
    raise newException(CurlImpersonateError, "ImpersonateSession is closed or nil")
  var effectiveReq = req
  if effectiveReq.share == nil:
    effectiveReq.share = session.share
  result = executeOnHandle(
    session.handle,
    effectiveReq,
    resetFirst = true,
    streaming = true,
    onHeaders = onHeaders,
    onChunk = onChunk,
    onProgress = onProgress
  )

proc request*(
  session: ImpersonateSession,
  url: string,
  httpMethod: string = "GET",
  headers: openArray[(string, string)] = [],
  body: string = "",
  mimeParts: openArray[MimePartSpec] = [],
  target: string = ""
): Response =
  ## Performs an HTTP request on an existing `ImpersonateSession`, preserving
  ## pooled connections, cookies, and TLS sessions.
  if session == nil or session.handle == nil:
    raise newException(CurlImpersonateError, "ImpersonateSession is closed or nil")

  var mergedHeaders = session.headers
  for (k, v) in headers:
    mergedHeaders.add((k, v))

  var req = initRequest(
    url = url,
    httpMethod = httpMethod,
    target = (if target.len > 0: target else: session.target),
    defaultHeaders = session.defaultHeaders,
    headers = mergedHeaders,
    body = body,
    timeoutMs = session.timeoutMs,
    connectTimeoutMs = session.connectTimeoutMs,
    lowSpeedLimit = session.lowSpeedLimit,
    lowSpeedTimeSec = session.lowSpeedTimeSec,
    bufferSize = session.bufferSize,
    httpContentDecoding = session.httpContentDecoding,
    followRedirects = session.followRedirects,
    safeRedirects = session.safeRedirects,
    maxRedirects = session.maxRedirects,
    verifySsl = session.verifySsl,
    proxy = session.proxy,
    httpVersion = session.httpVersion,
    share = session.share
  )
  req.mimeParts = @mimeParts
  req.cookieFile = session.cookieFile
  req.cookieJar = session.cookieJar
  req.fingerprint = session.fingerprint
  result = executeOnHandle(session.handle, req, resetFirst = true)

proc get*(session: ImpersonateSession, url: string,
          headers: openArray[(string, string)] = []): Response =
  session.request(url, "GET", headers = headers)

proc post*(session: ImpersonateSession, url: string, body: string = "",
           headers: openArray[(string, string)] = [],
           mimeParts: openArray[MimePartSpec] = []): Response =
  session.request(url, "POST", headers = headers, body = body, mimeParts = mimeParts)

proc put*(session: ImpersonateSession, url: string, body: string = "",
          headers: openArray[(string, string)] = []): Response =
  session.request(url, "PUT", headers = headers, body = body)

proc patch*(session: ImpersonateSession, url: string, body: string = "",
            headers: openArray[(string, string)] = []): Response =
  session.request(url, "PATCH", headers = headers, body = body)

proc delete*(session: ImpersonateSession, url: string, body: string = "",
             headers: openArray[(string, string)] = []): Response =
  session.request(url, "DELETE", headers = headers, body = body)

proc head*(session: ImpersonateSession, url: string,
           headers: openArray[(string, string)] = []): Response =
  session.request(url, "HEAD", headers = headers)

proc options*(session: ImpersonateSession, url: string,
              headers: openArray[(string, string)] = []): Response =
  session.request(url, "OPTIONS", headers = headers)

# Top-level convenience procs
proc get*(
  url: string,
  target: ImpersonateTarget | string = itChromeLatest,
  headers: openArray[(string, string)] = [],
  defaultHeaders: bool = true,
  timeoutMs: int = 30_000,
  followRedirects: bool = true,
  safeRedirects: bool = false,
  verifySsl: bool = true,
  proxy: string = "",
  httpVersion: abi.HTTP_VERSION = HTTP_VERSION_NONE
): Response =
  ## Performs an impersonated HTTP GET request.
  let req = initRequest(
    url = url,
    httpMethod = "GET",
    target = target,
    defaultHeaders = defaultHeaders,
    headers = headers,
    timeoutMs = timeoutMs,
    followRedirects = followRedirects,
    safeRedirects = safeRedirects,
    verifySsl = verifySsl,
    proxy = proxy,
    httpVersion = httpVersion
  )
  perform(req)

proc post*(
  url: string,
  body: string = "",
  target: ImpersonateTarget | string = itChromeLatest,
  headers: openArray[(string, string)] = [],
  mimeParts: openArray[MimePartSpec] = [],
  defaultHeaders: bool = true,
  timeoutMs: int = 30_000,
  followRedirects: bool = true,
  safeRedirects: bool = false,
  verifySsl: bool = true,
  proxy: string = "",
  httpVersion: abi.HTTP_VERSION = HTTP_VERSION_NONE
): Response =
  ## Performs an impersonated HTTP POST request.
  var req = initRequest(
    url = url,
    httpMethod = "POST",
    target = target,
    defaultHeaders = defaultHeaders,
    headers = headers,
    body = body,
    timeoutMs = timeoutMs,
    followRedirects = followRedirects,
    safeRedirects = safeRedirects,
    verifySsl = verifySsl,
    proxy = proxy,
    httpVersion = httpVersion
  )
  req.mimeParts = @mimeParts
  perform(req)

proc put*(
  url: string,
  body: string = "",
  target: ImpersonateTarget | string = itChromeLatest,
  headers: openArray[(string, string)] = [],
  defaultHeaders: bool = true,
  timeoutMs: int = 30_000,
  followRedirects: bool = true,
  safeRedirects: bool = false,
  verifySsl: bool = true,
  proxy: string = "",
  httpVersion: abi.HTTP_VERSION = HTTP_VERSION_NONE
): Response =
  ## Performs an impersonated HTTP PUT request.
  let req = initRequest(
    url = url,
    httpMethod = "PUT",
    target = target,
    defaultHeaders = defaultHeaders,
    headers = headers,
    body = body,
    timeoutMs = timeoutMs,
    followRedirects = followRedirects,
    safeRedirects = safeRedirects,
    verifySsl = verifySsl,
    proxy = proxy,
    httpVersion = httpVersion
  )
  perform(req)

proc patch*(
  url: string,
  body: string = "",
  target: ImpersonateTarget | string = itChromeLatest,
  headers: openArray[(string, string)] = [],
  defaultHeaders: bool = true,
  timeoutMs: int = 30_000,
  followRedirects: bool = true,
  safeRedirects: bool = false,
  verifySsl: bool = true,
  proxy: string = "",
  httpVersion: abi.HTTP_VERSION = HTTP_VERSION_NONE
): Response =
  ## Performs an impersonated HTTP PATCH request.
  let req = initRequest(
    url = url,
    httpMethod = "PATCH",
    target = target,
    defaultHeaders = defaultHeaders,
    headers = headers,
    body = body,
    timeoutMs = timeoutMs,
    followRedirects = followRedirects,
    safeRedirects = safeRedirects,
    verifySsl = verifySsl,
    proxy = proxy,
    httpVersion = httpVersion
  )
  perform(req)

proc delete*(
  url: string,
  body: string = "",
  target: ImpersonateTarget | string = itChromeLatest,
  headers: openArray[(string, string)] = [],
  defaultHeaders: bool = true,
  timeoutMs: int = 30_000,
  followRedirects: bool = true,
  safeRedirects: bool = false,
  verifySsl: bool = true,
  proxy: string = "",
  httpVersion: abi.HTTP_VERSION = HTTP_VERSION_NONE
): Response =
  ## Performs an impersonated HTTP DELETE request.
  let req = initRequest(
    url = url,
    httpMethod = "DELETE",
    target = target,
    defaultHeaders = defaultHeaders,
    headers = headers,
    body = body,
    timeoutMs = timeoutMs,
    followRedirects = followRedirects,
    safeRedirects = safeRedirects,
    verifySsl = verifySsl,
    proxy = proxy,
    httpVersion = httpVersion
  )
  perform(req)

proc head*(
  url: string,
  target: ImpersonateTarget | string = itChromeLatest,
  headers: openArray[(string, string)] = [],
  defaultHeaders: bool = true,
  timeoutMs: int = 30_000,
  followRedirects: bool = true,
  safeRedirects: bool = false,
  verifySsl: bool = true,
  proxy: string = "",
  httpVersion: abi.HTTP_VERSION = HTTP_VERSION_NONE
): Response =
  ## Performs an impersonated HTTP HEAD request.
  let req = initRequest(
    url = url,
    httpMethod = "HEAD",
    target = target,
    defaultHeaders = defaultHeaders,
    headers = headers,
    timeoutMs = timeoutMs,
    followRedirects = followRedirects,
    safeRedirects = safeRedirects,
    verifySsl = verifySsl,
    proxy = proxy,
    httpVersion = httpVersion
  )
  perform(req)

proc fetch*(
  url: string,
  target: ImpersonateTarget | string = itChromeLatest,
  headers: openArray[(string, string)] = []
): string =
  ## Simple helper that performs an impersonated GET request and returns the body string.
  ## Raises `CurlImpersonateError` if the status code is not 2xx.
  let resp = get(url, target = target, headers = headers)
  if resp.statusCode < 200 or resp.statusCode >= 300:
    raise newException(CurlImpersonateError, "HTTP status " & $resp.statusCode & ": " & resp.body)
  result = resp.body

proc isImpersonateBuild*(): bool =
  ## Returns true if the loaded dynamic library is `libcurl-impersonate` (rather than vanilla `libcurl`).
  let ver = $version()
  result = "IMPERSONATE" in ver.toUpperAscii() or "curl-impersonate" in ver.toLowerAscii()
