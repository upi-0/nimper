#
#          curl-impersonate Wrapper for Nim
#        Comprehensive Unit & Integration Test Suite
#

import std/[unittest, strutils, httpcore, json, nativesockets, net, os, tables]
import nimper

# Spawn a lightweight local HTTP test server in a background thread to test
# GET, POST, PUT, DELETE, headers, redirects (CURLINFO_REDIRECT_HISTORY),
# cookies (CURLINFO_COOKIECHANGES), and multipart MIME uploads deterministically.
type
  ServerArgs = object
    port: Port

proc runLocalTestServer(args: ServerArgs) {.thread.} =
  var server = newSocket()
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(args.port, "127.0.0.1")
  server.listen()

  while true:
    var client: net.Socket
    try:
      server.accept(client)
    except CatchableError:
      break

    try:
      var reqLine = client.recvLine()
      if reqLine.len == 0:
        client.close()
        continue

      let parts = reqLine.strip().split(' ')
      let meth = if parts.len > 0: parts[0] else: "GET"
      let path = if parts.len > 1: parts[1] else: "/"

      var headers = initTable[string, string]()
      var rawHeaders: seq[string] = @[]
      var contentLength = 0
      while true:
        let line = client.recvLine()
        if line == "\r\n" or line == "" or line == "\n":
          break
        let stripped = line.strip()
        rawHeaders.add(stripped)
        let colon = stripped.find(':')
        if colon > 0:
          let k = stripped[0 ..< colon].strip().toLowerAscii()
          let v = stripped[colon + 1 .. ^1].strip()
          headers[k] = v
          if k == "content-length":
            try:
              contentLength = parseInt(v)
            except ValueError:
              contentLength = 0

      var body = ""
      if contentLength > 0:
        body = client.recv(contentLength)

      if path == "/quit":
        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbye"
        client.send(resp)
        client.close()
        break
      elif path == "/echo":
        var j = %*{
          "method": meth,
          "path": path,
          "body": body,
          "user_agent": headers.getOrDefault("user-agent", ""),
          "sec_ch_ua": headers.getOrDefault("sec-ch-ua", ""),
          "custom_header": headers.getOrDefault("x-custom-test", ""),
          "cookie": headers.getOrDefault("cookie", ""),
          "content_type": headers.getOrDefault("content-type", ""),
          "raw_headers": rawHeaders
        }
        let payload = $j
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Server-Header: nim-test\r\nContent-Length: " & $payload.len & "\r\nConnection: close\r\n\r\n" & payload
        client.send(resp)
      elif path == "/redirect-1":
        let loc = "http://127.0.0.1:" & $int(args.port) & "/redirect-2"
        let resp = "HTTP/1.1 302 Found\r\nLocation: " & loc & "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        client.send(resp)
      elif path == "/redirect-2":
        let loc = "http://127.0.0.1:" & $int(args.port) & "/echo"
        let resp = "HTTP/1.1 301 Moved Permanently\r\nLocation: " & loc & "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        client.send(resp)
      elif path == "/set-cookie":
        let payload = "cookies set"
        let resp = "HTTP/1.1 200 OK\r\n" &
                   "Set-Cookie: session_id=abc123xyz; Path=/; HttpOnly\r\n" &
                   "Set-Cookie: theme=dark; Path=/\r\n" &
                   "Content-Length: " & $payload.len & "\r\nConnection: close\r\n\r\n" & payload
        client.send(resp)
      else:
        let payload = "not found"
        let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: " & $payload.len & "\r\nConnection: close\r\n\r\n" & payload
        client.send(resp)
    except CatchableError:
      discard
    finally:
      try: client.close() except CatchableError: discard

  try: server.close() except CatchableError: discard

suite "nimper: Low-Level ABI & Introspection":
  test "Dynamic library version and impersonate build detection":
    let verStr = $curl_version()
    echo "Loaded libcurl version: ", verStr
    check verStr.len > 0
    check isImpersonateBuild()

    let vinfo = curl_version_info(VERSION_NOW)
    check vinfo != nil
    check ($vinfo.version).contains("IMPERSONATE")
    check ($vinfo.ssl_version).toLowerAscii().contains("boringssl")
    check (vinfo.features and VERSION_HTTP2) != 0
    check (vinfo.features and VERSION_HTTP3) != 0
    check (vinfo.features and VERSION_BROTLI) != 0
    check (vinfo.features and VERSION_ZSTD) != 0

  test "curl_easy_option_by_name / by_id introspection for custom curl-impersonate options":
    let optImp = easy_option_by_name("IMPERSONATE")
    check optImp != nil
    check optImp.id == OPT_IMPERSONATE

    let optH2 = easy_option_by_id(OPT_HTTP2_SETTINGS)
    check optH2 != nil
    check $optH2.name == "HTTP2_SETTINGS"

    let optH3 = easy_option_by_id(OPT_HTTP3_SETTINGS)
    check optH3 != nil
    check $optH3.name == "HTTP3_SETTINGS"

    let optQuic = easy_option_by_id(OPT_QUIC_TRANSPORT_PARAMETERS)
    check optQuic != nil
    check $optQuic.name == "QUIC_TRANSPORT_PARAMETERS"

  test "URL API (curl_url_*)":
    let u = url_init()
    check u != nil
    defer: url_cleanup(u)

    check url_set(u, UPART_URL, "https://example.com:8443/test/path?foo=bar#frag") == UE_OK
    var host: cstring = nil
    check url_get(u, UPART_HOST, host) == UE_OK
    check $host == "example.com"
    curl_free(host)

    var port: cstring = nil
    check url_get(u, UPART_PORT, port) == UE_OK
    check $port == "8443"
    curl_free(port)

suite "nimper: Browser Impersonation Targets":
  test "All ImpersonateTarget enum values are accepted by curl_easy_impersonate":
    ensureGlobalInit()
    let h = easy_init()
    check h != nil
    defer: easy_cleanup(h)

    for target in ImpersonateTarget:
      if target == itNone:
        continue
      easy_reset(h)
      let code = easy_impersonate(h, ($target).cstring, 1)
      if code != E_OK:
        echo "Failed target: ", target, " -> ", easy_strerror(code)
      check code == E_OK

      # Also verify alias acceptance
      let ti = target.info()
      if ti.alias.len > 0:
        easy_reset(h)
        check easy_impersonate(h, ti.alias.cstring, 0) == E_OK

  test "Unknown target returns E_BAD_FUNCTION_ARGUMENT":
    let h = easy_init()
    defer: easy_cleanup(h)
    let code = easy_impersonate(h, "nonexistent_browser_999", 1)
    check code == E_BAD_FUNCTION_ARGUMENT

  test "parseImpersonateTarget and formatImpersonateOpt":
    check parseImpersonateTarget("chrome") == itChromeLatest
    check parseImpersonateTarget("firefox") == itFirefoxLatest
    check parseImpersonateTarget("safari") == itSafariLatest
    check parseImpersonateTarget("edge") == itEdgeLatest
    check parseImpersonateTarget("tor") == itTorLatest
    check parseImpersonateTarget("safari18_4") == itSafari184
    check parseImpersonateTarget("chrome152_macos") == itChrome152Macos
    check isSupportedTarget("chrome152")
    check not isSupportedTarget("netscape4")
    check formatImpersonateOpt(itChrome152, true) == "chrome152:yes"
    check formatImpersonateOpt(itFirefox147, false) == "firefox147:no"

suite "nimper: BoringSSL WebCrypto Primitives":
  test "SHA-256, SHA-384, SHA-512 digests and constant-time equality":
    let d256 = webcryptoDigest(whSha256, "abc")
    check d256.len == 32
    # Known SHA-256("abc") starts with ba7816bf...
    check d256[0] == 0xba'u8
    check d256[1] == 0x78'u8
    check d256[2] == 0x16'u8
    check d256[3] == 0xbf'u8

    let d512 = webcryptoDigest(whSha512, "abc")
    check d512.len == 64

    check webcryptoEqual(d256, d256)
    check not webcryptoEqual(d256, d512)

  test "HMAC, HKDF, and PBKDF2":
    let mac = webcryptoHmac(whSha256, "secret-key", "message-payload")
    check mac.len == 32

    let hkdfKey = webcryptoHkdf(whSha256, @[1'u8, 2, 3, 4], @[5'u8, 6], @[7'u8, 8], 48)
    check hkdfKey.len == 48

    let pbkdf2Key = webcryptoPbkdf2(whSha256, @[1'u8, 2, 3], @[4'u8, 5, 6], 1000'u32, 32)
    check pbkdf2Key.len == 32

  test "AES-GCM encryption and decryption":
    var key = newSeq[byte](32)
    for i in 0 ..< 32:
      key[i] = byte(i + 1)
    let iv = @[1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    let aad = @[0xaa'u8, 0xbb'u8]
    let plaintext = @[byte('h'), byte('e'), byte('l'), byte('l'), byte('o')]

    let ciphertext = webcryptoCipher(wcAesGcm, encrypt = true, key, iv, aad, plaintext, tagLen = 16)
    check ciphertext.len == plaintext.len + 16

    let decrypted = webcryptoCipher(wcAesGcm, encrypt = false, key, iv, aad, ciphertext, tagLen = 16)
    check decrypted == plaintext

  test "EC P-256 key generation, SPKI/PKCS8 export/parse, ECDSA sign/verify, and ECDH":
    let alice = generateEcKey(wcrvP256)
    let bob = generateEcKey(wcrvP256)
    check alice.kind() == wkEc
    check alice.curve() == wcrvP256
    check alice.bits() == 256

    let spki = alice.exportKey(wkfSpki)
    let pkcs8 = alice.exportKey(wkfPkcs8)
    check spki.len > 0
    check pkcs8.len > 0

    let alicePub = parseKey(spki, isPrivate = false)
    let msg = @[byte(10), 20, 30, 40]
    let sig = alice.sign(wssEcdsa, whSha256, msg)
    check sig.len == 64
    check alicePub.verify(wssEcdsa, whSha256, msg, sig)

    # Tampered signature must fail verification
    var badSig = sig
    badSig[0] = badSig[0] xor 0xff'u8
    check not alicePub.verify(wssEcdsa, whSha256, msg, badSig)

    # ECDH shared secret agreement
    let bobPub = parseKey(bob.exportKey(wkfSpki), isPrivate = false)
    let secret1 = ecdh(alice, bobPub)
    let secret2 = ecdh(bob, alicePub)
    check secret1.len == 32
    check secret1 == secret2

suite "nimper: High-Level HTTP Client & Session":
  var serverThread: Thread[ServerArgs]
  let testPort = Port(18943)
  let baseUrl = "http://127.0.0.1:" & $int(testPort)

  createThread(serverThread, runLocalTestServer, ServerArgs(port: testPort))
  sleep(100)

  test "Impersonated GET injects browser default headers and merges custom headers":
    let resp = get(
      baseUrl & "/echo",
      target = itChrome152,
      headers = {"X-Custom-Test": "antigravity-nim"}
    )
    check resp.statusCode == 200
    check resp.headers["X-Server-Header"] == "nim-test"

    let data = parseJson(resp.body)
    check data["method"].getStr() == "GET"
    check data["user_agent"].getStr().contains("Chrome/152")
    check data["sec_ch_ua"].getStr().contains("152")
    check data["custom_header"].getStr() == "antigravity-nim"

  test "Firefox impersonation profile headers":
    let resp = get(baseUrl & "/echo", target = itFirefox155)
    check resp.statusCode == 200
    let data = parseJson(resp.body)
    check data["user_agent"].getStr().contains("Firefox/155")

  test "POST, PUT, DELETE and multipart MIME upload":
    let postResp = post(
      baseUrl & "/echo",
      body = """{"hello":"world"}""",
      target = itSafari270,
      headers = {"Content-Type": "application/json"}
    )
    check postResp.statusCode == 200
    let postData = parseJson(postResp.body)
    check postData["method"].getStr() == "POST"
    check postData["body"].getStr() == """{"hello":"world"}"""

    let mimeResp = post(
      baseUrl & "/echo",
      target = itChrome152,
      mimeParts = [
        MimePartSpec(name: "field1", content: "val1"),
        MimePartSpec(name: "file1", content: "file-content-abc", filename: "test.txt", contentType: "text/plain")
      ]
    )
    check mimeResp.statusCode == 200
    let mimeData = parseJson(mimeResp.body)
    check mimeData["content_type"].getStr().startsWith("multipart/form-data; boundary=")
    check mimeData["content_type"].getStr().contains("WebKitFormBoundary")
    check mimeData["body"].getStr().contains("file-content-abc")

  test "Redirect history tracking (CURLINFO_REDIRECT_HISTORY)":
    let resp = get(baseUrl & "/redirect-1", target = itChrome152, followRedirects = true)
    check resp.statusCode == 200
    check resp.redirectCount == 2
    check resp.redirectHistory.len == 2
    check resp.redirectHistory[0].statusCode == 302
    check resp.redirectHistory[0].url.endsWith("/redirect-1")
    check resp.redirectHistory[1].statusCode == 301
    check resp.redirectHistory[1].url.endsWith("/redirect-2")
    check resp.url.endsWith("/echo")

  test "SSRF-safe redirects (CURLFOLLOW_SAFE) blocks private IP redirect":
    expect CurlImpersonateError:
      discard get(baseUrl & "/redirect-1", target = itChrome152, followRedirects = true, safeRedirects = true)

  test "Persistent ImpersonateSession & Cookie Changes (CURLINFO_COOKIECHANGES)":
    let session = newImpersonateSession(target = itChrome152)
    defer: session.close()

    let r1 = session.get(baseUrl & "/set-cookie")
    check r1.statusCode == 200
    check r1.cookieChanges.len == 2
    check r1.cookieChanges[0].action == "SET"
    check r1.cookieChanges[0].name == "session_id"
    check r1.cookieChanges[0].value == "abc123xyz"
    check r1.cookieChanges[1].name == "theme"
    check r1.cookieChanges[1].value == "dark"

    # Subsequent request in the same session automatically sends the stored cookies
    let r2 = session.get(baseUrl & "/echo")
    check r2.statusCode == 200
    let data = parseJson(r2.body)
    check data["cookie"].getStr().contains("session_id=abc123xyz")
    check data["cookie"].getStr().contains("theme=dark")

  try:
    discard get(baseUrl & "/quit", timeoutMs = 2000)
  except CatchableError:
    discard
  joinThread(serverThread)
