#
#          curl-impersonate Wrapper for Nim
#        BoringSSL WebCrypto Primitives (<curl-impersonate/webcrypto.h>)
#

## Low-level and high-level idiomatic Nim bindings for the BoringSSL WebCrypto
## interface embedded in `libcurl-impersonate` v2.3.x (`<curl-impersonate/webcrypto.h>`).
##
## Provides:
## - Digests: SHA-1, SHA-256, SHA-384, SHA-512
## - HMAC: SHA-1, SHA-256, SHA-384, SHA-512
## - Constant-time byte comparison (`webcryptoEqual`)
## - Key derivation: HKDF and PBKDF2
## - Symmetric ciphers: AES-GCM, AES-CBC (PKCS#7), AES-CTR, AES-KW (RFC 3394)
## - Asymmetric keys (RSA and EC P-256 / P-384 / P-521): generation, SPKI/PKCS#8 DER parsing & export,
##   RSASSA-PKCS1-v1_5 / RSA-PSS / ECDSA signing & verification, RSA-OAEP encryption/decryption, and ECDH

## Muntazier Was Here

import abi

type
  BsslWebcryptoKey* {.incompleteStruct.} = object
  PBsslWebcryptoKey* = ptr BsslWebcryptoKey

  BsslWebcryptoSlice* {.pure, final.} = object
    data*: ptr uint8
    len*: csize_t

  BsslWebcryptoBuffer* {.pure, final.} = object
    data*: ptr uint8
    len*: csize_t

  WebcryptoHash* {.size: sizeof(cint).} = enum
    whSha1 = 1
    whSha256 = 256
    whSha384 = 384
    whSha512 = 512

  WebcryptoDeriveAlg* {.size: sizeof(cint).} = enum
    wdHkdf = 1
    wdPbkdf2 = 2

  WebcryptoCipherAlg* {.size: sizeof(cint).} = enum
    wcAesGcm = 1
    wcAesCbc = 2
    wcAesCtr = 3
    wcAesKw = 4

  WebcryptoKeyKind* {.size: sizeof(cint).} = enum
    wkRsa = 1
    wkEc = 2

  WebcryptoCurve* {.size: sizeof(cint).} = enum
    wcrvNone = 0
    wcrvP256 = 256
    wcrvP384 = 384
    wcrvP521 = 521

  WebcryptoKeyFormat* {.size: sizeof(cint).} = enum
    wkfSpki = 1
    wkfPkcs8 = 2
    wkfEcUncompressedPoint = 3
    wkfRsaN = 10
    wkfRsaE = 11
    wkfRsaD = 12
    wkfRsaP = 13
    wkfRsaQ = 14
    wkfRsaDp = 15
    wkfRsaDq = 16
    wkfRsaQi = 17
    wkfEcX = 20
    wkfEcY = 21
    wkfEcD = 22

  WebcryptoSignScheme* {.size: sizeof(cint).} = enum
    wssRsaPkcs1v15 = 1
    wssRsaPss = 2
    wssEcdsa = 3

  WebcryptoError* = object of CatchableError

  WebcryptoKeyObj = object
    raw*: PBsslWebcryptoKey
  WebcryptoKey* = ref WebcryptoKeyObj

{.push cdecl, dynlib: libname.}

proc bssl_webcrypto_buffer_free*(buffer: BsslWebcryptoBuffer) {.importc: "bssl_webcrypto_buffer_free".}
proc bssl_webcrypto_key_free*(key: PBsslWebcryptoKey) {.importc: "bssl_webcrypto_key_free".}
proc bssl_webcrypto_digest*(hash: cint, data: BsslWebcryptoSlice,
                            outBuf: var BsslWebcryptoBuffer): cint {.importc: "bssl_webcrypto_digest".}
proc bssl_webcrypto_hmac*(hash: cint, key: BsslWebcryptoSlice, data: BsslWebcryptoSlice,
                          outBuf: var BsslWebcryptoBuffer): cint {.importc: "bssl_webcrypto_hmac".}
proc bssl_webcrypto_equal*(a: BsslWebcryptoSlice, b: BsslWebcryptoSlice): cint {.importc: "bssl_webcrypto_equal".}
proc bssl_webcrypto_derive*(algorithm: cint, hash: cint, key: BsslWebcryptoSlice,
                            salt: BsslWebcryptoSlice, info: BsslWebcryptoSlice,
                            iterations: uint32, outPtr: ptr uint8, outLen: csize_t): cint {.importc: "bssl_webcrypto_derive".}
proc bssl_webcrypto_cipher*(cipher: cint, encrypt: cint, key: BsslWebcryptoSlice,
                            iv: BsslWebcryptoSlice, aad: BsslWebcryptoSlice,
                            data: BsslWebcryptoSlice, tagLen: csize_t,
                            outBuf: var BsslWebcryptoBuffer): cint {.importc: "bssl_webcrypto_cipher".}
proc bssl_webcrypto_key_generate*(kind: cint, curve: cint, bits: cuint,
                                  exponent: BsslWebcryptoSlice): PBsslWebcryptoKey {.importc: "bssl_webcrypto_key_generate".}
proc bssl_webcrypto_key_parse*(privateKey: cint, der: BsslWebcryptoSlice): PBsslWebcryptoKey {.importc: "bssl_webcrypto_key_parse".}
proc bssl_webcrypto_key_rsa*(components: ptr BsslWebcryptoSlice): PBsslWebcryptoKey {.importc: "bssl_webcrypto_key_rsa".}
proc bssl_webcrypto_key_ec*(curve: cint, x: BsslWebcryptoSlice, y: BsslWebcryptoSlice,
                            d: BsslWebcryptoSlice): PBsslWebcryptoKey {.importc: "bssl_webcrypto_key_ec".}
proc bssl_webcrypto_key_kind*(key: PBsslWebcryptoKey): cint {.importc: "bssl_webcrypto_key_kind".}
proc bssl_webcrypto_key_curve*(key: PBsslWebcryptoKey): cint {.importc: "bssl_webcrypto_key_curve".}
proc bssl_webcrypto_key_bits*(key: PBsslWebcryptoKey): cuint {.importc: "bssl_webcrypto_key_bits".}
proc bssl_webcrypto_key_export*(key: PBsslWebcryptoKey, format: cint,
                                outBuf: var BsslWebcryptoBuffer): cint {.importc: "bssl_webcrypto_key_export".}
proc bssl_webcrypto_sign*(key: PBsslWebcryptoKey, scheme: cint, hash: cint,
                          saltLen: cint, data: BsslWebcryptoSlice,
                          outBuf: var BsslWebcryptoBuffer): cint {.importc: "bssl_webcrypto_sign".}
proc bssl_webcrypto_verify*(key: PBsslWebcryptoKey, scheme: cint, hash: cint,
                            saltLen: cint, data: BsslWebcryptoSlice,
                            signature: BsslWebcryptoSlice): cint {.importc: "bssl_webcrypto_verify".}
proc bssl_webcrypto_oaep*(key: PBsslWebcryptoKey, encrypt: cint, hash: cint,
                          label: BsslWebcryptoSlice, data: BsslWebcryptoSlice,
                          outBuf: var BsslWebcryptoBuffer): cint {.importc: "bssl_webcrypto_oaep".}
proc bssl_webcrypto_ecdh*(key: PBsslWebcryptoKey, peer: PBsslWebcryptoKey,
                          outBuf: var BsslWebcryptoBuffer): cint {.importc: "bssl_webcrypto_ecdh".}

{.pop.}

when defined(gcDestructors):
  proc `=destroy`(x: var WebcryptoKeyObj) =
    if x.raw != nil:
      bssl_webcrypto_key_free(x.raw)
      x.raw = nil

proc toSlice(data: openArray[byte]): BsslWebcryptoSlice {.inline.} =
  if data.len == 0:
    BsslWebcryptoSlice(data: nil, len: 0)
  else:
    BsslWebcryptoSlice(data: unsafeAddr data[0], len: data.len.csize_t)

proc toSlice(data: string): BsslWebcryptoSlice {.inline.} =
  if data.len == 0:
    BsslWebcryptoSlice(data: nil, len: 0)
  else:
    BsslWebcryptoSlice(data: cast[ptr uint8](unsafeAddr data[0]), len: data.len.csize_t)

proc consumeToBytes(buf: var BsslWebcryptoBuffer): seq[byte] =
  try:
    if buf.len > 0 and buf.data != nil:
      result = newSeq[byte](buf.len)
      copyMem(addr result[0], buf.data, buf.len)
  finally:
    bssl_webcrypto_buffer_free(buf)
    buf.data = nil
    buf.len = 0

proc webcryptoDigest*(hash: WebcryptoHash, data: openArray[byte]): seq[byte] =
  ## Computes the cryptographic digest (SHA-1, SHA-256, SHA-384, or SHA-512) of `data`.
  var outBuf = BsslWebcryptoBuffer(data: nil, len: 0)
  if bssl_webcrypto_digest(cint(hash), toSlice(data), outBuf) != 1:
    raise newException(WebcryptoError, "bssl_webcrypto_digest failed")
  result = consumeToBytes(outBuf)

proc webcryptoDigest*(hash: WebcryptoHash, data: string): seq[byte] =
  var outBuf = BsslWebcryptoBuffer(data: nil, len: 0)
  if bssl_webcrypto_digest(cint(hash), toSlice(data), outBuf) != 1:
    raise newException(WebcryptoError, "bssl_webcrypto_digest failed")
  result = consumeToBytes(outBuf)

proc webcryptoHmac*(hash: WebcryptoHash, key, data: openArray[byte]): seq[byte] =
  ## Computes HMAC over `data` using `key` and `hash`.
  var outBuf = BsslWebcryptoBuffer(data: nil, len: 0)
  if bssl_webcrypto_hmac(cint(hash), toSlice(key), toSlice(data), outBuf) != 1:
    raise newException(WebcryptoError, "bssl_webcrypto_hmac failed")
  result = consumeToBytes(outBuf)

proc webcryptoHmac*(hash: WebcryptoHash, key, data: string): seq[byte] =
  var outBuf = BsslWebcryptoBuffer(data: nil, len: 0)
  if bssl_webcrypto_hmac(cint(hash), toSlice(key), toSlice(data), outBuf) != 1:
    raise newException(WebcryptoError, "bssl_webcrypto_hmac failed")
  result = consumeToBytes(outBuf)

proc webcryptoEqual*(a, b: openArray[byte]): bool =
  ## Constant-time byte comparison.
  bssl_webcrypto_equal(toSlice(a), toSlice(b)) == 1

proc webcryptoEqual*(a, b: string): bool =
  bssl_webcrypto_equal(toSlice(a), toSlice(b)) == 1

proc webcryptoHkdf*(hash: WebcryptoHash, key, salt, info: openArray[byte], outLen: int): seq[byte] =
  ## Derives `outLen` bytes using HKDF.
  if outLen <= 0:
    return @[]
  result = newSeq[byte](outLen)
  if bssl_webcrypto_derive(cint(wdHkdf), cint(hash), toSlice(key), toSlice(salt),
                           toSlice(info), 0'u32, addr result[0], outLen.csize_t) != 1:
    raise newException(WebcryptoError, "bssl_webcrypto_derive (HKDF) failed")

proc webcryptoPbkdf2*(hash: WebcryptoHash, password, salt: openArray[byte],
                      iterations: uint32, outLen: int): seq[byte] =
  ## Derives `outLen` bytes using PBKDF2.
  if outLen <= 0:
    return @[]
  result = newSeq[byte](outLen)
  let emptySlice = BsslWebcryptoSlice(data: nil, len: 0)
  if bssl_webcrypto_derive(cint(wdPbkdf2), cint(hash), toSlice(password), toSlice(salt),
                           emptySlice, iterations, addr result[0], outLen.csize_t) != 1:
    raise newException(WebcryptoError, "bssl_webcrypto_derive (PBKDF2) failed")

proc webcryptoCipher*(alg: WebcryptoCipherAlg, encrypt: bool, key, iv, aad, data: openArray[byte],
                      tagLen: int = 16): seq[byte] =
  ## Encrypts or decrypts `data` using AES-GCM, AES-CBC, AES-CTR, or AES-KW.
  var outBuf = BsslWebcryptoBuffer(data: nil, len: 0)
  let encInt: cint = if encrypt: 1 else: 0
  if bssl_webcrypto_cipher(cint(alg), encInt, toSlice(key), toSlice(iv),
                           toSlice(aad), toSlice(data), tagLen.csize_t, outBuf) != 1:
    raise newException(WebcryptoError, "bssl_webcrypto_cipher failed")
  result = consumeToBytes(outBuf)

proc generateEcKey*(curve: WebcryptoCurve): WebcryptoKey =
  ## Generates a new EC private key on `curve` (P-256, P-384, or P-521).
  let emptyExp = BsslWebcryptoSlice(data: nil, len: 0)
  let raw = bssl_webcrypto_key_generate(cint(wkEc), cint(curve), 0'u32, emptyExp)
  if raw == nil:
    raise newException(WebcryptoError, "bssl_webcrypto_key_generate (EC) failed")
  result = WebcryptoKey(raw: raw)

proc generateRsaKey*(bits: int = 2048, exponent: openArray[byte] = [0x01'u8, 0x00'u8, 0x01'u8]): WebcryptoKey =
  ## Generates a new RSA private key with `bits` modulus size and public `exponent` (defaults to 65537).
  let raw = bssl_webcrypto_key_generate(cint(wkRsa), 0, bits.cuint, toSlice(exponent))
  if raw == nil:
    raise newException(WebcryptoError, "bssl_webcrypto_key_generate (RSA) failed")
  result = WebcryptoKey(raw: raw)

proc parseKey*(der: openArray[byte], isPrivate: bool): WebcryptoKey =
  ## Parses a PKCS#8 PrivateKeyInfo (`isPrivate = true`) or SPKI (`isPrivate = false`) DER key.
  let raw = bssl_webcrypto_key_parse(if isPrivate: 1 else: 0, toSlice(der))
  if raw == nil:
    raise newException(WebcryptoError, "bssl_webcrypto_key_parse failed")
  result = WebcryptoKey(raw: raw)

proc kind*(key: WebcryptoKey): WebcryptoKeyKind =
  case bssl_webcrypto_key_kind(key.raw)
  of 1: wkRsa
  of 2: wkEc
  else: raise newException(WebcryptoError, "Unknown key kind")

proc curve*(key: WebcryptoKey): WebcryptoCurve =
  case bssl_webcrypto_key_curve(key.raw)
  of 256: wcrvP256
  of 384: wcrvP384
  of 521: wcrvP521
  else: wcrvNone

proc bits*(key: WebcryptoKey): int =
  int(bssl_webcrypto_key_bits(key.raw))

proc exportKey*(key: WebcryptoKey, format: WebcryptoKeyFormat): seq[byte] =
  ## Exports `key` in the requested `format` (SPKI, PKCS#8, uncompressed EC point, or raw RSA/EC components).
  var outBuf = BsslWebcryptoBuffer(data: nil, len: 0)
  if bssl_webcrypto_key_export(key.raw, cint(format), outBuf) != 1:
    raise newException(WebcryptoError, "bssl_webcrypto_key_export failed")
  result = consumeToBytes(outBuf)

proc sign*(key: WebcryptoKey, scheme: WebcryptoSignScheme, hash: WebcryptoHash,
           data: openArray[byte], saltLen: int = 0): seq[byte] =
  ## Signs `data` using `key`, `scheme`, and `hash`.
  var outBuf = BsslWebcryptoBuffer(data: nil, len: 0)
  if bssl_webcrypto_sign(key.raw, cint(scheme), cint(hash), saltLen.cint,
                         toSlice(data), outBuf) != 1:
    raise newException(WebcryptoError, "bssl_webcrypto_sign failed")
  result = consumeToBytes(outBuf)

proc verify*(key: WebcryptoKey, scheme: WebcryptoSignScheme, hash: WebcryptoHash,
             data, signature: openArray[byte], saltLen: int = 0): bool =
  ## Verifies `signature` over `data` using `key`, `scheme`, and `hash`.
  bssl_webcrypto_verify(key.raw, cint(scheme), cint(hash), saltLen.cint,
                        toSlice(data), toSlice(signature)) == 1

proc oaep*(key: WebcryptoKey, encrypt: bool, hash: WebcryptoHash,
           data: openArray[byte], label: openArray[byte] = []): seq[byte] =
  ## Performs RSA-OAEP encryption or decryption.
  var outBuf = BsslWebcryptoBuffer(data: nil, len: 0)
  if bssl_webcrypto_oaep(key.raw, if encrypt: 1 else: 0, cint(hash),
                         toSlice(label), toSlice(data), outBuf) != 1:
    raise newException(WebcryptoError, "bssl_webcrypto_oaep failed")
  result = consumeToBytes(outBuf)

proc ecdh*(privateKey, peerPublicKey: WebcryptoKey): seq[byte] =
  ## Performs ECDH shared secret derivation between `privateKey` and `peerPublicKey`.
  var outBuf = BsslWebcryptoBuffer(data: nil, len: 0)
  if bssl_webcrypto_ecdh(privateKey.raw, peerPublicKey.raw, outBuf) != 1:
    raise newException(WebcryptoError, "bssl_webcrypto_ecdh failed")
  result = consumeToBytes(outBuf)
