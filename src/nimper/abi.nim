#
#          curl-impersonate Wrapper for Nim
#        Low-level C ABI Bindings (curl 8.23.0-IMPERSONATE)
#

## Low-level C bindings for `libcurl-impersonate` (and backwards-compatible with standard `libcurl`).
## Exposes the complete C API of `libcurl-impersonate` v2.3.x (based on curl 8.23.0-IMPERSONATE),
## including:
## - `curl_easy_impersonate` and all `CURLOPT_*` / `CURLINFO_*` extensions for TLS, HTTP/2, HTTP/3, QUIC, and WebSockets fingerprinting
## - Standard `easy`, `multi`, `share`, `mime`, `url`, `header`, `options`, and `websockets` APIs
## - Backwards-compatible symbol aliases matching Nim's `libcurl` package (`PCurl`, `Option`, `Code`, `INFO`, `easy_init`, etc.)

import std/[times, os]

const
   homeLibDir = getHomeDir() / ".local" / "lib" & "/"

when defined(windows):
  const
    defaultLibName = "libcurl-impersonate(|-chrome|-ff).dll|libcurl.dll"
elif defined(macosx):
  const
    defaultLibName = "(" & homeLibDir & "|/opt/homebrew/lib/|/usr/local/lib/|)(libcurl-impersonate(|-chrome|-ff)|libcurl)(|.4).dylib"
else:
  const
    defaultLibName = "(" & homeLibDir & "|/usr/local/lib/|/usr/lib/|/usr/lib/x86_64-linux-gnu/|/usr/lib/aarch64-linux-gnu/|)(libcurl-impersonate(|-chrome|-ff)|libcurl).so(|.4)"

const
  curlImpLib* {.strdefine.} = defaultLibName
  libname* = curlImpLib

type
  CurlOffT* = int64
  CurlSocketT* = int32
  Socket* = CurlSocketT
  Psocket* = ptr Socket

  Curl* = pointer
  PCurl* = ptr Curl
  M* = pointer
  PM* = ptr M
  SH* = pointer
  PSH* = ptr SH
  CurlU* = pointer
  PCurlU* = ptr CurlU
  CurlMime* = pointer
  PCurlMime* = ptr CurlMime
  CurlMimePart* = pointer
  PCurlMimePart* = ptr CurlMimePart
  Pfd_set* = pointer

  Slist* {.pure, final.} = object
    data*: cstring
    next*: Pslist
  Pslist* = ptr Slist

  CurlBlob* {.pure, final.} = object
    data*: pointer
    len*: csize_t
    flags*: cuint
  PCurlBlob* = ptr CurlBlob

  Httppost* {.pure, final.} = object
    next*: Phttppost
    name*: cstring
    namelength*: clong
    contents*: cstring
    contentslength*: clong
    buffer*: cstring
    bufferlength*: clong
    contenttype*: cstring
    contentheader*: Pslist
    more*: Phttppost
    flags*: clong
    showfilename*: cstring
    userp*: pointer
    contentlen*: CurlOffT
  Phttppost* = ptr Httppost
  PPcurl_httppost* = ptr Phttppost

  CurlSslBackendId* {.size: sizeof(cint).} = enum
    SSLBACKEND_NONE = 0
    SSLBACKEND_OPENSSL = 1
    SSLBACKEND_GNUTLS = 2
    SSLBACKEND_NSS = 3
    SSLBACKEND_OBSOLETE4 = 4
    SSLBACKEND_GSKIT = 5
    SSLBACKEND_POLARSSL = 6
    SSLBACKEND_WOLFSSL = 7
    SSLBACKEND_SCHANNEL = 8
    SSLBACKEND_SECURETRANSPORT = 9
    SSLBACKEND_AXTLS = 10
    SSLBACKEND_MBEDTLS = 11
    SSLBACKEND_MESALINK = 12
    SSLBACKEND_BEARSSL = 13
    SSLBACKEND_RUSTLS = 14

  CurlSslBackend* {.pure, final.} = object
    id*: CurlSslBackendId
    name*: cstring
  PCurlSslBackend* = ptr CurlSslBackend

  CurlSslSet* {.size: sizeof(cint).} = enum
    SSLSET_OK = 0
    SSLSET_UNKNOWN_BACKEND = 1
    SSLSET_TOO_LATE = 2
    SSLSET_NO_BACKENDS = 3

  CurlFileType* {.size: sizeof(cint).} = enum
    FILETYPE_FILE = 0
    FILETYPE_DIRECTORY = 1
    FILETYPE_SYMLINK = 2
    FILETYPE_DEVICE_BLOCK = 3
    FILETYPE_DEVICE_CHAR = 4
    FILETYPE_NAMEDPIPE = 5
    FILETYPE_SOCKET = 6
    FILETYPE_DOOR = 7
    FILETYPE_UNKNOWN = 8

  CurlSockType* {.size: sizeof(cint).} = enum
    SOCKTYPE_IPCXN = 0
    SOCKTYPE_ACCEPT = 1
    SOCKTYPE_LAST = 2

  Ioerr* {.size: sizeof(cint).} = enum
    IOE_OK = 0
    IOE_UNKNOWNCMD = 1
    IOE_FAILRESTART = 2
    IOE_LAST = 3
  Pioerr* = ptr Ioerr

  Iocmd* {.size: sizeof(cint).} = enum
    IOCMD_NOP = 0
    IOCMD_RESTARTREAD = 1
    IOCMD_LAST = 2
  Piocmd* = ptr Iocmd

  Infotype* {.size: sizeof(cint).} = enum
    INFO_TEXT = 0
    INFO_HEADER_IN = 1
    INFO_HEADER_OUT = 2
    INFO_DATA_IN = 3
    INFO_DATA_OUT = 4
    INFO_SSL_DATA_IN = 5
    INFO_SSL_DATA_OUT = 6
    INFO_END = 7
  Pinfotype* = ptr Infotype

  Code* {.size: sizeof(cint).} = enum
    E_OK = 0
    E_UNSUPPORTED_PROTOCOL = 1
    E_FAILED_INIT = 2
    E_URL_MALFORMAT = 3
    E_NOT_BUILT_IN = 4
    E_COULDNT_RESOLVE_PROXY = 5
    E_COULDNT_RESOLVE_HOST = 6
    E_COULDNT_CONNECT = 7
    E_WEIRD_SERVER_REPLY = 8
    E_REMOTE_ACCESS_DENIED = 9
    E_FTP_ACCEPT_FAILED = 10
    E_FTP_WEIRD_PASS_REPLY = 11
    E_FTP_ACCEPT_TIMEOUT = 12
    E_FTP_WEIRD_PASV_REPLY = 13
    E_FTP_WEIRD_227_FORMAT = 14
    E_FTP_CANT_GET_HOST = 15
    E_HTTP2 = 16
    E_FTP_COULDNT_SET_TYPE = 17
    E_PARTIAL_FILE = 18
    E_FTP_COULDNT_RETR_FILE = 19
    E_OBSOLETE20 = 20
    E_QUOTE_ERROR = 21
    E_HTTP_RETURNED_ERROR = 22
    E_WRITE_ERROR = 23
    E_OBSOLETE24 = 24
    E_UPLOAD_FAILED = 25
    E_READ_ERROR = 26
    E_OUT_OF_MEMORY = 27
    E_OPERATION_TIMEDOUT = 28
    E_OBSOLETE29 = 29
    E_FTP_PORT_FAILED = 30
    E_FTP_COULDNT_USE_REST = 31
    E_OBSOLETE32 = 32
    E_RANGE_ERROR = 33
    E_OBSOLETE34 = 34
    E_SSL_CONNECT_ERROR = 35
    E_BAD_DOWNLOAD_RESUME = 36
    E_FILE_COULDNT_READ_FILE = 37
    E_LDAP_CANNOT_BIND = 38
    E_LDAP_SEARCH_FAILED = 39
    E_OBSOLETE40 = 40
    E_OBSOLETE41 = 41
    E_ABORTED_BY_CALLBACK = 42
    E_BAD_FUNCTION_ARGUMENT = 43
    E_OBSOLETE44 = 44
    E_INTERFACE_FAILED = 45
    E_OBSOLETE46 = 46
    E_TOO_MANY_REDIRECTS = 47
    E_UNKNOWN_OPTION = 48
    E_SETOPT_OPTION_SYNTAX = 49
    E_OBSOLETE50 = 50
    E_OBSOLETE51 = 51
    E_GOT_NOTHING = 52
    E_SSL_ENGINE_NOTFOUND = 53
    E_SSL_ENGINE_SETFAILED = 54
    E_SEND_ERROR = 55
    E_RECV_ERROR = 56
    E_OBSOLETE57 = 57
    E_SSL_CERTPROBLEM = 58
    E_SSL_CIPHER = 59
    E_PEER_FAILED_VERIFICATION = 60
    E_BAD_CONTENT_ENCODING = 61
    E_OBSOLETE62 = 62
    E_FILESIZE_EXCEEDED = 63
    E_USE_SSL_FAILED = 64
    E_SEND_FAIL_REWIND = 65
    E_SSL_ENGINE_INITFAILED = 66
    E_LOGIN_DENIED = 67
    E_TFTP_NOTFOUND = 68
    E_TFTP_PERM = 69
    E_REMOTE_DISK_FULL = 70
    E_TFTP_ILLEGAL = 71
    E_TFTP_UNKNOWNID = 72
    E_REMOTE_FILE_EXISTS = 73
    E_TFTP_NOSUCHUSER = 74
    E_OBSOLETE75 = 75
    E_OBSOLETE76 = 76
    E_SSL_CACERT_BADFILE = 77
    E_REMOTE_FILE_NOT_FOUND = 78
    E_SSH = 79
    E_SSL_SHUTDOWN_FAILED = 80
    E_AGAIN = 81
    E_SSL_CRL_BADFILE = 82
    E_SSL_ISSUER_ERROR = 83
    E_FTP_PRET_FAILED = 84
    E_RTSP_CSEQ_ERROR = 85
    E_RTSP_SESSION_ERROR = 86
    E_FTP_BAD_FILE_LIST = 87
    E_CHUNK_FAILED = 88
    E_NO_CONNECTION_AVAILABLE = 89
    E_SSL_PINNEDPUBKEYNOTMATCH = 90
    E_SSL_INVALIDCERTSTATUS = 91
    E_HTTP2_STREAM = 92
    E_RECURSIVE_API_CALL = 93
    E_AUTH_ERROR = 94
    E_HTTP3 = 95
    E_QUIC_CONNECT_ERROR = 96
    E_PROXY = 97
    E_SSL_CLIENTCERT = 98
    E_UNRECOVERABLE_POLL = 99
    E_TOO_LARGE = 100
    E_ECH_REQUIRED = 101
    LAST = 102
  Pcode* = ptr Code
  CURLcode* = Code

  ProxyCode* {.size: sizeof(cint).} = enum
    PX_OK = 0
    PX_BAD_ADDRESS_TYPE
    PX_BAD_VERSION
    PX_CLOSED
    PX_GSSAPI
    PX_GSSAPI_PERMSG
    PX_GSSAPI_PROTECTION
    PX_IDENTD
    PX_IDENTD_DIFFER
    PX_LONG_HOSTNAME
    PX_LONG_PASSWD
    PX_LONG_USER
    PX_NO_AUTH
    PX_RECV_ADDRESS
    PX_RECV_AUTH
    PX_RECV_CONNECT
    PX_RECV_REQACK
    PX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED
    PX_REPLY_COMMAND_NOT_SUPPORTED
    PX_REPLY_CONNECTION_REFUSED
    PX_REPLY_GENERAL_SERVER_FAILURE
    PX_REPLY_HOST_UNREACHABLE
    PX_REPLY_NETWORK_UNREACHABLE
    PX_REPLY_NOT_ALLOWED
    PX_REPLY_TTL_EXPIRED
    PX_REPLY_UNASSIGNED
    PX_REQUEST_FAILED
    PX_RESOLVE_HOST
    PX_SEND_AUTH
    PX_SEND_CONNECT
    PX_SEND_REQUEST
    PX_UNKNOWN_FAIL
    PX_UNKNOWN_MODE
    PX_USER_REJECTED
    PX_LAST

  Proxytype* {.size: sizeof(cint).} = enum
    PROXY_HTTP = 0
    PROXY_HTTP_1_0 = 1
    PROXY_HTTPS = 2
    PROXY_HTTPS2 = 3
    PROXY_SOCKS4 = 4
    PROXY_SOCKS5 = 5
    PROXY_SOCKS4A = 6
    PROXY_SOCKS5_HOSTNAME = 7
    PROXY_HTTPS3 = 8
    PROXY_LAST = 9
  Pproxytype* = ptr Proxytype

  Ftpssl* {.size: sizeof(cint).} = enum
    FTPSSL_NONE = 0
    FTPSSL_TRY = 1
    FTPSSL_CONTROL = 2
    FTPSSL_ALL = 3
    FTPSSL_LAST = 4
  Pftpssl* = ptr Ftpssl

  Ftpauth* {.size: sizeof(cint).} = enum
    FTPAUTH_DEFAULT = 0
    FTPAUTH_SSL = 1
    FTPAUTH_TLS = 2
    FTPAUTH_LAST = 3
  Pftpauth* = ptr Ftpauth

  Ftpmethod* {.size: sizeof(cint).} = enum
    FTPMETHOD_DEFAULT = 0
    FTPMETHOD_MULTICWD = 1
    FTPMETHOD_NOCWD = 2
    FTPMETHOD_SINGLECWD = 3
    FTPMETHOD_LAST = 4
  Pftpmethod* = ptr Ftpmethod

  HTTP_VERSION* {.size: sizeof(cint).} = enum
    HTTP_VERSION_NONE = 0
    HTTP_VERSION_1_0 = 1
    HTTP_VERSION_1_1 = 2
    HTTP_VERSION_2_0 = 3
    HTTP_VERSION_2TLS = 4
    HTTP_VERSION_2_PRIOR_KNOWLEDGE = 5
    HTTP_VERSION_3 = 30
    HTTP_VERSION_3ONLY = 31
    HTTP_VERSION_LAST = 32
  PHTTP_VERSION* = ptr HTTP_VERSION

  NETRC_OPTION* {.size: sizeof(cint).} = enum
    NETRC_IGNORED = 0
    NETRC_OPTIONAL = 1
    NETRC_REQUIRED = 2
    NETRC_LAST = 3
  PNETRC_OPTION* = ptr NETRC_OPTION

  SSL_VERSION* {.size: sizeof(cint).} = enum
    SSLVERSION_DEFAULT = 0
    SSLVERSION_TLSv1 = 1
    SSLVERSION_SSLv2 = 2
    SSLVERSION_SSLv3 = 3
    SSLVERSION_TLSv1_0 = 4
    SSLVERSION_TLSv1_1 = 5
    SSLVERSION_TLSv1_2 = 6
    SSLVERSION_TLSv1_3 = 7
    SSLVERSION_LAST = 8
  PSSL_VERSION* = ptr SSL_VERSION

  TIMECOND* {.size: sizeof(cint).} = enum
    TIMECOND_NONE = 0
    TIMECOND_IFMODSINCE = 1
    TIMECOND_IFUNMODSINCE = 2
    TIMECOND_LASTMOD = 3
    TIMECOND_LAST = 4
  PTIMECOND* = ptr TIMECOND

  Option* {.size: sizeof(cint).} = enum
    OPT_PORT = 0 + 3
    OPT_TIMEOUT = 0 + 13
    OPT_INFILESIZE = 0 + 14
    OPT_LOW_SPEED_LIMIT = 0 + 19
    OPT_LOW_SPEED_TIME = 0 + 20
    OPT_RESUME_FROM = 0 + 21
    OPT_CRLF = 0 + 27
    OPT_SSLVERSION = 0 + 32
    OPT_TIMECONDITION = 0 + 33
    OPT_TIMEVALUE = 0 + 34
    OPT_VERBOSE = 0 + 41
    OPT_HEADER = 0 + 42
    OPT_NOPROGRESS = 0 + 43
    OPT_NOBODY = 0 + 44
    OPT_FAILONERROR = 0 + 45
    OPT_UPLOAD = 0 + 46
    OPT_POST = 0 + 47
    OPT_DIRLISTONLY = 0 + 48
    OPT_APPEND = 0 + 50
    OPT_NETRC = 0 + 51
    OPT_FOLLOWLOCATION = 0 + 52
    OPT_TRANSFERTEXT = 0 + 53
    OPT_PUT = 0 + 54
    OPT_AUTOREFERER = 0 + 58
    OPT_PROXYPORT = 0 + 59
    OPT_POSTFIELDSIZE = 0 + 60
    OPT_HTTPPROXYTUNNEL = 0 + 61
    OPT_SSL_VERIFYPEER = 0 + 64
    OPT_MAXREDIRS = 0 + 68
    OPT_FILETIME = 0 + 69
    OPT_MAXCONNECTS = 0 + 71
    OPT_CLOSEPOLICY = 0 + 72
    OPT_FRESH_CONNECT = 0 + 74
    OPT_FORBID_REUSE = 0 + 75
    OPT_CONNECTTIMEOUT = 0 + 78
    OPT_HTTPGET = 0 + 80
    OPT_SSL_VERIFYHOST = 0 + 81
    OPT_HTTP_VERSION = 0 + 84
    OPT_FTP_USE_EPSV = 0 + 85
    OPT_SSLENGINE_DEFAULT = 0 + 90
    OPT_DNS_USE_GLOBAL_CACHE = 0 + 91
    OPT_DNS_CACHE_TIMEOUT = 0 + 92
    OPT_COOKIESESSION = 0 + 96
    OPT_BUFFERSIZE = 0 + 98
    OPT_NOSIGNAL = 0 + 99
    OPT_PROXYTYPE = 0 + 101
    OPT_UNRESTRICTED_AUTH = 0 + 105
    OPT_FTP_USE_EPRT = 0 + 106
    OPT_HTTPAUTH = 0 + 107
    OPT_FTP_CREATE_MISSING_DIRS = 0 + 110
    OPT_PROXYAUTH = 0 + 111
    OPT_SERVER_RESPONSE_TIMEOUT = 0 + 112
    OPT_IPRESOLVE = 0 + 113
    OPT_MAXFILESIZE = 0 + 114
    OPT_USE_SSL = 0 + 119
    OPT_TCP_NODELAY = 0 + 121
    OPT_FTPSSLAUTH = 0 + 129
    OPT_IGNORE_CONTENT_LENGTH = 0 + 136
    OPT_FTP_SKIP_PASV_IP = 0 + 137
    OPT_FTP_FILEMETHOD = 0 + 138
    OPT_LOCALPORT = 0 + 139
    OPT_LOCALPORTRANGE = 0 + 140
    OPT_CONNECT_ONLY = 0 + 141
    OPT_SSL_SESSIONID_CACHE = 0 + 150
    OPT_SSH_AUTH_TYPES = 0 + 151
    OPT_FTP_SSL_CCC = 0 + 154
    OPT_TIMEOUT_MS = 0 + 155
    OPT_CONNECTTIMEOUT_MS = 0 + 156
    OPT_HTTP_TRANSFER_DECODING = 0 + 157
    OPT_HTTP_CONTENT_DECODING = 0 + 158
    OPT_NEW_FILE_PERMS = 0 + 159
    OPT_NEW_DIRECTORY_PERMS = 0 + 160
    OPT_POSTREDIR = 0 + 161
    OPT_PROXY_TRANSFER_MODE = 0 + 166
    OPT_ADDRESS_SCOPE = 0 + 171
    OPT_CERTINFO = 0 + 172
    OPT_TFTP_BLKSIZE = 0 + 178
    OPT_SOCKS5_GSSAPI_NEC = 0 + 180
    OPT_PROTOCOLS = 0 + 181
    OPT_REDIR_PROTOCOLS = 0 + 182
    OPT_FTP_USE_PRET = 0 + 188
    OPT_RTSP_REQUEST = 0 + 189
    OPT_RTSP_CLIENT_CSEQ = 0 + 193
    OPT_RTSP_SERVER_CSEQ = 0 + 194
    OPT_WILDCARDMATCH = 0 + 197
    OPT_TRANSFER_ENCODING = 0 + 207
    OPT_GSSAPI_DELEGATION = 0 + 210
    OPT_ACCEPTTIMEOUT_MS = 0 + 212
    OPT_TCP_KEEPALIVE = 0 + 213
    OPT_TCP_KEEPIDLE = 0 + 214
    OPT_TCP_KEEPINTVL = 0 + 215
    OPT_SSL_OPTIONS = 0 + 216
    OPT_SASL_IR = 0 + 218
    OPT_SSL_ENABLE_NPN = 0 + 225
    OPT_SSL_ENABLE_ALPN = 0 + 226
    OPT_EXPECT_100_TIMEOUT_MS = 0 + 227
    OPT_HEADEROPT = 0 + 229
    OPT_SSL_VERIFYSTATUS = 0 + 232
    OPT_SSL_FALSESTART = 0 + 233
    OPT_PATH_AS_IS = 0 + 234
    OPT_PIPEWAIT = 0 + 237
    OPT_STREAM_WEIGHT = 0 + 239
    OPT_TFTP_NO_OPTIONS = 0 + 242
    OPT_TCP_FASTOPEN = 0 + 244
    OPT_KEEP_SENDING_ON_ERROR = 0 + 245
    OPT_PROXY_SSL_VERIFYPEER = 0 + 248
    OPT_PROXY_SSL_VERIFYHOST = 0 + 249
    OPT_PROXY_SSLVERSION = 0 + 250
    OPT_PROXY_SSL_OPTIONS = 0 + 261
    OPT_SUPPRESS_CONNECT_HEADERS = 0 + 265
    OPT_SOCKS5_AUTH = 0 + 267
    OPT_SSH_COMPRESSION = 0 + 268
    OPT_HAPPY_EYEBALLS_TIMEOUT_MS = 0 + 271
    OPT_HAPROXYPROTOCOL = 0 + 274
    OPT_DNS_SHUFFLE_ADDRESSES = 0 + 275
    OPT_DISALLOW_USERNAME_IN_URL = 0 + 278
    OPT_UPLOAD_BUFFERSIZE = 0 + 280
    OPT_UPKEEP_INTERVAL_MS = 0 + 281
    OPT_HTTP09_ALLOWED = 0 + 285
    OPT_ALTSVC_CTRL = 0 + 286
    OPT_MAXAGE_CONN = 0 + 288
    OPT_MAIL_RCPT_ALLOWFAILS = 0 + 290
    OPT_HSTS_CTRL = 0 + 299
    OPT_DOH_SSL_VERIFYPEER = 0 + 306
    OPT_DOH_SSL_VERIFYHOST = 0 + 307
    OPT_DOH_SSL_VERIFYSTATUS = 0 + 308
    OPT_MAXLIFETIME_CONN = 0 + 314
    OPT_MIME_OPTIONS = 0 + 315
    OPT_WS_OPTIONS = 0 + 320
    OPT_CA_CACHE_TIMEOUT = 0 + 321
    OPT_QUICK_EXIT = 0 + 322
    OPT_SERVER_RESPONSE_TIMEOUT_MS = 0 + 324
    OPT_TCP_KEEPCNT = 0 + 326
    OPT_UPLOAD_FLAGS = 0 + 327
    OPT_HTTPSIG_ALGORITHM = 0 + 329

    # curl-impersonate LONG options (0 + 1000..1041)
    OPT_SSL_ENABLE_ALPS = 0 + 1002
    OPT_SSL_ENABLE_TICKET = 0 + 1004
    OPT_SSL_PERMUTE_EXTENSIONS = 0 + 1007
    OPT_HTTP2_WINDOW_UPDATE = 0 + 1008
    OPT_TLS_GREASE = 0 + 1011
    OPT_STREAM_EXCLUSIVE = 0 + 1013
    OPT_TLS_KEY_USAGE_NO_CHECK = 0 + 1014
    OPT_TLS_SIGNED_CERT_TIMESTAMPS = 0 + 1015
    OPT_TLS_STATUS_REQUEST = 0 + 1016
    OPT_TLS_RECORD_SIZE_LIMIT = 0 + 1018
    OPT_TLS_KEY_SHARES_LIMIT = 0 + 1019
    OPT_TLS_USE_NEW_ALPS_CODEPOINT = 0 + 1020
    OPT_HTTP2_NO_PRIORITY = 0 + 1021
    OPT_PROXY_CREDENTIAL_NO_REUSE = 0 + 1022
    OPT_SPLIT_COOKIES = 0 + 1023
    OPT_WS_SSL_DISABLE_TICKET = 0 + 1036
    OPT_HTTP3_SSL_PERMUTE_EXTENSIONS = 0 + 1039
    OPT_QUIC_INITIAL_PACKET_NUMBER = 0 + 1041

    # OBJECTPOINT / STRINGPOINT / SLISTPOINT / CBPOINT options (10000 + N)
    OPT_WRITEDATA = 10000 + 1
    OPT_URL = 10000 + 2
    OPT_PROXY = 10000 + 4
    OPT_USERPWD = 10000 + 5
    OPT_PROXYUSERPWD = 10000 + 6
    OPT_RANGE = 10000 + 7
    OPT_READDATA = 10000 + 9
    OPT_ERRORBUFFER = 10000 + 10
    OPT_POSTFIELDS = 10000 + 15
    OPT_REFERER = 10000 + 16
    OPT_FTPPORT = 10000 + 17
    OPT_USERAGENT = 10000 + 18
    OPT_COOKIE = 10000 + 22
    OPT_HTTPHEADER = 10000 + 23
    OPT_HTTPPOST = 10000 + 24
    OPT_SSLCERT = 10000 + 25
    OPT_KEYPASSWD = 10000 + 26
    OPT_QUOTE = 10000 + 28
    OPT_HEADERDATA = 10000 + 29
    OPT_COOKIEFILE = 10000 + 31
    OPT_CUSTOMREQUEST = 10000 + 36
    OPT_STDERR = 10000 + 37
    OPT_POSTQUOTE = 10000 + 39
    OPT_WRITEINFO = 10000 + 40
    OPT_XFERINFODATA = 10000 + 57
    OPT_INTERFACE = 10000 + 62
    OPT_KRBLEVEL = 10000 + 63
    OPT_CAINFO = 10000 + 65
    OPT_TELNETOPTIONS = 10000 + 70
    OPT_RANDOM_FILE = 10000 + 76
    OPT_EGDSOCKET = 10000 + 77
    OPT_COOKIEJAR = 10000 + 82
    OPT_SSL_CIPHER_LIST = 10000 + 83
    OPT_SSLCERTTYPE = 10000 + 86
    OPT_SSLKEY = 10000 + 87
    OPT_SSLKEYTYPE = 10000 + 88
    OPT_SSLENGINE = 10000 + 89
    OPT_PREQUOTE = 10000 + 93
    OPT_DEBUGDATA = 10000 + 95
    OPT_CAPATH = 10000 + 97
    OPT_SHARE = 10000 + 100
    OPT_ACCEPT_ENCODING = 10000 + 102
    OPT_PRIVATE = 10000 + 103
    OPT_HTTP200ALIASES = 10000 + 104
    OPT_SSL_CTX_DATA = 10000 + 109
    OPT_NETRC_FILE = 10000 + 118
    OPT_SOURCE_USERPWD = 10000 + 123
    OPT_SOURCE_PREQUOTE = 10000 + 127
    OPT_SOURCE_POSTQUOTE = 10000 + 128
    OPT_IOCTLDATA = 10000 + 131
    OPT_SOURCE_URL = 10000 + 132
    OPT_SOURCE_QUOTE = 10000 + 133
    OPT_FTP_ACCOUNT = 10000 + 134
    OPT_COOKIELIST = 10000 + 135
    OPT_FTP_ALTERNATIVE_TO_USER = 10000 + 147
    OPT_SOCKOPTDATA = 10000 + 149
    OPT_SSH_PUBLIC_KEYFILE = 10000 + 152
    OPT_SSH_PRIVATE_KEYFILE = 10000 + 153
    OPT_SSH_HOST_PUBLIC_KEY_MD5 = 10000 + 162
    OPT_OPENSOCKETDATA = 10000 + 164
    OPT_COPYPOSTFIELDS = 10000 + 165
    OPT_SEEKDATA = 10000 + 168
    OPT_CRLFILE = 10000 + 169
    OPT_ISSUERCERT = 10000 + 170
    OPT_USERNAME = 10000 + 173
    OPT_PASSWORD = 10000 + 174
    OPT_PROXYUSERNAME = 10000 + 175
    OPT_PROXYPASSWORD = 10000 + 176
    OPT_NOPROXY = 10000 + 177
    OPT_SOCKS5_GSSAPI_SERVICE = 10000 + 179
    OPT_SSH_KNOWNHOSTS = 10000 + 183
    OPT_SSH_KEYDATA = 10000 + 185
    OPT_MAIL_FROM = 10000 + 186
    OPT_MAIL_RCPT = 10000 + 187
    OPT_RTSP_SESSION_ID = 10000 + 190
    OPT_RTSP_STREAM_URI = 10000 + 191
    OPT_RTSP_TRANSPORT = 10000 + 192
    OPT_INTERLEAVEDATA = 10000 + 195
    OPT_CHUNK_DATA = 10000 + 201
    OPT_FNMATCH_DATA = 10000 + 202
    OPT_RESOLVE = 10000 + 203
    OPT_TLSAUTH_USERNAME = 10000 + 204
    OPT_TLSAUTH_PASSWORD = 10000 + 205
    OPT_TLSAUTH_TYPE = 10000 + 206
    OPT_CLOSESOCKETDATA = 10000 + 209
    OPT_DNS_SERVERS = 10000 + 211
    OPT_MAIL_AUTH = 10000 + 217
    OPT_XOAUTH2_BEARER = 10000 + 220
    OPT_DNS_INTERFACE = 10000 + 221
    OPT_DNS_LOCAL_IP4 = 10000 + 222
    OPT_DNS_LOCAL_IP6 = 10000 + 223
    OPT_LOGIN_OPTIONS = 10000 + 224
    OPT_PROXYHEADER = 10000 + 228
    OPT_PINNEDPUBLICKEY = 10000 + 230
    OPT_UNIX_SOCKET_PATH = 10000 + 231
    OPT_PROXY_SERVICE_NAME = 10000 + 235
    OPT_SERVICE_NAME = 10000 + 236
    OPT_DEFAULT_PROTOCOL = 10000 + 238
    OPT_STREAM_DEPENDS = 10000 + 240
    OPT_STREAM_DEPENDS_E = 10000 + 241
    OPT_CONNECT_TO = 10000 + 243
    OPT_PROXY_CAINFO = 10000 + 246
    OPT_PROXY_CAPATH = 10000 + 247
    OPT_PROXY_TLSAUTH_USERNAME = 10000 + 251
    OPT_PROXY_TLSAUTH_PASSWORD = 10000 + 252
    OPT_PROXY_TLSAUTH_TYPE = 10000 + 253
    OPT_PROXY_SSLCERT = 10000 + 254
    OPT_PROXY_SSLCERTTYPE = 10000 + 255
    OPT_PROXY_SSLKEY = 10000 + 256
    OPT_PROXY_SSLKEYTYPE = 10000 + 257
    OPT_PROXY_KEYPASSWD = 10000 + 258
    OPT_PROXY_SSL_CIPHER_LIST = 10000 + 259
    OPT_PROXY_CRLFILE = 10000 + 260
    OPT_PRE_PROXY = 10000 + 262
    OPT_PROXY_PINNEDPUBLICKEY = 10000 + 263
    OPT_ABSTRACT_UNIX_SOCKET = 10000 + 264
    OPT_REQUEST_TARGET = 10000 + 266
    OPT_MIMEPOST = 10000 + 269
    OPT_RESOLVER_START_DATA = 10000 + 273
    OPT_TLS13_CIPHERS = 10000 + 276
    OPT_PROXY_TLS13_CIPHERS = 10000 + 277
    OPT_DOH_URL = 10000 + 279
    OPT_CURLU = 10000 + 282
    OPT_TRAILERDATA = 10000 + 284
    OPT_ALTSVC = 10000 + 287
    OPT_SASL_AUTHZID = 10000 + 289
    OPT_PROXY_ISSUERCERT = 10000 + 296
    OPT_SSL_EC_CURVES = 10000 + 298
    OPT_HSTS = 10000 + 300
    OPT_HSTSREADDATA = 10000 + 302
    OPT_HSTSWRITEDATA = 10000 + 304
    OPT_AWS_SIGV4 = 10000 + 305
    OPT_SSH_HOST_PUBLIC_KEY_SHA256 = 10000 + 311
    OPT_PREREQDATA = 10000 + 313
    OPT_SSH_HOSTKEYDATA = 10000 + 317
    OPT_PROTOCOLS_STR = 10000 + 318
    OPT_REDIR_PROTOCOLS_STR = 10000 + 319
    OPT_HAPROXY_CLIENT_IP = 10000 + 323
    OPT_ECH = 10000 + 325
    OPT_SSL_SIGNATURE_ALGORITHMS = 10000 + 328
    OPT_HTTPSIG_KEY = 10000 + 330
    OPT_HTTPSIG_KEYID = 10000 + 331
    OPT_HTTPSIG_HEADERS = 10000 + 332

    # curl-impersonate STRINGPOINT / SLISTPOINT options (10000 + 999..1040)
    OPT_IMPERSONATE = 10000 + 999
    OPT_HTTPBASEHEADER = 10000 + 1000
    OPT_SSL_SIG_HASH_ALGS = 10000 + 1001
    OPT_SSL_CERT_COMPRESSION = 10000 + 1003
    OPT_HTTP2_PSEUDO_HEADERS_ORDER = 10000 + 1005
    OPT_HTTP2_SETTINGS = 10000 + 1006
    OPT_HTTP2_STREAMS = 10000 + 1010
    OPT_TLS_EXTENSION_ORDER = 10000 + 1012
    OPT_TLS_DELEGATED_CREDENTIALS = 10000 + 1017
    OPT_FORM_BOUNDARY = 10000 + 1024
    OPT_HTTP3_PSEUDO_HEADERS_ORDER = 10000 + 1025
    OPT_HTTP3_SETTINGS = 10000 + 1026
    OPT_QUIC_TRANSPORT_PARAMETERS = 10000 + 1027
    OPT_HTTP3_SIG_HASH_ALGS = 10000 + 1028
    OPT_HTTP3_TLS_EXTENSION_ORDER = 10000 + 1029
    OPT_HTTPHEADER_ORDER = 10000 + 1030
    OPT_HTTP3_HTTPHEADER = 10000 + 1031
    OPT_HTTP3_HTTPHEADER_ORDER = 10000 + 1032
    OPT_HTTP3_SSL_EC_CURVES = 10000 + 1033
    OPT_WS_HTTPHEADER = 10000 + 1034
    OPT_WS_HTTPHEADER_ORDER = 10000 + 1035
    OPT_WS_SSL_CERT_COMPRESSION = 10000 + 1037
    OPT_QUIC_CID_LENGTH = 10000 + 1038
    OPT_TLS_TRUST_ANCHORS = 10000 + 1040
    OPT_LASTENTRY = 10000 + 1042

    # FUNCTIONPOINT options (20000 + N)
    OPT_WRITEFUNCTION = 20000 + 11
    OPT_READFUNCTION = 20000 + 12
    OPT_PROGRESSFUNCTION = 20000 + 56
    OPT_HEADERFUNCTION = 20000 + 79
    OPT_DEBUGFUNCTION = 20000 + 94
    OPT_SSL_CTX_FUNCTION = 20000 + 108
    OPT_IOCTLFUNCTION = 20000 + 130
    OPT_CONV_FROM_NETWORK_FUNCTION = 20000 + 142
    OPT_CONV_TO_NETWORK_FUNCTION = 20000 + 143
    OPT_CONV_FROM_UTF8_FUNCTION = 20000 + 144
    OPT_SOCKOPTFUNCTION = 20000 + 148
    OPT_OPENSOCKETFUNCTION = 20000 + 163
    OPT_SEEKFUNCTION = 20000 + 167
    OPT_SSH_KEYFUNCTION = 20000 + 184
    OPT_INTERLEAVEFUNCTION = 20000 + 196
    OPT_CHUNK_BGN_FUNCTION = 20000 + 198
    OPT_CHUNK_END_FUNCTION = 20000 + 199
    OPT_FNMATCH_FUNCTION = 20000 + 200
    OPT_CLOSESOCKETFUNCTION = 20000 + 208
    OPT_XFERINFOFUNCTION = 20000 + 219
    OPT_RESOLVER_START_FUNCTION = 20000 + 272
    OPT_TRAILERFUNCTION = 20000 + 283
    OPT_HSTSREADFUNCTION = 20000 + 301
    OPT_HSTSWRITEFUNCTION = 20000 + 303
    OPT_PREREQFUNCTION = 20000 + 312
    OPT_SSH_HOSTKEYFUNCTION = 20000 + 316

    # OFF_T options (30000 + N)
    OPT_INFILESIZE_LARGE = 30000 + 115
    OPT_RESUME_FROM_LARGE = 30000 + 116
    OPT_MAXFILESIZE_LARGE = 30000 + 117
    OPT_POSTFIELDSIZE_LARGE = 30000 + 120
    OPT_MAX_SEND_SPEED_LARGE = 30000 + 145
    OPT_MAX_RECV_SPEED_LARGE = 30000 + 146
    OPT_TIMEVALUE_LARGE = 30000 + 270

    # BLOB options (40000 + N)
    OPT_SSLCERT_BLOB = 40000 + 291
    OPT_SSLKEY_BLOB = 40000 + 292
    OPT_PROXY_SSLCERT_BLOB = 40000 + 293
    OPT_PROXY_SSLKEY_BLOB = 40000 + 294
    OPT_ISSUERCERT_BLOB = 40000 + 295
    OPT_PROXY_ISSUERCERT_BLOB = 40000 + 297
    OPT_CAINFO_BLOB = 40000 + 309
    OPT_PROXY_CAINFO_BLOB = 40000 + 310
  Poption* = ptr Option
  CURLoption* = Option

  Formoption* {.size: sizeof(cint).} = enum
    FORM_NOTHING = 0
    FORM_COPYNAME = 1
    FORM_PTRNAME = 2
    FORM_NAMELENGTH = 3
    FORM_COPYCONTENTS = 4
    FORM_PTRCONTENTS = 5
    FORM_CONTENTSLENGTH = 6
    FORM_FILECONTENT = 7
    FORM_ARRAY = 8
    FORM_OBSOLETE = 9
    FORM_FILE = 10
    FORM_BUFFER = 11
    FORM_BUFFERPTR = 12
    FORM_BUFFERLENGTH = 13
    FORM_CONTENTTYPE = 14
    FORM_CONTENTHEADER = 15
    FORM_FILENAME = 16
    FORM_END = 17
    FORM_OBSOLETE2 = 18
    FORM_STREAM = 19
    FORM_CONTENTLEN = 20
    FORM_LASTENTRY = 21
  Pformoption* = ptr Formoption

  Forms* {.pure, final.} = object
    option*: Formoption
    value*: cstring
  Pforms* = ptr Forms

  FORMcode* {.size: sizeof(cint).} = enum
    FORMADD_OK = 0
    FORMADD_MEMORY = 1
    FORMADD_OPTION_TWICE = 2
    FORMADD_NULL = 3
    FORMADD_UNKNOWN_OPTION = 4
    FORMADD_INCOMPLETE = 5
    FORMADD_ILLEGAL_ARRAY = 6
    FORMADD_DISABLED = 7
    FORMADD_LAST = 8
  PFORMcode* = ptr FORMcode

  CurlCertInfo* {.pure, final.} = object
    num_of_certs*: cint
    certinfo*: ptr UncheckedArray[Pslist]
  PCurlCertInfo* = ptr CurlCertInfo

  CurlTlsSessionInfo* {.pure, final.} = object
    backend*: CurlSslBackendId
    internals*: pointer
  PCurlTlsSessionInfo* = ptr CurlTlsSessionInfo

  INFO* {.size: sizeof(cint).} = enum
    INFO_NONE = 0
    INFO_LASTONE = 1001

    # STRING (0x100000 + N)
    INFO_EFFECTIVE_URL = 0x00100000 + 1
    INFO_CONTENT_TYPE = 0x00100000 + 18
    INFO_PRIVATE = 0x00100000 + 21
    INFO_FTP_ENTRY_PATH = 0x00100000 + 30
    INFO_REDIRECT_URL = 0x00100000 + 31
    INFO_PRIMARY_IP = 0x00100000 + 32
    INFO_RTSP_SESSION_ID = 0x00100000 + 36
    INFO_LOCAL_IP = 0x00100000 + 41
    INFO_SCHEME = 0x00100000 + 49
    INFO_EFFECTIVE_METHOD = 0x00100000 + 58
    INFO_REFERER = 0x00100000 + 60
    INFO_CAINFO = 0x00100000 + 61
    INFO_CAPATH = 0x00100000 + 62

    # LONG (0x200000 + N)
    INFO_RESPONSE_CODE = 0x00200000 + 2
    INFO_HEADER_SIZE = 0x00200000 + 11
    INFO_REQUEST_SIZE = 0x00200000 + 12
    INFO_SSL_VERIFYRESULT = 0x00200000 + 13
    INFO_FILETIME = 0x00200000 + 14
    INFO_REDIRECT_COUNT = 0x00200000 + 20
    INFO_HTTP_CONNECTCODE = 0x00200000 + 22
    INFO_HTTPAUTH_AVAIL = 0x00200000 + 23
    INFO_PROXYAUTH_AVAIL = 0x00200000 + 24
    INFO_OS_ERRNO = 0x00200000 + 25
    INFO_NUM_CONNECTS = 0x00200000 + 26
    INFO_LASTSOCKET = 0x00200000 + 29
    INFO_CONDITION_UNMET = 0x00200000 + 35
    INFO_RTSP_CLIENT_CSEQ = 0x00200000 + 37
    INFO_RTSP_SERVER_CSEQ = 0x00200000 + 38
    INFO_RTSP_CSEQ_RECV = 0x00200000 + 39
    INFO_PRIMARY_PORT = 0x00200000 + 40
    INFO_LOCAL_PORT = 0x00200000 + 42
    INFO_HTTP_VERSION = 0x00200000 + 46
    INFO_PROXY_SSL_VERIFYRESULT = 0x00200000 + 47
    INFO_PROTOCOL = 0x00200000 + 48
    INFO_PROXY_ERROR = 0x00200000 + 59
    INFO_USED_PROXY = 0x00200000 + 66
    INFO_HTTPAUTH_USED = 0x00200000 + 69
    INFO_PROXYAUTH_USED = 0x00200000 + 70

    # DOUBLE (0x300000 + N)
    INFO_TOTAL_TIME = 0x00300000 + 3
    INFO_NAMELOOKUP_TIME = 0x00300000 + 4
    INFO_CONNECT_TIME = 0x00300000 + 5
    INFO_PRETRANSFER_TIME = 0x00300000 + 6
    INFO_SIZE_UPLOAD = 0x00300000 + 7
    INFO_SIZE_DOWNLOAD = 0x00300000 + 8
    INFO_SPEED_DOWNLOAD = 0x00300000 + 9
    INFO_SPEED_UPLOAD = 0x00300000 + 10
    INFO_CONTENT_LENGTH_DOWNLOAD = 0x00300000 + 15
    INFO_CONTENT_LENGTH_UPLOAD = 0x00300000 + 16
    INFO_STARTTRANSFER_TIME = 0x00300000 + 17
    INFO_REDIRECT_TIME = 0x00300000 + 19
    INFO_APPCONNECT_TIME = 0x00300000 + 33

    # SLIST / PTR (0x400000 + N)
    INFO_SSL_ENGINES = 0x00400000 + 27
    INFO_COOKIELIST = 0x00400000 + 28
    INFO_CERTINFO = 0x00400000 + 34
    INFO_TLS_SESSION = 0x00400000 + 43
    INFO_TLS_SSL_PTR = 0x00400000 + 45
    # curl-impersonate custom CURLINFOs
    INFO_COOKIECHANGES = 0x00400000 + 1000
    INFO_REDIRECT_HISTORY = 0x00400000 + 1001

    # SOCKET (0x500000 + N)
    INFO_ACTIVESOCKET = 0x00500000 + 44

    # OFF_T (0x600000 + N)
    INFO_SIZE_UPLOAD_T = 0x00600000 + 7
    INFO_SIZE_DOWNLOAD_T = 0x00600000 + 8
    INFO_SPEED_DOWNLOAD_T = 0x00600000 + 9
    INFO_SPEED_UPLOAD_T = 0x00600000 + 10
    INFO_FILETIME_T = 0x00600000 + 14
    INFO_CONTENT_LENGTH_DOWNLOAD_T = 0x00600000 + 15
    INFO_CONTENT_LENGTH_UPLOAD_T = 0x00600000 + 16
    INFO_TOTAL_TIME_T = 0x00600000 + 50
    INFO_NAMELOOKUP_TIME_T = 0x00600000 + 51
    INFO_CONNECT_TIME_T = 0x00600000 + 52
    INFO_PRETRANSFER_TIME_T = 0x00600000 + 53
    INFO_STARTTRANSFER_TIME_T = 0x00600000 + 54
    INFO_REDIRECT_TIME_T = 0x00600000 + 55
    INFO_APPCONNECT_TIME_T = 0x00600000 + 56
    INFO_RETRY_AFTER = 0x00600000 + 57
    INFO_XFER_ID = 0x00600000 + 63
    INFO_CONN_ID = 0x00600000 + 64
    INFO_QUEUE_TIME_T = 0x00600000 + 65
    INFO_POSTTRANSFER_TIME_T = 0x00600000 + 67
    INFO_EARLYDATA_SENT_T = 0x00600000 + 68
    INFO_SIZE_DELIVERED = 0x00600000 + 71
  PINFO* = ptr INFO
  CURLINFO* = INFO

  Closepolicy* {.size: sizeof(cint).} = enum
    CLOSEPOLICY_NONE = 0
    CLOSEPOLICY_OLDEST = 1
    CLOSEPOLICY_LEAST_RECENTLY_USED = 2
    CLOSEPOLICY_LEAST_TRAFFIC = 3
    CLOSEPOLICY_SLOWEST = 4
    CLOSEPOLICY_CALLBACK = 5
    CLOSEPOLICY_LAST = 6
  Pclosepolicy* = ptr Closepolicy

  Lock_data* {.size: sizeof(cint).} = enum
    LOCK_DATA_NONE = 0
    LOCK_DATA_SHARE = 1
    LOCK_DATA_COOKIE = 2
    LOCK_DATA_DNS = 3
    LOCK_DATA_SSL_SESSION = 4
    LOCK_DATA_CONNECT = 5
    LOCK_DATA_PSL = 6
    LOCK_DATA_HSTS = 7
    LOCK_DATA_LAST = 8
  Plock_data* = ptr Lock_data

  Lock_access* {.size: sizeof(cint).} = enum
    LOCK_ACCESS_NONE = 0
    LOCK_ACCESS_SHARED = 1
    LOCK_ACCESS_SINGLE = 2
    LOCK_ACCESS_LAST = 3
  Plock_access* = ptr Lock_access

  SHcode* {.size: sizeof(cint).} = enum
    SHE_OK = 0
    SHE_BAD_OPTION = 1
    SHE_IN_USE = 2
    SHE_INVALID = 3
    SHE_NOMEM = 4
    SHE_NOT_BUILT_IN = 5
    SHE_LAST = 6
  PSHcode* = ptr SHcode

  SHoption* {.size: sizeof(cint).} = enum
    SHOPT_NONE = 0
    SHOPT_SHARE = 1
    SHOPT_UNSHARE = 2
    SHOPT_LOCKFUNC = 3
    SHOPT_UNLOCKFUNC = 4
    SHOPT_USERDATA = 5
    SHOPT_LAST = 6
  PSHoption* = ptr SHoption

  Version* {.size: sizeof(cint).} = enum
    VERSION_FIRST = 0
    VERSION_SECOND = 1
    VERSION_THIRD = 2
    VERSION_FOURTH = 3
    VERSION_FIFTH = 4
    VERSION_SIXTH = 5
    VERSION_SEVENTH = 6
    VERSION_EIGHTH = 7
    VERSION_NINTH = 8
    VERSION_TENTH = 9
    VERSION_ELEVENTH = 10
    VERSION_TWELFTH = 11
    VERSION_LAST = 12
  Pversion* = ptr Version

  Version_info_data* {.pure, final.} = object
    age*: Version
    version*: cstring
    version_num*: cuint
    host*: cstring
    features*: cint
    ssl_version*: cstring
    ssl_version_num*: clong
    libz_version*: cstring
    protocols*: cstringArray
    ares*: cstring
    ares_num*: cint
    libidn*: cstring
    iconv_ver_num*: cint
    libssh_version*: cstring
    brotli_ver_num*: cuint
    brotli_version*: cstring
    nghttp2_ver_num*: cuint
    nghttp2_version*: cstring
    quic_version*: cstring
    cainfo*: cstring
    capath*: cstring
    zstd_ver_num*: cuint
    zstd_version*: cstring
    hyper_version*: cstring
    gsasl_version*: cstring
    feature_names*: cstringArray
    rtmp_version*: cstring
  Pversion_info_data* = ptr Version_info_data

  Mcode* {.size: sizeof(cint).} = enum
    M_CALL_MULTI_PERFORM = -1
    M_OK = 0
    M_BAD_HANDLE = 1
    M_BAD_EASY_HANDLE = 2
    M_OUT_OF_MEMORY = 3
    M_INTERNAL_ERROR = 4
    M_BAD_SOCKET = 5
    M_UNKNOWN_OPTION = 6
    M_ADDED_ALREADY = 7
    M_RECURSIVE_API_CALL = 8
    M_WAKEUP_FAILURE = 9
    M_BAD_FUNCTION_ARGUMENT = 10
    M_ABORTED_BY_CALLBACK = 11
    M_UNRECOVERABLE_POLL = 12
    M_LAST = 13
  PMcode* = ptr Mcode

  MSGEnum* {.size: sizeof(cint).} = enum
    MSG_NONE = 0
    MSG_DONE = 1
    MSG_LAST = 2

  Msg* {.pure, final.} = object
    msg*: MSGEnum
    easy_handle*: PCurl
    whatever*: pointer
  PMsg* = ptr Msg

  CurlWaitFd* {.pure, final.} = object
    fd*: CurlSocketT
    events*: cshort
    revents*: cshort
  PCurlWaitFd* = ptr CurlWaitFd

  Moption* {.size: sizeof(cint).} = enum
    MOPT_PIPELINING = 0 + 3
    MOPT_MAXCONNECTS = 0 + 6
    MOPT_MAX_HOST_CONNECTIONS = 0 + 7
    MOPT_MAX_PIPELINE_LENGTH = 0 + 8
    MOPT_MAX_TOTAL_CONNECTIONS = 0 + 13
    MOPT_MAX_CONCURRENT_STREAMS = 0 + 16
    MOPT_NETWORK_CHANGED = 0 + 17
    MOPT_RESOLVE_THREADS_MAX = 0 + 20
    MOPT_QUICK_EXIT = 0 + 21
    MOPT_SOCKETDATA = 10000 + 2
    MOPT_TIMERDATA = 10000 + 5
    MOPT_PIPELINING_SITE_BL = 10000 + 11
    MOPT_PIPELINING_SERVER_BL = 10000 + 12
    MOPT_PUSHDATA = 10000 + 15
    MOPT_NOTIFYDATA = 10000 + 19
    MOPT_LASTENTRY = 10000 + 22
    MOPT_SOCKETFUNCTION = 20000 + 1
    MOPT_TIMERFUNCTION = 20000 + 4
    MOPT_PUSHFUNCTION = 20000 + 14
    MOPT_NOTIFYFUNCTION = 20000 + 18
    MOPT_CONTENT_LENGTH_PENALTY_SIZE = 30000 + 9
    MOPT_CHUNK_LENGTH_PENALTY_SIZE = 30000 + 10
  PMoption* = ptr Moption

  MinfoOfft* {.size: sizeof(cint).} = enum
    MINFO_NONE = 0
    MINFO_XFERS_CURRENT = 1
    MINFO_XFERS_RUNNING = 2
    MINFO_XFERS_PENDING = 3
    MINFO_XFERS_DONE = 4
    MINFO_XFERS_ADDED = 5
    MINFO_LASTENTRY = 6

  # URL API types
  CURLUcode* {.size: sizeof(cint).} = enum
    UE_OK = 0
    UE_BAD_HANDLE = 1
    UE_BAD_PARTPOINTER = 2
    UE_MALFORMED_INPUT = 3
    UE_BAD_PORT_NUMBER = 4
    UE_UNSUPPORTED_SCHEME = 5
    UE_URLDECODE = 6
    UE_OUT_OF_MEMORY = 7
    UE_USER_NOT_ALLOWED = 8
    UE_UNKNOWN_PART = 9
    UE_NO_SCHEME = 10
    UE_NO_USER = 11
    UE_NO_PASSWORD = 12
    UE_NO_OPTIONS = 13
    UE_NO_HOST = 14
    UE_NO_PORT = 15
    UE_NO_QUERY = 16
    UE_NO_FRAGMENT = 17
    UE_NO_ZONEID = 18
    UE_BAD_FILE_URL = 19
    UE_BAD_FRAGMENT = 20
    UE_BAD_HOSTNAME = 21
    UE_BAD_IPV6 = 22
    UE_BAD_LOGIN = 23
    UE_BAD_PASSWORD = 24
    UE_BAD_PATH = 25
    UE_BAD_QUERY = 26
    UE_BAD_SCHEME = 27
    UE_BAD_SLASHES = 28
    UE_BAD_USER = 29
    UE_LACKS_IDN = 30
    UE_TOO_LARGE = 31
    UE_BACKSLASH = 32
    UE_LAST = 33

  CURLUPart* {.size: sizeof(cint).} = enum
    UPART_URL = 0
    UPART_SCHEME = 1
    UPART_USER = 2
    UPART_PASSWORD = 3
    UPART_OPTIONS = 4
    UPART_HOST = 5
    UPART_PORT = 6
    UPART_PATH = 7
    UPART_QUERY = 8
    UPART_FRAGMENT = 9
    UPART_ZONEID = 10

  # Header API types
  CurlHeader* {.pure, final.} = object
    name*: cstring
    value*: cstring
    amount*: csize_t
    index*: csize_t
    origin*: cuint
    anchor*: pointer
  PCurlHeader* = ptr CurlHeader

  CURLHcode* {.size: sizeof(cint).} = enum
    HE_OK = 0
    HE_BADINDEX = 1
    HE_MISSING = 2
    HE_NOHEADERS = 3
    HE_NOREQUEST = 4
    HE_OUT_OF_MEMORY = 5
    HE_BAD_ARGUMENT = 6
    HE_NOT_BUILT_IN = 7

  # Options Introspection API types
  CurlEasyType* {.size: sizeof(cint).} = enum
    OT_LONG = 0
    OT_VALUES = 1
    OT_OFF_T = 2
    OT_OBJECT = 3
    OT_STRING = 4
    OT_SLIST = 5
    OT_CBPTR = 6
    OT_BLOB = 7
    OT_FUNCTION = 8

  CurlEasyOption* {.pure, final.} = object
    name*: cstring
    id*: Option
    `type`*: CurlEasyType
    flags*: cuint
  PCurlEasyOption* = ptr CurlEasyOption

  # WebSockets API types
  CurlWsFrame* {.pure, final.} = object
    age*: cint
    flags*: cint
    offset*: CurlOffT
    bytesleft*: CurlOffT
    len*: csize_t
  PCurlWsFrame* = ptr CurlWsFrame

  # Callback procedural types
  Progress_callback* = proc (clientp: pointer, dltotal: float64, dlnow: float64,
                             ultotal: float64, ulnow: float64): int32 {.cdecl.}
  Xferinfo_callback* = proc (clientp: pointer, dltotal: CurlOffT, dlnow: CurlOffT,
                             ultotal: CurlOffT, ulnow: CurlOffT): int32 {.cdecl.}
  Write_callback* = proc (buffer: cstring, size: int, nitems: int,
                          outstream: pointer): int {.cdecl.}
  Read_callback* = proc (buffer: cstring, size: int, nitems: int,
                         instream: pointer): int {.cdecl.}
  Seek_callback* = proc (instream: pointer, offset: CurlOffT, origin: int32): int32 {.cdecl.}
  Passwd_callback* = proc (clientp: pointer, prompt: cstring, buffer: cstring,
                           buflen: int32): int32 {.cdecl.}
  Ioctl_callback* = proc (handle: PCurl, cmd: int32, clientp: pointer): Ioerr {.cdecl.}
  Malloc_callback* = proc (size: int): pointer {.cdecl.}
  Pmalloc_callback* = ptr Malloc_callback
  Free_callback* = proc (p: pointer) {.cdecl.}
  Realloc_callback* = proc (p: pointer, size: int): pointer {.cdecl.}
  Prealloc_callback* = ptr Realloc_callback
  Strdup_callback* = proc (str: cstring): cstring {.cdecl.}
  Pstrdup_callback* = ptr Strdup_callback
  Calloc_callback* = proc (nmemb: int, size: int): pointer {.cdecl.}
  Pcalloc_callback* = ptr Calloc_callback
  Debug_callback* = proc (handle: PCurl, theType: Infotype, data: cstring,
                          size: int, userptr: pointer): int32 {.cdecl.}
  Conv_callback* = proc (buffer: cstring, len: int): Code {.cdecl.}
  Ssl_ctx_callback* = proc (curl: PCurl, ssl_ctx, userptr: pointer): Code {.cdecl.}
  Formget_callback* = proc (arg: pointer, buf: cstring, length: int): int {.cdecl.}
  Lock_function* = proc (handle: PCurl, data: Lock_data, locktype: Lock_access,
                         userptr: pointer) {.cdecl.}
  Unlock_function* = proc (handle: PCurl, data: Lock_data, userptr: pointer) {.cdecl.}
  Socket_callback* = proc (easy: PCurl, s: Socket, what: int32,
                           userp, socketp: pointer): int32 {.cdecl.}
  Multi_timer_callback* = proc (multi: PM, timeout_ms: clong, userp: pointer): int32 {.cdecl.}

const
  # Backwards compatibility option aliases
  OPT_FILE* = OPT_WRITEDATA
  OPT_INFILE* = OPT_READDATA
  OPT_WRITEHEADER* = OPT_HEADERDATA
  OPT_PROGRESSDATA* = OPT_XFERINFODATA
  OPT_SSLKEYPASSWD* = OPT_KEYPASSWD
  OPT_SSLCERTPASSWD* = OPT_KEYPASSWD
  OPT_FTPAPPEND* = OPT_APPEND
  OPT_FTPLISTONLY* = OPT_DIRLISTONLY
  OPT_FTP_SSL* = OPT_USE_SSL
  OPT_ENCODING* = OPT_ACCEPT_ENCODING
  OPT_KRB4LEVEL* = OPT_KRBLEVEL
  OPT_FTP_RESPONSE_TIMEOUT* = OPT_SERVER_RESPONSE_TIMEOUT
  OPT_POST301* = OPT_POSTREDIR
  OPT_RTSPHEADER* = OPT_HTTPHEADER

  # Backwards compatibility error code aliases
  E_URL_MALFORMAT_USER* = E_NOT_BUILT_IN
  E_FTP_WEIRD_SERVER_REPLY* = E_WEIRD_SERVER_REPLY
  E_FTP_ACCESS_DENIED* = E_REMOTE_ACCESS_DENIED
  E_FTP_USER_PASSWORD_INCORRECT* = E_FTP_ACCEPT_FAILED
  E_FTP_WEIRD_USER_REPLY* = E_FTP_ACCEPT_TIMEOUT
  E_FTP_CANT_RECONNECT* = E_HTTP2
  E_FTP_COULDNT_SET_BINARY* = E_FTP_COULDNT_SET_TYPE
  E_FTP_WRITE_ERROR* = E_OBSOLETE20
  E_FTP_QUOTE_ERROR* = E_QUOTE_ERROR
  E_MALFORMAT_USER* = E_OBSOLETE24
  E_FTP_COULDNT_STOR_FILE* = E_UPLOAD_FAILED
  E_OPERATION_TIMEOUTED* = E_OPERATION_TIMEDOUT
  E_FTP_COULDNT_SET_ASCII* = E_OBSOLETE29
  E_FTP_COULDNT_GET_SIZE* = E_OBSOLETE32
  E_HTTP_RANGE_ERROR* = E_RANGE_ERROR
  E_HTTP_POST_ERROR* = E_OBSOLETE34
  E_LIBRARY_NOT_FOUND* = E_OBSOLETE40
  E_FUNCTION_NOT_FOUND* = E_OBSOLETE41
  E_BAD_CALLING_ORDER* = E_OBSOLETE44
  E_BAD_PASSWORD_ENTERED* = E_OBSOLETE46
  E_UNKNOWN_TELNET_OPTION* = E_UNKNOWN_OPTION
  E_TELNET_OPTION_SYNTAX* = E_SETOPT_OPTION_SYNTAX
  E_OBSOLETE* = E_OBSOLETE50
  E_SSL_PEER_CERTIFICATE* = E_PEER_FAILED_VERIFICATION
  E_SHARE_IN_USE* = E_OBSOLETE57
  E_SSL_CACERT* = E_PEER_FAILED_VERIFICATION
  E_LDAP_INVALID_URL* = E_OBSOLETE62
  E_FTP_SSL_FAILED* = E_USE_SSL_FAILED
  E_TFTP_DISKFULL* = E_REMOTE_DISK_FULL
  E_TFTP_EXISTS* = E_REMOTE_FILE_EXISTS
  E_CONV_FAILED* = E_OBSOLETE75
  E_CONV_REQD* = E_OBSOLETE76
  E_ALREADY_COMPLETE* = 99999
  E_FTP_BAD_DOWNLOAD_RESUME* = E_BAD_DOWNLOAD_RESUME
  E_FTP_PARTIAL_FILE* = E_PARTIAL_FILE
  E_HTTP_NOT_FOUND* = E_HTTP_RETURNED_ERROR
  E_HTTP_PORT_FAILED* = E_INTERFACE_FAILED

  # Follow location flags
  CURLFOLLOW_ALL* = 1
  CURLFOLLOW_OBEYCODE* = 2
  CURLFOLLOW_FIRSTONLY* = 3
  CURLFOLLOW_SAFE* = 4  ## curl-impersonate: Follow redirects, but reject private/internal IPs (SSRF protection)

  # HTTP/3 SSL permute extensions values (for OPT_HTTP3_SSL_PERMUTE_EXTENSIONS)
  CURL_HTTP3_SSL_PERMUTE_FALLBACK* = -1
  CURL_HTTP3_SSL_PERMUTE_DISABLE* = 0
  CURL_HTTP3_SSL_PERMUTE_ENABLE* = 1

  # Blob flags
  CURL_BLOB_NOCOPY* = 0'u32
  CURL_BLOB_COPY* = 1'u32

  # Auth bitmasks
  AUTH_NONE* = 0
  AUTH_BASIC* = 1 shl 0
  AUTH_DIGEST* = 1 shl 1
  AUTH_NEGOTIATE* = 1 shl 2
  AUTH_GSSNEGOTIATE* = AUTH_NEGOTIATE
  AUTH_GSSAPI* = AUTH_NEGOTIATE
  AUTH_NTLM* = 1 shl 3
  AUTH_DIGEST_IE* = 1 shl 4
  AUTH_NTLM_WB* = 1 shl 5
  AUTH_BEARER* = 1 shl 6
  AUTH_AWS_SIGV4* = 1 shl 7
  AUTH_HTTPSIG* = 1 shl 8
  AUTH_ANY* = not (AUTH_DIGEST_IE or AUTH_HTTPSIG)
  AUTH_ANYSAFE* = not (AUTH_BASIC or AUTH_DIGEST_IE or AUTH_HTTPSIG)

  # SSL options bitmasks (for OPT_SSL_OPTIONS)
  CURLSSLOPT_ALLOW_BEAST* = 1 shl 0
  CURLSSLOPT_NO_REVOKE* = 1 shl 1
  CURLSSLOPT_NO_PARTIALCHAIN* = 1 shl 2
  CURLSSLOPT_REVOKE_BEST_EFFORT* = 1 shl 3
  CURLSSLOPT_NATIVE_CA* = 1 shl 4
  CURLSSLOPT_AUTO_CLIENT_CERT* = 1 shl 5
  CURLSSLOPT_EARLYDATA* = 1 shl 6

  # SSL max version bitmasks
  CURL_SSLVERSION_MAX_NONE* = 0
  CURL_SSLVERSION_MAX_DEFAULT* = ord(SSLVERSION_TLSv1) shl 16
  CURL_SSLVERSION_MAX_TLSv1_0* = ord(SSLVERSION_TLSv1_0) shl 16
  CURL_SSLVERSION_MAX_TLSv1_1* = ord(SSLVERSION_TLSv1_1) shl 16
  CURL_SSLVERSION_MAX_TLSv1_2* = ord(SSLVERSION_TLSv1_2) shl 16
  CURL_SSLVERSION_MAX_TLSv1_3* = ord(SSLVERSION_TLSv1_3) shl 16

  # Header options
  CURLHEADER_UNIFIED* = 0
  CURLHEADER_SEPARATE* = 1 shl 0

  # Alt-Svc flags
  CURLALTSVC_READONLYFILE* = 1 shl 2
  CURLALTSVC_H1* = 1 shl 3
  CURLALTSVC_H2* = 1 shl 4
  CURLALTSVC_H3* = 1 shl 5

  # HSTS flags
  CURLHSTS_ENABLE* = 1 shl 0
  CURLHSTS_READONLYFILE* = 1 shl 1

  # Post redir flags
  CURL_REDIR_GET_ALL* = 0
  CURL_REDIR_POST_301* = 1
  CURL_REDIR_POST_302* = 2
  CURL_REDIR_POST_303* = 4
  CURL_REDIR_POST_ALL* = CURL_REDIR_POST_301 or CURL_REDIR_POST_302 or CURL_REDIR_POST_303

  # Global init flags
  GLOBAL_NOTHING* = 0
  GLOBAL_SSL* = 1 shl 0
  GLOBAL_WIN32* = 1 shl 1
  GLOBAL_WINSOCK* = GLOBAL_WIN32
  GLOBAL_ALL* = GLOBAL_SSL or GLOBAL_WIN32
  GLOBAL_DEFAULT* = GLOBAL_ALL
  GLOBAL_ACK_EINTR* = 1 shl 2

  # Info masks
  INFO_STRING* = 0x00100000
  INFO_LONG* = 0x00200000
  INFO_DOUBLE* = 0x00300000
  INFO_SLIST* = 0x00400000
  INFO_PTR* = 0x00400000
  INFO_SOCKET* = 0x00500000
  INFO_OFF_T* = 0x00600000
  INFO_MASK* = 0x000FFFFF
  INFO_TYPEMASK* = 0x00F00000
  INFO_HTTP_CODE* = INFO_RESPONSE_CODE

  # IP resolve constants
  IPRESOLVE_WHATEVER* = 0
  IPRESOLVE_V4* = 1
  IPRESOLVE_V6* = 2

  # Option type offsets
  OPTTYPE_LONG* = 0
  OPTTYPE_OBJECTPOINT* = 10000
  OPTTYPE_STRINGPOINT* = 10000
  OPTTYPE_SLISTPOINT* = 10000
  OPTTYPE_CBPOINT* = 10000
  OPTTYPE_VALUES* = 0
  OPTTYPE_FUNCTIONPOINT* = 20000
  OPTTYPE_OFF_T* = 30000
  OPTTYPE_BLOB* = 40000
  FUNCTIONPOINT* = OPTTYPE_FUNCTIONPOINT

  # Poll / Socket constants
  POLL_NONE* = 0
  POLL_IN* = 1
  POLL_OUT* = 2
  POLL_INOUT* = 3
  POLL_REMOVE* = 4
  SOCKET_BAD* = -1
  SOCKET_TIMEOUT* = SOCKET_BAD
  M_CALL_MULTI_SOCKET* = M_CALL_MULTI_PERFORM

  # Multi wait poll flags
  CURL_WAIT_POLLIN* = 0x0001'i16
  CURL_WAIT_POLLPRI* = 0x0002'i16
  CURL_WAIT_POLLOUT* = 0x0004'i16

  # Multi pipe flags
  CURLPIPE_NOTHING* = 0
  CURLPIPE_HTTP1* = 1
  CURLPIPE_MULTIPLEX* = 2

  # Pause flags
  CURLPAUSE_RECV* = 1 shl 0
  CURLPAUSE_RECV_CONT* = 0
  CURLPAUSE_SEND* = 1 shl 2
  CURLPAUSE_SEND_CONT* = 0
  CURLPAUSE_ALL* = CURLPAUSE_RECV or CURLPAUSE_SEND
  CURLPAUSE_CONT* = CURLPAUSE_RECV_CONT or CURLPAUSE_SEND_CONT

  # URL API flags
  CURLU_DEFAULT_PORT* = (1 shl 0).cuint
  CURLU_NO_DEFAULT_PORT* = (1 shl 1).cuint
  CURLU_DEFAULT_SCHEME* = (1 shl 2).cuint
  CURLU_NON_SUPPORT_SCHEME* = (1 shl 3).cuint
  CURLU_PATH_AS_IS* = (1 shl 4).cuint
  CURLU_DISALLOW_USER* = (1 shl 5).cuint
  CURLU_URLDECODE* = (1 shl 6).cuint
  CURLU_URLENCODE* = (1 shl 7).cuint
  CURLU_APPENDQUERY* = (1 shl 8).cuint
  CURLU_GUESS_SCHEME* = (1 shl 9).cuint
  CURLU_NO_AUTHORITY* = (1 shl 10).cuint
  CURLU_ALLOW_SPACE* = (1 shl 11).cuint
  CURLU_PUNYCODE* = (1 shl 12).cuint
  CURLU_PUNY2IDN* = (1 shl 13).cuint
  CURLU_GET_EMPTY* = (1 shl 14).cuint
  CURLU_NO_GUESS_SCHEME* = (1 shl 15).cuint

  # Header API origin flags
  CURLH_HEADER* = (1 shl 0).cuint
  CURLH_TRAILER* = (1 shl 1).cuint
  CURLH_CONNECT* = (1 shl 2).cuint
  CURLH_1XX* = (1 shl 3).cuint
  CURLH_PSEUDO* = (1 shl 4).cuint

  # WebSocket frame & option flags
  CURLWS_TEXT* = 1 shl 0
  CURLWS_BINARY* = 1 shl 1
  CURLWS_CONT* = 1 shl 2
  CURLWS_CLOSE* = 1 shl 3
  CURLWS_PING* = 1 shl 4
  CURLWS_OFFSET* = 1 shl 5
  CURLWS_PONG* = 1 shl 6

  CURLWS_RAW_MODE* = 1 shl 0
  CURLWS_NOAUTOPONG* = 1 shl 1
  CURLWS_PERMESSAGE_DEFLATE* = 1 shl 2  ## curl-impersonate WebSocket permessage-deflate

  # Version feature bits
  VERSION_IPV6* = 1 shl 0
  VERSION_KERBEROS4* = 1 shl 1
  VERSION_SSL* = 1 shl 2
  VERSION_LIBZ* = 1 shl 3
  VERSION_NTLM* = 1 shl 4
  VERSION_GSSNEGOTIATE* = 1 shl 5
  VERSION_DEBUG* = 1 shl 6
  VERSION_ASYNCHDNS* = 1 shl 7
  VERSION_SPNEGO* = 1 shl 8
  VERSION_LARGEFILE* = 1 shl 9
  VERSION_IDN* = 1 shl 10
  VERSION_SSPI* = 1 shl 11
  VERSION_CONV* = 1 shl 12
  VERSION_CURLDEBUG* = 1 shl 13
  VERSION_TLSAUTH_SRP* = 1 shl 14
  VERSION_NTLM_WB* = 1 shl 15
  VERSION_HTTP2* = 1 shl 16
  VERSION_GSSAPI* = 1 shl 17
  VERSION_KERBEROS5* = 1 shl 18
  VERSION_UNIX_SOCKETS* = 1 shl 19
  VERSION_PSL* = 1 shl 20
  VERSION_HTTPS_PROXY* = 1 shl 21
  VERSION_MULTI_SSL* = 1 shl 22
  VERSION_BROTLI* = 1 shl 23
  VERSION_ALTSVC* = 1 shl 24
  VERSION_HTTP3* = 1 shl 25
  VERSION_ZSTD* = 1 shl 26
  VERSION_UNICODE* = 1 shl 27
  VERSION_HSTS* = 1 shl 28
  VERSION_GSASL* = 1 shl 29
  VERSION_THREADSAFE* = 1 shl 30
  VERSION_NOW* = VERSION_TWELFTH

  # Misc constants
  ERROR_SIZE* = 256
  MAX_WRITE_SIZE* = 16384
  MAX_HTTP_HEADER* = 100 * 1024
  WRITEFUNC_PAUSE* = 0x10000001
  WRITEFUNC_ERROR* = 0xFFFFFFFF'u32
  READFUNC_ABORT* = 0x10000000
  READFUNC_PAUSE* = 0x10000001
  CURL_ZERO_TERMINATED* = high(csize_t)

  HTTPPOST_FILENAME* = 1 shl 0
  HTTPPOST_READFILE* = 1 shl 1
  HTTPPOST_PTRNAME* = 1 shl 2
  HTTPPOST_PTRCONTENTS* = 1 shl 3
  HTTPPOST_BUFFER* = 1 shl 4
  HTTPPOST_PTRBUFFER* = 1 shl 5
  HTTPPOST_CALLBACK* = 1 shl 6
  HTTPPOST_LARGE* = 1 shl 7

  LIBCURL_VERSION* = "8.23.0-IMPERSONATE"
  LIBCURL_VERSION_MAJOR* = 8
  LIBCURL_VERSION_MINOR* = 23
  LIBCURL_VERSION_PATCH* = 0
  LIBCURL_VERSION_NUM* = 0x081700

{.push cdecl, dynlib: libname.}

# Core & Global functions
proc strequal*(s1, s2: cstring): int32 {.importc: "curl_strequal".}
proc strnequal*(s1, s2: cstring, n: csize_t): int32 {.importc: "curl_strnequal".}
proc formadd*(httppost, last_post: PPcurl_httppost): FORMcode {.varargs, importc: "curl_formadd".}
proc formget*(form: Phttppost, arg: pointer, append: Formget_callback): int32 {.importc: "curl_formget".}
proc formfree*(form: Phttppost) {.importc: "curl_formfree".}
proc getenv*(variable: cstring): cstring {.importc: "curl_getenv".}
proc version*(): cstring {.importc: "curl_version".}
proc easy_escape*(handle: PCurl, str: cstring, len: int32): cstring {.importc: "curl_easy_escape".}
proc escape*(str: cstring, len: int32): cstring {.importc: "curl_escape".}
proc easy_unescape*(handle: PCurl, str: cstring, len: int32, outlength: var int32): cstring {.importc: "curl_easy_unescape".}
proc unescape*(str: cstring, len: int32): cstring {.importc: "curl_unescape".}
proc free*(p: pointer) {.importc: "curl_free".}
proc global_init*(flags: clong): Code {.importc: "curl_global_init".}
proc global_init_mem*(flags: clong, m: Malloc_callback, f: Free_callback,
                      r: Realloc_callback, s: Strdup_callback,
                      c: Calloc_callback): Code {.importc: "curl_global_init_mem".}
proc global_cleanup*() {.importc: "curl_global_cleanup".}
proc global_trace*(config: cstring): Code {.importc: "curl_global_trace".}
proc global_sslset*(id: CurlSslBackendId, name: cstring,
                    avail: ptr ptr UncheckedArray[PCurlSslBackend]): CurlSslSet {.importc: "curl_global_sslset".}
proc slist_append*(slist: Pslist, p: cstring): Pslist {.importc: "curl_slist_append".}
proc slist_free_all*(para1: Pslist) {.importc: "curl_slist_free_all".}
proc getdate*(p: cstring, unused: ptr Time): Time {.importc: "curl_getdate".}
proc version_info*(para1: Version = VERSION_NOW): Pversion_info_data {.importc: "curl_version_info".}

# Share API
proc share_init*(): PSH {.importc: "curl_share_init".}
proc share_setopt*(para1: PSH, option: SHoption): SHcode {.varargs, importc: "curl_share_setopt".}
proc share_cleanup*(para1: PSH): SHcode {.importc: "curl_share_cleanup".}
proc share_strerror*(para1: SHcode): cstring {.importc: "curl_share_strerror".}

# Easy API
proc easy_strerror*(para1: Code): cstring {.importc: "curl_easy_strerror".}
proc easy_init*(): PCurl {.importc: "curl_easy_init".}
proc easy_setopt*(curl: PCurl, option: Option): Code {.varargs, importc: "curl_easy_setopt".}
proc easy_perform*(curl: PCurl): Code {.importc: "curl_easy_perform".}
proc easy_cleanup*(curl: PCurl) {.importc: "curl_easy_cleanup".}
proc easy_getinfo*(curl: PCurl, info: INFO): Code {.varargs, importc: "curl_easy_getinfo".}
proc easy_duphandle*(curl: PCurl): PCurl {.importc: "curl_easy_duphandle".}
proc easy_reset*(curl: PCurl) {.importc: "curl_easy_reset".}
proc easy_pause*(curl: PCurl, bitmask: cint): Code {.importc: "curl_easy_pause".}
proc easy_recv*(curl: PCurl, buffer: pointer, buflen: csize_t, n: var csize_t): Code {.importc: "curl_easy_recv".}
proc easy_send*(curl: PCurl, buffer: pointer, buflen: csize_t, n: var csize_t): Code {.importc: "curl_easy_send".}
proc easy_upkeep*(curl: PCurl): Code {.importc: "curl_easy_upkeep".}

# curl-impersonate Easy Extension!
proc easy_impersonate*(curl: PCurl, target: cstring, default_headers: cint = 1): Code {.importc: "curl_easy_impersonate".}

# Mime API
proc mime_init*(easy: PCurl): PCurlMime {.importc: "curl_mime_init".}
proc mime_free*(mime: PCurlMime) {.importc: "curl_mime_free".}
proc mime_addpart*(mime: PCurlMime): PCurlMimePart {.importc: "curl_mime_addpart".}
proc mime_name*(part: PCurlMimePart, name: cstring): Code {.importc: "curl_mime_name".}
proc mime_filename*(part: PCurlMimePart, filename: cstring): Code {.importc: "curl_mime_filename".}
proc mime_type*(part: PCurlMimePart, mimetype: cstring): Code {.importc: "curl_mime_type".}
proc mime_encoder*(part: PCurlMimePart, encoding: cstring): Code {.importc: "curl_mime_encoder".}
proc mime_data*(part: PCurlMimePart, data: pointer, datasize: csize_t): Code {.importc: "curl_mime_data".}
proc mime_filedata*(part: PCurlMimePart, filename: cstring): Code {.importc: "curl_mime_filedata".}
proc mime_data_cb*(part: PCurlMimePart, datasize: CurlOffT, readfunc: Read_callback,
                   seekfunc: Seek_callback, freefunc: Free_callback, arg: pointer): Code {.importc: "curl_mime_data_cb".}
proc mime_subparts*(part: PCurlMimePart, subparts: PCurlMime): Code {.importc: "curl_mime_subparts".}
proc mime_headers*(part: PCurlMimePart, headers: Pslist, take_ownership: cint): Code {.importc: "curl_mime_headers".}

# Multi API
proc multi_init*(): PM {.importc: "curl_multi_init".}
proc multi_add_handle*(multi_handle: PM, handle: PCurl): Mcode {.importc: "curl_multi_add_handle".}
proc multi_remove_handle*(multi_handle: PM, handle: PCurl): Mcode {.importc: "curl_multi_remove_handle".}
proc multi_fdset*(multi_handle: PM, read_fd_set: Pfd_set, write_fd_set: Pfd_set,
                  exc_fd_set: Pfd_set, max_fd: var int32): Mcode {.importc: "curl_multi_fdset".}
proc multi_wait*(multi_handle: PM, extra_fds: ptr CurlWaitFd, extra_nfds: cuint,
                 timeout_ms: cint, ret: var cint): Mcode {.importc: "curl_multi_wait".}
proc multi_poll*(multi_handle: PM, extra_fds: ptr CurlWaitFd, extra_nfds: cuint,
                 timeout_ms: cint, ret: var cint): Mcode {.importc: "curl_multi_poll".}
proc multi_wakeup*(multi_handle: PM): Mcode {.importc: "curl_multi_wakeup".}
proc multi_perform*(multi_handle: PM, running_handles: var int32): Mcode {.importc: "curl_multi_perform".}
proc multi_cleanup*(multi_handle: PM): Mcode {.importc: "curl_multi_cleanup".}
proc multi_info_read*(multi_handle: PM, msgs_in_queue: var int32): PMsg {.importc: "curl_multi_info_read".}
proc multi_strerror*(para1: Mcode): cstring {.importc: "curl_multi_strerror".}
proc multi_socket*(multi_handle: PM, s: Socket, running_handles: var int32): Mcode {.importc: "curl_multi_socket".}
proc multi_socket_action*(multi_handle: PM, s: Socket, ev_bitmask: cint,
                          running_handles: var int32): Mcode {.importc: "curl_multi_socket_action".}
proc multi_socket_all*(multi_handle: PM, running_handles: var int32): Mcode {.importc: "curl_multi_socket_all".}
proc multi_timeout*(multi_handle: PM, milliseconds: var clong): Mcode {.importc: "curl_multi_timeout".}
proc multi_setopt*(multi_handle: PM, option: Moption): Mcode {.varargs, importc: "curl_multi_setopt".}
proc multi_assign*(multi_handle: PM, sockfd: Socket, sockp: pointer): Mcode {.importc: "curl_multi_assign".}
proc multi_get_handles*(multi_handle: PM): ptr UncheckedArray[PCurl] {.importc: "curl_multi_get_handles".}
proc multi_get_offt*(multi_handle: PM, info: MinfoOfft, pvalue: var CurlOffT): Mcode {.importc: "curl_multi_get_offt".}
proc multi_waitfds*(multi_handle: PM, ufds: ptr CurlWaitFd, size: cuint, fd_count: var cuint): Mcode {.importc: "curl_multi_waitfds".}
proc multi_notify_enable*(multi_handle: PM, notification: cuint): Mcode {.importc: "curl_multi_notify_enable".}
proc multi_notify_disable*(multi_handle: PM, notification: cuint): Mcode {.importc: "curl_multi_notify_disable".}

# URL API
proc url_init*(): PCurlU {.importc: "curl_url".}
proc url_cleanup*(u: PCurlU) {.importc: "curl_url_cleanup".}
proc url_dup*(u: PCurlU): PCurlU {.importc: "curl_url_dup".}
proc url_get*(u: PCurlU, what: CURLUPart, part: var cstring, flags: cuint = 0): CURLUcode {.importc: "curl_url_get".}
proc url_set*(u: PCurlU, what: CURLUPart, part: cstring, flags: cuint = 0): CURLUcode {.importc: "curl_url_set".}
proc url_strerror*(error: CURLUcode): cstring {.importc: "curl_url_strerror".}

# Header Inspection API
proc easy_header*(curl: PCurl, name: cstring, index: csize_t, origin: cuint,
                  request: cint, hout: var PCurlHeader): CURLHcode {.importc: "curl_easy_header".}
proc easy_nextheader*(curl: PCurl, origin: cuint, request: cint,
                      prev: PCurlHeader): PCurlHeader {.importc: "curl_easy_nextheader".}

# Options Introspection API
proc easy_option_by_name*(name: cstring): PCurlEasyOption {.importc: "curl_easy_option_by_name".}
proc easy_option_by_id*(id: Option): PCurlEasyOption {.importc: "curl_easy_option_by_id".}
proc easy_option_next*(prev: PCurlEasyOption): PCurlEasyOption {.importc: "curl_easy_option_next".}

# WebSockets API
proc ws_recv*(curl: PCurl, buffer: pointer, buflen: csize_t, recv: var csize_t,
              metap: var PCurlWsFrame): Code {.importc: "curl_ws_recv".}
proc ws_send*(curl: PCurl, buffer: pointer, buflen: csize_t, sent: var csize_t,
              fragsize: CurlOffT, flags: cuint): Code {.importc: "curl_ws_send".}
proc ws_start_frame*(curl: PCurl, flags: cuint, frame_len: CurlOffT): Code {.importc: "curl_ws_start_frame".}
proc ws_meta*(curl: PCurl): PCurlWsFrame {.importc: "curl_ws_meta".}

{.pop.}

# C-style curl_* aliases for convenience
template curl_easy_init*(): PCurl = easy_init()
template curl_easy_setopt*(curl: PCurl, option: Option, arg: untyped): Code = easy_setopt(curl, option, arg)
template curl_easy_perform*(curl: PCurl): Code = easy_perform(curl)
template curl_easy_cleanup*(curl: PCurl) = easy_cleanup(curl)
template curl_easy_getinfo*(curl: PCurl, info: INFO, arg: untyped): Code = easy_getinfo(curl, info, arg)
template curl_easy_duphandle*(curl: PCurl): PCurl = easy_duphandle(curl)
template curl_easy_reset*(curl: PCurl) = easy_reset(curl)
template curl_easy_impersonate*(curl: PCurl, target: cstring, default_headers: cint = 1): Code =
  easy_impersonate(curl, target, default_headers)
template curl_easy_strerror*(code: Code): cstring = easy_strerror(code)
template curl_slist_append*(list: Pslist, data: cstring): Pslist = slist_append(list, data)
template curl_slist_free_all*(list: Pslist) = slist_free_all(list)
template curl_global_init*(flags: clong = GLOBAL_DEFAULT): Code = global_init(flags)
template curl_global_cleanup*() = global_cleanup()
template curl_version*(): cstring = version()
template curl_version_info*(age: Version = VERSION_NOW): Pversion_info_data = version_info(age)
template curl_free*(p: pointer) = free(p)

proc slistToSeq*(list: Pslist): seq[string] =
  ## Converts a `curl_slist` linked list into a Nim `seq[string]`.
  ## Does NOT free the list; call `slist_free_all(list)` when appropriate.
  var curr = list
  while curr != nil:
    if curr.data != nil:
      result.add($curr.data)
    curr = curr.next
