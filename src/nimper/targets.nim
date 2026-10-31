#
#          curl-impersonate Wrapper for Nim
#        Browser Impersonation Targets & Profiles
#

## Defines strongly-typed browser impersonation targets (`ImpersonateTarget`),
## browser families (`BrowserFamily`), target metadata, and string parsing helpers
## for `curl-impersonate` v2.3.x.

import std/strutils

type
  BrowserFamily* = enum
    bfChrome = "chrome"
    bfEdge = "edge"
    bfSafari = "safari"
    bfFirefox = "firefox"
    bfTor = "tor"
    bfOkHttp = "okhttp"

  ImpersonateTarget* = enum
    ## All supported browser impersonation targets in `libcurl-impersonate`.
    itNone = ""
    # Chrome Desktop & macOS / Windows
    itChrome99 = "chrome99"
    itChrome100 = "chrome100"
    itChrome101 = "chrome101"
    itChrome104 = "chrome104"
    itChrome107 = "chrome107"
    itChrome110 = "chrome110"
    itChrome116 = "chrome116"
    itChrome119 = "chrome119"
    itChrome120 = "chrome120"
    itChrome123 = "chrome123"
    itChrome124 = "chrome124"
    itChrome131 = "chrome131"
    itChrome133a = "chrome133a"
    itChrome136 = "chrome136"
    itChrome142 = "chrome142"
    itChrome145 = "chrome145"
    itChrome146 = "chrome146"
    itChrome150 = "chrome150"
    itChrome151 = "chrome151"
    itChrome151Macos = "chrome151_macos"
    itChrome152 = "chrome152"
    itChrome152Macos = "chrome152_macos"
    # Chrome Android
    itChrome99Android = "chrome99_android"
    itChrome131Android = "chrome131_android"
    # Edge
    itEdge99 = "edge99"
    itEdge101 = "edge101"
    # Safari macOS & iOS
    itSafari153 = "safari153"
    itSafari155 = "safari155"
    itSafari170 = "safari170"
    itSafari172Ios = "safari172_ios"
    itSafari180 = "safari180"
    itSafari180Ios = "safari180_ios"
    itSafari184 = "safari184"
    itSafari184Ios = "safari184_ios"
    itSafari260 = "safari260"
    itSafari260Ios = "safari260_ios"
    itSafari2601 = "safari2601"
    itSafari270 = "safari270"
    itSafari270Ios = "safari270_ios"
    # Firefox
    itFirefox133 = "firefox133"
    itFirefox135 = "firefox135"
    itFirefox144 = "firefox144"
    itFirefox147 = "firefox147"
    itFirefox153 = "firefox153"
    itFirefox154 = "firefox154"
    itFirefox155 = "firefox155"
    # Tor
    itTor145 = "tor145"

  TargetInfo* = object
    ## Metadata describing a browser impersonation profile.
    target*: ImpersonateTarget
    name*: string
    alias*: string
    family*: BrowserFamily
    version*: string
    os*: string
    supportsHttp3Fingerprint*: bool

const
  itChromeLatest* = itChrome152
  itChromeMacosLatest* = itChrome152Macos
  itChromeAndroidLatest* = itChrome131Android
  itEdgeLatest* = itEdge101
  itSafariLatest* = itSafari270
  itSafariIosLatest* = itSafari270Ios
  itFirefoxLatest* = itFirefox155
  itTorLatest* = itTor145
  itDefault* = itChromeLatest

  AllTargetInfos*: array[ImpersonateTarget, TargetInfo] = [
    itNone: TargetInfo(target: itNone, name: "", alias: "", family: bfChrome, version: "", os: "", supportsHttp3Fingerprint: false),
    itChrome99: TargetInfo(target: itChrome99, name: "chrome99", alias: "chrome99", family: bfChrome, version: "99", os: "Windows 10", supportsHttp3Fingerprint: false),
    itChrome100: TargetInfo(target: itChrome100, name: "chrome100", alias: "chrome100", family: bfChrome, version: "100", os: "Windows 10", supportsHttp3Fingerprint: false),
    itChrome101: TargetInfo(target: itChrome101, name: "chrome101", alias: "chrome101", family: bfChrome, version: "101", os: "Windows 10", supportsHttp3Fingerprint: false),
    itChrome104: TargetInfo(target: itChrome104, name: "chrome104", alias: "chrome104", family: bfChrome, version: "104", os: "Windows 10", supportsHttp3Fingerprint: false),
    itChrome107: TargetInfo(target: itChrome107, name: "chrome107", alias: "chrome107", family: bfChrome, version: "107", os: "Windows 10", supportsHttp3Fingerprint: false),
    itChrome110: TargetInfo(target: itChrome110, name: "chrome110", alias: "chrome110", family: bfChrome, version: "110", os: "Windows 10", supportsHttp3Fingerprint: false),
    itChrome116: TargetInfo(target: itChrome116, name: "chrome116", alias: "chrome116", family: bfChrome, version: "116", os: "Windows 10", supportsHttp3Fingerprint: false),
    itChrome119: TargetInfo(target: itChrome119, name: "chrome119", alias: "chrome119", family: bfChrome, version: "119", os: "macOS Sonoma", supportsHttp3Fingerprint: false),
    itChrome120: TargetInfo(target: itChrome120, name: "chrome120", alias: "chrome120", family: bfChrome, version: "120", os: "macOS Sonoma", supportsHttp3Fingerprint: false),
    itChrome123: TargetInfo(target: itChrome123, name: "chrome123", alias: "chrome123", family: bfChrome, version: "123", os: "macOS Sonoma", supportsHttp3Fingerprint: false),
    itChrome124: TargetInfo(target: itChrome124, name: "chrome124", alias: "chrome124", family: bfChrome, version: "124", os: "macOS Sonoma", supportsHttp3Fingerprint: false),
    itChrome131: TargetInfo(target: itChrome131, name: "chrome131", alias: "chrome131", family: bfChrome, version: "131", os: "macOS Sonoma", supportsHttp3Fingerprint: false),
    itChrome133a: TargetInfo(target: itChrome133a, name: "chrome133a", alias: "chrome133a", family: bfChrome, version: "133", os: "macOS Sequoia", supportsHttp3Fingerprint: false),
    itChrome136: TargetInfo(target: itChrome136, name: "chrome136", alias: "chrome136", family: bfChrome, version: "136", os: "macOS Sequoia", supportsHttp3Fingerprint: false),
    itChrome142: TargetInfo(target: itChrome142, name: "chrome142", alias: "chrome142", family: bfChrome, version: "142", os: "macOS Tahoe", supportsHttp3Fingerprint: false),
    itChrome145: TargetInfo(target: itChrome145, name: "chrome145", alias: "chrome145", family: bfChrome, version: "145", os: "macOS Tahoe", supportsHttp3Fingerprint: true),
    itChrome146: TargetInfo(target: itChrome146, name: "chrome146", alias: "chrome146", family: bfChrome, version: "146", os: "macOS Tahoe", supportsHttp3Fingerprint: true),
    itChrome150: TargetInfo(target: itChrome150, name: "chrome150", alias: "chrome150", family: bfChrome, version: "150", os: "macOS Tahoe", supportsHttp3Fingerprint: true),
    itChrome151: TargetInfo(target: itChrome151, name: "chrome151", alias: "chrome151", family: bfChrome, version: "151", os: "Windows 10", supportsHttp3Fingerprint: true),
    itChrome151Macos: TargetInfo(target: itChrome151Macos, name: "chrome151_macos", alias: "chrome151_macos", family: bfChrome, version: "151", os: "macOS 26.0", supportsHttp3Fingerprint: true),
    itChrome152: TargetInfo(target: itChrome152, name: "chrome152", alias: "chrome152", family: bfChrome, version: "152", os: "Windows 10", supportsHttp3Fingerprint: true),
    itChrome152Macos: TargetInfo(target: itChrome152Macos, name: "chrome152_macos", alias: "chrome152_macos", family: bfChrome, version: "152", os: "macOS 26.0", supportsHttp3Fingerprint: true),
    itChrome99Android: TargetInfo(target: itChrome99Android, name: "chrome99_android", alias: "chrome99_android", family: bfChrome, version: "99", os: "Android 12", supportsHttp3Fingerprint: false),
    itChrome131Android: TargetInfo(target: itChrome131Android, name: "chrome131_android", alias: "chrome131_android", family: bfChrome, version: "131", os: "Android 14", supportsHttp3Fingerprint: false),
    itEdge99: TargetInfo(target: itEdge99, name: "edge99", alias: "edge99", family: bfEdge, version: "99", os: "Windows 10", supportsHttp3Fingerprint: false),
    itEdge101: TargetInfo(target: itEdge101, name: "edge101", alias: "edge101", family: bfEdge, version: "101", os: "Windows 10", supportsHttp3Fingerprint: false),
    itSafari153: TargetInfo(target: itSafari153, name: "safari153", alias: "safari15_3", family: bfSafari, version: "15.3", os: "macOS Big Sur", supportsHttp3Fingerprint: false),
    itSafari155: TargetInfo(target: itSafari155, name: "safari155", alias: "safari15_5", family: bfSafari, version: "15.5", os: "macOS Monterey", supportsHttp3Fingerprint: false),
    itSafari170: TargetInfo(target: itSafari170, name: "safari170", alias: "safari17_0", family: bfSafari, version: "17.0", os: "macOS Sonoma", supportsHttp3Fingerprint: false),
    itSafari172Ios: TargetInfo(target: itSafari172Ios, name: "safari172_ios", alias: "safari17_2_ios", family: bfSafari, version: "17.2", os: "iOS 17.2", supportsHttp3Fingerprint: false),
    itSafari180: TargetInfo(target: itSafari180, name: "safari180", alias: "safari18_0", family: bfSafari, version: "18.0", os: "macOS Sequoia", supportsHttp3Fingerprint: false),
    itSafari180Ios: TargetInfo(target: itSafari180Ios, name: "safari180_ios", alias: "safari18_0_ios", family: bfSafari, version: "18.0", os: "iOS 18.0", supportsHttp3Fingerprint: false),
    itSafari184: TargetInfo(target: itSafari184, name: "safari184", alias: "safari18_4", family: bfSafari, version: "18.4", os: "macOS Sequoia", supportsHttp3Fingerprint: false),
    itSafari184Ios: TargetInfo(target: itSafari184Ios, name: "safari184_ios", alias: "safari18_4_ios", family: bfSafari, version: "18.4", os: "iOS 18.4", supportsHttp3Fingerprint: false),
    itSafari260: TargetInfo(target: itSafari260, name: "safari260", alias: "safari26_0", family: bfSafari, version: "26.0", os: "macOS Tahoe", supportsHttp3Fingerprint: false),
    itSafari260Ios: TargetInfo(target: itSafari260Ios, name: "safari260_ios", alias: "safari26_0_ios", family: bfSafari, version: "26.0", os: "iOS 26.0", supportsHttp3Fingerprint: false),
    itSafari2601: TargetInfo(target: itSafari2601, name: "safari2601", alias: "safari26_0_1", family: bfSafari, version: "26.0.1", os: "macOS Tahoe", supportsHttp3Fingerprint: false),
    itSafari270: TargetInfo(target: itSafari270, name: "safari270", alias: "safari270", family: bfSafari, version: "27.0", os: "macOS 27.0", supportsHttp3Fingerprint: true),
    itSafari270Ios: TargetInfo(target: itSafari270Ios, name: "safari270_ios", alias: "safari270_ios", family: bfSafari, version: "27.0", os: "iOS 27.0", supportsHttp3Fingerprint: true),
    itFirefox133: TargetInfo(target: itFirefox133, name: "firefox133", alias: "firefox133", family: bfFirefox, version: "133.0", os: "macOS Sonoma", supportsHttp3Fingerprint: false),
    itFirefox135: TargetInfo(target: itFirefox135, name: "firefox135", alias: "firefox135", family: bfFirefox, version: "135.0", os: "macOS Sonoma", supportsHttp3Fingerprint: false),
    itFirefox144: TargetInfo(target: itFirefox144, name: "firefox144", alias: "firefox144", family: bfFirefox, version: "144.0", os: "macOS Tahoe", supportsHttp3Fingerprint: false),
    itFirefox147: TargetInfo(target: itFirefox147, name: "firefox147", alias: "firefox147", family: bfFirefox, version: "147.0", os: "macOS Tahoe", supportsHttp3Fingerprint: true),
    itFirefox153: TargetInfo(target: itFirefox153, name: "firefox153", alias: "firefox153", family: bfFirefox, version: "153.0", os: "Windows 10", supportsHttp3Fingerprint: false),
    itFirefox154: TargetInfo(target: itFirefox154, name: "firefox154", alias: "firefox154", family: bfFirefox, version: "154.0", os: "Windows 10", supportsHttp3Fingerprint: false),
    itFirefox155: TargetInfo(target: itFirefox155, name: "firefox155", alias: "firefox155", family: bfFirefox, version: "155.0", os: "Windows 10", supportsHttp3Fingerprint: false),
    itTor145: TargetInfo(target: itTor145, name: "tor145", alias: "tor145", family: bfTor, version: "14.5", os: "macOS Sonoma", supportsHttp3Fingerprint: false)
  ]

proc info*(target: ImpersonateTarget): TargetInfo =
  ## Returns the `TargetInfo` metadata for the given `ImpersonateTarget`.
  AllTargetInfos[target]

proc parseImpersonateTarget*(name: string): ImpersonateTarget =
  ## Parses a target name or alias (e.g., `"chrome152"`, `"safari18_4"`, `"chrome"`, `"firefox"`, `"safari"`, `"edge"`, `"tor"`)
  ## into an `ImpersonateTarget`. Raises `ValueError` if unknown.
  let clean = name.strip().toLowerAscii()
  if clean == "" or clean == "none":
    return itNone
  case clean
  of "chrome": return itChromeLatest
  of "chrome_macos": return itChromeMacosLatest
  of "chrome_android": return itChromeAndroidLatest
  of "edge": return itEdgeLatest
  of "safari": return itSafariLatest
  of "safari_ios": return itSafariIosLatest
  of "firefox", "ff": return itFirefoxLatest
  of "tor": return itTorLatest
  else:
    for t in ImpersonateTarget:
      if t != itNone:
        let ti = AllTargetInfos[t]
        if cmpIgnoreCase(ti.name, clean) == 0 or cmpIgnoreCase(ti.alias, clean) == 0:
          return t
    raise newException(ValueError, "Unknown impersonation target: " & name)

proc isSupportedTarget*(name: string): bool =
  ## Checks whether `name` is a known `ImpersonateTarget` or alias.
  try:
    discard parseImpersonateTarget(name)
    result = true
  except ValueError:
    result = false

proc formatImpersonateOpt*(target: ImpersonateTarget, defaultHeaders: bool = true): string =
  ## Formats a target for `CURLOPT_IMPERSONATE` (`"name:yes"` or `"name:no"`).
  if target == itNone:
    return ""
  result = $target & (if defaultHeaders: ":yes" else: ":no")
