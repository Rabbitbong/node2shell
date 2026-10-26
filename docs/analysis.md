# node2shell technical analysis

Deeper notes behind the [README](../README.md), verified on the lab (node 24.22.0
x86-64, Linux). It covers the measured memory layout, how the exploit gets around
ASLR, and how far `--autoprofile` ports across Node versions.

## Under the hood (gdb-measured)

Attaching gdb to the live worker and firing the bare DoS trigger (which writes at
a known `pos = 0x7FFFFFFF`) pins the exact layout.

The decode runs on a libuv threadpool thread (`UV_THREADPOOL_SIZE=1`). The fault
lands in thread `libuv-worker`, not the main thread, so the ring buffer and the
overwrite target both sit high in mmap space rather than on the main stack.

The OOB write is a single `movups %xmm0,(%r8)`, a 16-byte SSE store at `ring +
pos` where `pos` is a signed displacement (`ProcessCommands+695` in the stripped
binary).

The ring is a thread-arena allocation, high in mmap. From the known-`pos` fault,
`ring = 0x7001bc004cdf - 0x7FFFFFFF = 0x70013c004ce0`, which is inside the
`libuv-worker` arena at `0x70013c000000-0x70013c021000`.

The saved return address sits on that thread's stack
(`0x70018cd08000-0x70018d508000`), a randomized delta above the ring. A hit needs
`delta == pos` (`0x137ed748`). In the sampled life the real delta was about
`0x515...`, so the guess landed in a guard page and missed. That gap is the
~1-in-8.

`.bss` is fixed and low (`0x6ba7000-0x6be0000`, our `bss_base 0x6bdfb00`) because
the binary is non-PIE, so the ROP scratch is ASLR-immune. Only the ring-to-stack
delta is the gamble.

The measured ordering, low to high: `.bss` (fixed), `[heap]`, then the ring and
the worker stack (both high and close together), then libc, then the main stack.
The write reaches from the ring to the worker stack, both high, which is why a
`0x137ed748` displacement (about 324 MB) can cover the distance.

## Resolving ASLR without a leak

The bug is a write with no co-located read, so the destination cannot be leaked.
Two things are randomized: the write position (the ring-to-stack delta) and the
socket `fd`. Everything else (gadgets, PLT, `.bss`) is fixed because the binary is
non-PIE. The exploit does not defeat ASLR. It outlasts it.

It fires a fixed class-center guess (`0x137ed748`) that matches the real delta
about 1 in 8 worker lives. A miss crashes the worker; the supervisor restarts it
with a fresh layout; the exploit retries. The socket reports hit or miss on its
own: command output comes back on the exploit socket on a hit, and an HTTP error
or a dropped connection on a miss, so no target access is needed.

The center is a property of the build, not a per-target secret. You calibrate it
once against your own local copy of the build and reuse it against any instance of
that build. Three fresh lives landed at attempts 2, 4, and 13; a deliberately
wrong `fd` (25) at the same center landed 0 of 8, which shows the socket oracle
discriminates. A deterministic single-shot would need a separate info-leak
primitive to compute the exact delta, which this bug does not give.

## Version portability (`--autoprofile`)

`build_profile.py` resolves the binary-derived fields (gadgets, PLT, the `execvp`
call-site, the `.bss` scratch) from any non-PIE node ELF, so the exploit is not
tied to one build. Tested end to end:

| Target | Gadgets | Trigger | RCE | Result |
|---|---|---|---|---|
| node 24.22.0 (pinned) | native | SEGV | attempt 4 | baseline |
| node 24.19.0 | 9/9 auto-resolved | SEGV | attempt 2 | works |
| node 22.20.0 | `execvp` call-site missing | n/a | n/a | won't build |
| node 26.12.0 | `store rdi+0x88` missing | n/a | n/a | won't build |

Within the 24.x line it ports cleanly. A freshly built 24.19.0 lab takes a shell
via `--autoprofile`, with gadgets resolved from its own binary, the same trigger
stream, and the same position class (`0x137ed748` landed), because the
libuv/glibc allocation arrangement is shared across 24.x.

It stops working once the major version changes. The simple gadgets (`pop rdi;
ret` and the like) exist in every build, but the composite multi-instruction
gadgets do not. 22.x has no `execvp` call-site sequence, and 26.x has no `store
rdi+0x88` stub. When a gadget is missing, `build_profile.py` stops and prints
`"chain needs adapting"` rather than handing back a profile that would fail
silently. Getting it to work on 22.x or 26.x would mean finding equivalent gadget
sequences by hand for each one, which is real reverse-engineering work, not a
change to the resolver.

Gadget authenticity was checked directly too: all 9 binary-derived fields in
`poc.py`'s profile resolve to the exact addresses in the real pinned binary
(sha256 `67ca5783...`).

## Fidelity

The lab reaches the vulnerability through stock Express 5 / body-parser 2.x, with
no `eval`, no `execSync`, no application sink, and no in-process patching of the
decoder. The CVE id, fixed versions, root cause (an invalid block switch reported
as "need more input"), attack surface, and probabilistic behavior all match the
Node advisory and Imperva's write-up. One deviation is deliberate: Imperva demoed
arm64, while this lab is an x86-64 port with its own gadget chain, since Imperva
published no PoC. The target is not weakened. It runs as non-root
`uid=1000(node)` under full ASLR on a non-PIE binary; `labcheck.sh` shows this.
