# node2shell: CVE-2026-111497 PoC lab

A self-contained lab for **Node2Shell** (CVE-2026-111497): a heap out-of-bounds
write in the Brotli decoder bundled in Node.js's `zlib`, reachable remotely
because Express 5 / body-parser 2.x transparently decode `Content-Encoding: br`
request bodies. A crafted stream drives the decoder's *impossible distance-block
switch* into an invalid state, producing a controlled 16-byte OOB write that
`poc.py` turns into RCE.

Fixed upstream 2026-10-21 (Node 22.23.4 / 24.22.1 / 26.12.1). Background:
Imperva, [*"Node2Shell: From Brotli Data to Remote Code Execution"*](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/).

The target is **Orbital**, a fictional bulk-ingestion app. The bug sits where it
realistically would: a bulk import endpoint accepting large compressed batches
(`POST /api/v1/import`, 50 MB limit scoped to that one route; other routes keep
the default 100 KB).

> **Authorized lab use only.** This targets a **patched** CVE for reproduction
> and defense research. `poc.py` is loopback-only by construction
> (`127.0.0.1` / `::1` / `localhost`). Never point it at anything you do not own.

![poc.py landing remote code execution on the Orbital container](docs/demo-poc.png)

## Quickstart

Requires Docker with linux/amd64 (the ROP profile is calibrated to the pinned
node 24.22.0 x86-64 binary).

```sh
./run.sh                       # build + run: vuln :3000, patched :3002
python3 poc.py --port 3000     # exploit the vuln container  -> uid=1000(node)
python3 poc.py --port 3002     # patched build: FAILs closed
```

Browse the app at <http://localhost:3000/> and `/dashboard`. With the compose
plugin, `docker compose up -d --build` replaces `run.sh`.

## `poc.py`

Stdlib-only network exploit. It builds a ~23 MB Brotli trigger (SHA-256 pinned)
plus a 1031-byte ROP prefix, delivers them as a two-write chunked POST (write 1
parks the decoder, write 2 resumes it into the invalid state), then fires the
16-byte OOB write. On a hit the ROP chain runs `dup2(conn_fd, 1)` +
`execvp("/usr/bin/id")`, so `id` output returns on the attacker's own socket.

```
--port N          target port (loopback host only)
--path P          route to POST to              (default /api/v1/import)
--ctype T         Content-Type header           (default application/json)
--exec PATH       binary to run on target, absolute path, no args (default /usr/bin/id)
--fd N            accepted-socket fd for dup2    (default 19; bare node is 24)
--position 0x..   staged write position         (default 0x137ed748)
--sweep           sweep a range of positions and fds
--autoprofile X   build the ROP profile from a node binary or docker image
--quiet           print only the result line
```

`--exec` runs a **single binary, no arguments** (the ROP controls `execvp`'s
filename but not argv). It's **probabilistic**: up to 32 attempts per run
(~1 in 7-10 land); a miss crashes the worker, the supervisor re-rolls ASLR, and
`poc.py` retries. Re-run or `--sweep` if a run misses all attempts.

**`--autoprofile`** ports the exploit to other vulnerable builds. The ROP chain
is absolute addresses in a specific node binary; official binaries are non-PIE
(`ET_EXEC`), so `build_profile.py` resolves the gadgets, PLT entries, and `.bss`
straight from the ELF (or a docker image it extracts). Needs `pwntools`
(`pip install -r requirements.txt`); the normal path stays stdlib-only.

```sh
python3 poc.py --autoprofile node:24.19.0 --port <target> --sweep
```

## Why there's no point-and-shoot universal PoC

The exploit is per-target, not one-size-fits-all, and deliberately stays honest
about it:

- **Gadgets are per-binary**: absolute addresses in one node build; a different
  version/arch moves all of them. (`--autoprofile` rebuilds them given the binary.)
- **The `fd` is per-environment**: `dup2` needs the exact connection fd; the
  same binary used fd 19 in a container, fd 24 run bare. Real apps shift it further.
- **The write target is ASLR-randomized and the bug can't leak it**: it's a
  *write* with no pre-overwrite read, so `pos` is a guess (~8-14%/attempt, layout
  in ~6-7 classes megabytes apart). Grooming shapes the heap but can't touch the
  independently-randomized stack. A deterministic single-shot would need a
  separate info-leak bug this PoC does not fabricate.

## The target isn't weakened (standard user, full ASLR)

Several public "deterministic" PoCs only work because they disable ASLR or run as
root. This lab does neither; `labcheck.sh` proves it (non-root `uid=1000(node)`,
`ET_EXEC` non-PIE, `randomize_va_space=2`, and the libc base moving across worker
lives). The probabilistic retry loop is the cost of not weakening the target.

![labcheck.sh showing full ASLR, non-PIE binary, and the libc base moving across worker lives](docs/demo-labcheck.png)

## Defensive A/B

The same request against the **patched** container fails closed: the fixed
decoder rejects the impossible switch (`ERR__ERROR_FORMAT_BLOCK_SWITCH`).
Detection signal: a large `Content-Encoding: br` body on an import-style route
that a 24.22.0 decoder keeps processing (and crashes on) while 24.22.1 rejects. A
reverse proxy's body-size limit (nginx `client_max_body_size` defaults to 1 MB)
blocks the ~23 MB trigger outright: a natural mitigation.

## Layout

```
poc.py            the exploit (probabilistic network RCE, loopback-only)
build_profile.py  --autoprofile gadget resolver (needs pwntools)
run.sh            build + run the A/B lab with plain docker
labcheck.sh       prove the target isn't weakened (user + ASLR check)
Dockerfile        vulnerable fixture image (pinned node 24.22.0 x86-64)
docker-compose.yml  same A/B lab for environments that have compose
app/              Orbital: the realistic vuln web app + import console
```

## Rules of engagement

Authorized lab environments only. Patched-vulnerability reproduction and defense
research. Loopback-only; never target systems you do not own or anything
internet-facing.
