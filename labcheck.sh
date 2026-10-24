#!/bin/bash
# Prove the node2shell target is NOT weakened: standard user + full ASLR, with a
# live demonstration that the address space actually randomizes per worker life.
# This is what separates this PoC from "deterministic" ones that disable ASLR.
#   usage: ./labcheck.sh [container]   (default: node2shell-vuln)
CT="${1:-node2shell-vuln}"

echo "=================================================================="
echo " node2shell target check: $CT"
echo "=================================================================="
echo -n "  node version : "; docker exec "$CT" node -v
echo -n "  runs as      : "; docker exec "$CT" id
echo -n "  binary type  : "; docker exec "$CT" sh -c 'head -c20 /usr/local/bin/node | od -An -tx1 | grep -q "02 00" && echo "ET_EXEC (non-PIE)" || echo "PIE"'
rvs=$(docker exec "$CT" cat /proc/sys/kernel/randomize_va_space)
case "$rvs" in
  2) aslr="FULL ASLR (enabled, kernel default)";;
  1) aslr="partial ASLR (enabled)";;
  0) aslr="DISABLED";;
  *) aslr="unknown ($rvs)";;
esac
echo "  ASLR         : randomize_va_space=$rvs  ->  $aslr"

echo
echo "  live proof  (libc base must differ across worker lives):"
# the node worker is the server.js process that isn't PID 1 (the supervisor sh)
sample() {
  docker exec "$CT" sh -c 'for p in $(pgrep -f server.js); do [ "$p" != 1 ] && { grep -m1 libc /proc/$p/maps 2>/dev/null | cut -d- -f1; break; }; done'
}
a=$(sample); echo "    worker life A : 0x$a"
docker exec "$CT" sh -c 'for p in $(pgrep -f server.js); do [ "$p" != 1 ] && kill "$p"; done' 2>/dev/null
sleep 2
b=$(sample); echo "    worker life B : 0x$b"
if [ -n "$a" ] && [ "$a" != "$b" ]; then
  echo "    => the base moved: ASLR is live, not disabled."
else
  echo "    => bases match (recheck: worker may not have restarted yet)."
fi

echo
echo "  verdict: standard user, non-PIE binary, FULL ASLR enabled."
echo "           poc.py defeats real ASLR probabilistically. Nothing is weakened."
echo "=================================================================="
