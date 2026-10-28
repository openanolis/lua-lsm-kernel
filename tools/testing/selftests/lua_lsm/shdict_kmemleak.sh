#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu
testdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
control=/sys/kernel/debug/kmemleak
[ -w "$control" ] || { echo 'FAIL: kmemleak configuration required'; exit 1; }
echo scan > "$control"
sleep 6
echo scan > "$control"
echo 'KMEMLEAK_BEFORE_BEGIN'
cat "$control"
echo 'KMEMLEAK_BEFORE_END'
"$testdir/shdict_boundary"
"$testdir/shdict_shared_fd"
"$testdir/shdict_snapshot"
LIFECYCLE_ROUNDS=10 sh "$testdir/shdict_lifecycle.sh"
sleep 6
echo scan > "$control"
sleep 1
echo scan > "$control"
cat "$control" > /tmp/lua-lsm-kmemleak.after
echo 'KMEMLEAK_AFTER_BEGIN'
cat /tmp/lua-lsm-kmemleak.after
echo 'KMEMLEAK_AFTER_END'
[ ! -s /tmp/lua-lsm-kmemleak.after ] || { echo 'LUA-LSM-KMEMLEAK: FAIL'; exit 1; }
echo 'LUA-LSM-KMEMLEAK: ALL PASS'
