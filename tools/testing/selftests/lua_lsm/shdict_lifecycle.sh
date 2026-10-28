#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Overlap independent-FD access, enumeration and hooks with module teardown.
set -u

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROUNDS=${LIFECYCLE_ROUNDS:-3}

if [ ! -e /sys/kernel/security/lua/shdict ]; then
	echo "SKIP: Lua-LSM securityfs is unavailable"
	exit 4
fi
if [ ! -x "$TEST_DIR/shdict_lifecycle" ]; then
	echo "FAIL: build shdict_lifecycle first (see README.md)"
	exit 1
fi

log=$(mktemp /tmp/shdict-lifecycle-dmesg.XXXXXX) || exit 1
trap 'rm -f "$log"' EXIT
dmesg > "$log" || exit 1
before=$(wc -l < "$log")

"$TEST_DIR/shdict_lifecycle" "$TEST_DIR/shdict_lifecycle.lua" "$ROUNDS"
rc=$?

dmesg > "$log" || exit 1
after=$(wc -l < "$log")
if [ "$after" -lt "$before" ]; then
	echo "FAIL: kernel log wrapped; cannot verify diagnostics"
	exit 1
fi
if tail -n +$((before + 1)) "$log" | grep -Eq \
	'WARNING:|BUG:|Oops:|Kernel panic|KASAN:|use-after-free|refcount_t:|LuaVM traceback'; then
	echo "FAIL: unexpected kernel diagnostic during lifecycle test"
	tail -n +$((before + 1)) "$log"
	exit 1
fi

[ "$rc" -eq 0 ] || exit "$rc"
echo "LUA-LSM-SHDICT-LIFECYCLE: ALL PASS ($ROUNDS rounds)"
