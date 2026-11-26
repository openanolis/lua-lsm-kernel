#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Assertions for deny-tmp-write.lua, run while it is registered.
#
# Probe with a real write: file_permission fires from vfs_write(), so the
# truncating open of `: > file` would bypass the hook.
set -u

denied=/tmp/lua-lsm-denied-probe
allowed=/tmp/lua-lsm-allowed-probe

rm -f "$denied" "$allowed"

if printf 'probe\n' > "$denied" 2>/dev/null; then
	echo "deny-tmp-write allowed a write to $denied"
	rm -f "$denied"
	exit 1
fi

if ! printf 'probe\n' > "$allowed" 2>/dev/null; then
	echo "deny-tmp-write denied the control path $allowed"
	exit 1
fi

rm -f "$allowed"
exit 0
