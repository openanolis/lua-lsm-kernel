#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Companion assertions for allow-all.lua. Runs with the policy registered.
set -u

workfile=/tmp/lua-lsm-allow-all-probe

echo data > "$workfile" || { echo "allow-all denied a write"; exit 1; }
grep -q data "$workfile" || { echo "allow-all probe unreadable"; exit 1; }
rm -f "$workfile"
exit 0
