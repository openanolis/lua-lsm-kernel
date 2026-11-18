#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -u
TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$TEST_DIR/shdict_boundary"
rc=$?
[ "$rc" -eq 0 ] || exit "$rc"
echo 'LUA-LSM-SHDICT-BOUNDARY: ALL PASS'
