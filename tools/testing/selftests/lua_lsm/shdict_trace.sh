#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu
trace=/sys/kernel/tracing
testdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -w "$trace/kprobe_events" ] || { echo 'FAIL: kprobe ftrace events required'; exit 1; }
echo 0 > "$trace/tracing_on"
echo 4096 > "$trace/buffer_size_kb"
: > "$trace/trace"
echo 'p:lua_lsm/call_in lua_lsm_shdict_call' > "$trace/kprobe_events"
echo 'r:lua_lsm/call_out lua_lsm_shdict_call ret=$retval:s64' >> "$trace/kprobe_events"
echo 'p:lua_lsm/dump_in lua_lsm_shdict_dump' >> "$trace/kprobe_events"
echo 'r:lua_lsm/dump_out lua_lsm_shdict_dump ret=$retval:s64' >> "$trace/kprobe_events"
echo 1 > "$trace/events/lua_lsm/enable"
echo 1 > "$trace/tracing_on"
"$testdir/shdict_manage_bench" 40
echo 0 > "$trace/tracing_on"
echo 'LUA_LSM_TRACE_BEGIN'
cat "$trace/trace"
echo 'LUA_LSM_TRACE_END'
echo 0 > "$trace/events/lua_lsm/enable"
: > "$trace/kprobe_events"
echo 'LUA-LSM-TRACE: ALL PASS'
