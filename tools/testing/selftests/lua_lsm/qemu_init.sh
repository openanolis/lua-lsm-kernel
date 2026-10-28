#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Install as /init in a private BusyBox initramfs, never in the demo rootfs.
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /sys/kernel/security /sys/kernel/debug /sys/kernel/tracing
mount -t devpts devpts /dev/pts
mount -t securityfs securityfs /sys/kernel/security
mount -t debugfs debugfs /sys/kernel/debug
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
ulimit -c 0
mode=full
LIFECYCLE_ROUNDS=20
for word in $(command cat /proc/cmdline); do
	case "$word" in
	lua_lsm_mode=*) mode=${word#*=} ;;
	lua_lsm_rounds=*) LIFECYCLE_ROUNDS=${word#*=} ;;
	esac
done
export LIFECYCLE_ROUNDS
echo "LUA_LSM_RUN_BEGIN mode=$mode rounds=$LIFECYCLE_ROUNDS"
uname -a
rc=0
if [ "$mode" = perf ]; then
	/tests/shdict_bench 10000 5 500 || rc=$?
	if [ "$rc" -eq 0 ]; then /tests/shdict_manage_bench || rc=$?; fi
elif [ "$mode" = fault ]; then
	/tests/shdict_fault || rc=$?
elif [ "$mode" = trace ]; then
	sh /tests/shdict_trace.sh || rc=$?
elif [ "$mode" = kmemleak ]; then
	sh /tests/shdict_kmemleak.sh || rc=$?
else
	for test in shdict_poc shdict_stress shdict_boundary shdict_shared_fd shdict_snapshot shdict_lifecycle; do
		sh "/tests/$test.sh"
		status=$?
		echo "LUA_LSM_TEST $test status=$status"
		if [ "$status" -ne 0 ]; then rc=$status; break; fi
	done
fi
echo "LUA_LSM_RUN_END mode=$mode status=$rc"
sync
poweroff -f
