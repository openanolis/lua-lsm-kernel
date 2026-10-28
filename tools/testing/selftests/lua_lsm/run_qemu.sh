#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Host-side runner. A guest's failure must not be hidden by QEMU exit status 0.
set -eu
if [ "$#" -lt 3 ] || [ "$#" -gt 6 ]; then
	echo "usage: $0 IMAGE INITRAMFS LOG [full|perf|fault|kmemleak|trace] [CPUS] [ROUNDS]" >&2
	exit 1
fi
image=$1
initramfs=$2
log=$3
mode=${4:-full}
cpus=${5:-2}
rounds=${6:-20}
case "$mode" in full|perf|fault|kmemleak|trace) ;; *) exit 1 ;; esac
case "$cpus" in 1|2|4) ;; *) exit 1 ;; esac
case "$rounds" in ''|*[!0-9]*) exit 1 ;; esac
[ "$rounds" -ge 1 ] && [ "$rounds" -le 20 ] || exit 1
[ -r "$image" ] && [ -r "$initramfs" ] || exit 1
extra=
case "$mode" in fault|kmemleak) extra=lua.lvm_pool_max=0 ;; esac
timeout "${QEMU_TIMEOUT:-900}" qemu-system-riscv64 \
	-machine virt -accel tcg,thread=multi -cpu rv64 -m "${QEMU_MEMORY:-1G}" \
	-smp "$cpus" -nographic -bios default -kernel "$image" -initrd "$initramfs" \
	-append "console=ttyS0 earlycon=sbi rdinit=/init lua_lsm_mode=$mode lua_lsm_rounds=$rounds $extra" \
	> "$log" 2>&1
grep -aF "LUA_LSM_RUN_END mode=$mode status=0" "$log" >/dev/null || {
	echo "FAIL: missing successful guest completion; inspect $log" >&2
	exit 1
}
if grep -aE 'BUG:|WARNING:|Oops:|Kernel panic|KASAN:|Invalid wait context|possible circular locking|suspicious RCU usage' "$log"; then
	echo "FAIL: unexpected kernel diagnostic; inspect $log" >&2
	exit 1
fi
echo "PASS: $mode cpus=$cpus rounds=$rounds log=$log"
