#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# RISC-V setjmp/longjmp semantics and Lua protected-error recovery.

set -u

BASE=/sys/kernel/security/lua
REGISTER=$BASE/register
MODULES=$BASE/modules
TEST_DIR=${1:-$(dirname -- "$0")}
KUNIT_LOG=/tmp/riscv-setjmp-kunit.log
PASS=0
FAIL=0

ok()
{
	PASS=$((PASS + 1))
	echo "PASS: $1"
}

bad()
{
	FAIL=$((FAIL + 1))
	echo "FAIL: $1"
}

expect_register_failure()
{
	policy=$1
	description=$2

	if cat "$policy" > "$REGISTER" 2>/dev/null; then
		bad "$description (registration unexpectedly succeeded)"
	else
		ok "$description"
	fi
}

echo "== RISC-V setjmp/longjmp and Lua recovery =="

if [ "$(uname -m)" != "riscv64" ]; then
	echo "SKIP: this test requires a RISC-V kernel"
	exit 4
fi

if [ ! -w "$REGISTER" ] || [ ! -r "$MODULES" ]; then
	echo "SKIP: Lua-LSM securityfs interfaces are unavailable"
	exit 4
fi

dmesg > "$KUNIT_LOG"
if ! grep -q '# Subtest: riscv-setjmp' "$KUNIT_LOG"; then
	echo "SKIP: enable CONFIG_RISCV_SETJMP_KUNIT_TEST=y"
	rm -f "$KUNIT_LOG"
	exit 4
fi

if grep -Eq '(^|\]) +ok [0-9]+( -)? riscv-setjmp$' "$KUNIT_LOG"; then
	ok "KUnit setjmp/longjmp semantics"
else
	bad "KUnit setjmp/longjmp semantics"
fi

rm -f "$KUNIT_LOG"

syntax_policy=$TEST_DIR/setjmp_syntax_error.lua
runtime_policy=$TEST_DIR/setjmp_runtime_error.lua
recovery_policy=$TEST_DIR/setjmp_recovery.lua

for policy in "$syntax_policy" "$runtime_policy" "$recovery_policy"; do
	if [ ! -f "$policy" ]; then
		bad "missing fixture $policy"
		echo "== summary: PASS=$PASS FAIL=$FAIL =="
		exit 1
	fi
done

touch /tmp/setjmp-hook-error /tmp/setjmp-denied /tmp/setjmp-allowed || {
	bad "create file-open fixtures"
	exit 1
}

expect_register_failure "$syntax_policy" "Lua syntax error is contained"
expect_register_failure "$runtime_policy" "Lua runtime error is contained"

if grep -Eq '^setjmp_(syntax|runtime)_error[[:space:]]' "$MODULES"; then
	bad "failed policies must not remain registered"
else
	ok "failed policies leave no registered module"
fi

if cat "$recovery_policy" > "$REGISTER" 2>/dev/null; then
	ok "valid policy registers after both errors"
else
	bad "valid policy registers after both errors"
fi

if grep -Eq '^setjmp_recovery[[:space:]]' "$MODULES"; then
	ok "recovery policy is LIVE"
else
	bad "recovery policy is LIVE"
fi

if exec 4< /tmp/setjmp-hook-error; then
	ok "hook runtime error falls back without escaping into the kernel"
else
	bad "hook runtime error falls back without escaping into the kernel"
fi

if exec 5< /tmp/setjmp-allowed; then
	ok "same-task Lua VM runs the next hook after an error"
else
	bad "same-task Lua VM runs the next hook after an error"
fi
exec 4<&-
exec 5<&-

if cat /tmp/setjmp-denied > /dev/null 2>&1; then
	bad "recovery hook denies its configured path"
else
	ok "recovery hook denies its configured path"
fi

if cat /proc/version > /dev/null 2>&1; then
	ok "kernel remains usable after Lua errors"
else
	bad "kernel remains usable after Lua errors"
fi

echo
echo "== summary: PASS=$PASS FAIL=$FAIL =="
if [ "$FAIL" -eq 0 ]; then
	echo "LUA-LSM-SETJMP-RECOVERY: ALL PASS"
	exit 0
fi

echo "LUA-LSM-SETJMP-RECOVERY: FAILURES PRESENT"
exit 1
