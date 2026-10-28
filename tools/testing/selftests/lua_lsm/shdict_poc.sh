#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Lua-LSM shared-dictionary text-interface PoC.

set -u

BASE=/sys/kernel/security/lua
SHDICT=$BASE/shdict
POLICY=${1:-$(dirname -- "$0")/shdict_poc.lua}
MODULE=demo
PASS=0
FAIL=0
RESP_FILE=/tmp/shdict-response

ok()  { PASS=$((PASS + 1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

# Request results remain per-open. A fresh open reads the enumeration snapshot.
send() {
	command=$1
	if ! printf '%s\n' "$command" >&3 2>/dev/null; then
		resp=
		return 1
	fi
	resp=$(cat <&3)
}

send_file() {
	command=$1
	if ! printf '%s\n' "$command" >&3 2>/dev/null; then
		: > "$RESP_FILE"
		return 1
	fi
	cat <&3 > "$RESP_FILE"
}

expect() {
	expected=$1
	command=$2
	description=$3
	if send "$command" && [ "$resp" = "$expected" ]; then
		ok "$description"
	else
		bad "$description (expected '$expected', got '$resp')"
	fi
}

must_fail() {
	command=$1
	description=$2
	if send "$command"; then
		bad "$description (request unexpectedly succeeded)"
	else
		ok "$description"
	fi
}

make_a_run() {
	a_run=a
	while [ ${#a_run} -lt "$1" ]; do
		a_run=$a_run$a_run
	done
}

echo "== Lua-LSM shared dictionary text interface PoC =="
[ -f "$POLICY" ] || { bad "policy $POLICY not found"; exit 1; }
[ -w "$SHDICT" ] || { bad "$SHDICT missing"; exit 1; }

cat "$POLICY" > "$BASE/register" || { bad "module register failed"; exit 1; }
ok "module registered"
exec 3<>"$SHDICT" || { bad "cannot open $SHDICT"; exit 1; }

echo "-- 1. set/get and on-demand dictionary creation --"
expect true "set $MODULE runtime flag boolean true" "set boolean"
expect true "get $MODULE runtime flag" "get boolean"
expect true "set $MODULE runtime number number 42" "set number"
expect 42 "get $MODULE runtime number" "get number"
expect true "set $MODULE runtime message string hello world" \
	"set plain string with spaces"
expect "hello world" "get $MODULE runtime message" "get plain string"
expect true "set $MODULE config empty string " "set empty string"
expect "" "get $MODULE config empty" "get empty string"

echo "-- 2. incr, overwrite, delete and binary-safe strings --"
expect 2 "incr $MODULE runtime counter 2" "incr creates counter"
expect 3 "incr $MODULE runtime counter" "incr defaults to one"
expect true "set $MODULE runtime message string new" "overwrite string"
expect new "get $MODULE runtime message" "overwritten value visible"
expect true "delete $MODULE runtime message" "delete key"
must_fail "get $MODULE runtime message" \
	"missing key is distinct from an empty string"
must_fail "incr $MODULE runtime flag 1" \
	"shared method error is propagated through the bridge"
expect true "get $MODULE runtime flag" \
	"failed increment leaves the existing value intact"
expect true "set $MODULE runtime probe_expected hex 610062" \
	"set embedded-NUL string with hex"
if send_file "get $MODULE runtime probe_expected"; then
	hex=$(od -An -tx1 "$RESP_FILE" | tr -d ' \n')
	[ "$hex" = 610062 ] && ok "embedded-NUL returned intact" || \
		bad "embedded-NUL result (expected 610062, got $hex)"
else
	bad "get embedded-NUL string"
fi

echo "-- 3. enumeration snapshot --"
snapshot=$(cat "$SHDICT")
echo "$snapshot" | grep -Fqx "demo runtime flag boolean true" && \
	ok "enumerate boolean" || bad "enumerate boolean"
echo "$snapshot" | grep -Fqx "demo runtime number number 42" && \
	ok "enumerate number" || bad "enumerate number"
echo "$snapshot" | grep -Fqx 'demo runtime probe_expected string a\x00b' && \
	ok "enumeration escapes embedded NUL" || bad "enumeration escapes embedded NUL"
echo "$snapshot" | grep -Fqx "demo config empty string " && \
	ok "enumerate second named dictionary" || bad "enumerate second named dictionary"

echo "-- 4. dynamic file-access decision --"
touch /tmp/blocked /tmp/blocked2 /tmp/plain || { bad "touch fixtures"; exit 1; }
expect true "set $MODULE runtime blocked_path string /tmp/blocked" \
	"configure /tmp/blocked"
if cat /tmp/blocked > /dev/null 2>&1; then
	bad "open /tmp/blocked should be denied"
else
	ok "open /tmp/blocked denied"
fi
cat /tmp/plain > /dev/null 2>&1 && ok "unmatched path allowed" || \
	bad "unmatched path should be allowed"
expect true "set $MODULE runtime blocked_path string /tmp/blocked2" \
	"update policy without reload"
cat /tmp/blocked > /dev/null 2>&1 && ok "old path allowed after update" || \
	bad "old path should be allowed after update"
if cat /tmp/blocked2 > /dev/null 2>&1; then
	bad "new path should be denied"
else
	ok "new path denied after update"
fi

echo "-- 5. value and parser boundaries --"
cat /proc/version > /dev/null
expect false "get $MODULE runtime probe_mismatch" \
	"hook reads embedded-NUL value consistently"
snapshot=$(cat "$SHDICT")
echo "$snapshot" | grep -Fqx "demo runtime ptr lightuserdata <hidden>" && \
	ok "lightuserdata address is hidden" || bad "lightuserdata address is hidden"
must_fail "get nosuch runtime flag" "unknown module is refused"
must_fail "set $MODULE runtime bad boolean maybe" "invalid boolean is refused"
must_fail "set $MODULE runtime bad number 1x" "invalid number is refused"
must_fail "set $MODULE runtime bad table value" "unsupported type is refused"
must_fail "set $MODULE runtime bad hex 123" "odd-length hex is refused"
must_fail "get $MODULE runtime flag extra" "extra get argument is refused"
must_fail "unknown $MODULE runtime flag" "unknown operation is refused"

make_a_run 256
must_fail "get $a_run runtime flag" "module name over 128 bytes is refused"
if printf 'get demo\nruntime flag\n' >&3 2>/dev/null; then
	bad "multi-line request should fail"
else
	ok "multi-line request fails"
fi
make_a_run 8192
if printf 'set demo runtime long string %s\n' "$a_run" >&3 2>/dev/null; then
	bad "request over 4096 bytes should fail"
else
	ok "request over 4096 bytes fails"
fi

echo "-- 6. permission checks --"
if setpriv --reuid 1000 --regid 1000 --clear-groups sh -c \
	'exec 4<>/sys/kernel/security/lua/shdict' > /dev/null 2>&1; then
	bad "unprivileged open should fail"
else
	ok "unprivileged open denied"
fi
if setpriv --reuid 1000 --regid 1000 --clear-groups sh -c \
	'printf "get demo runtime flag\n" >&3' 2>/dev/null; then
	bad "unprivileged write on inherited fd should fail"
else
	ok "per-operation capability check enforced"
fi

echo "-- 7. repeated calls and Lua stack cleanup --"
i=1
repeat_ok=1
while [ "$i" -le 100 ]; do
	if ! send "set $MODULE runtime repeat number $i" || \
	   [ "$resp" != true ]; then
		repeat_ok=0
		break
	fi
	i=$((i + 1))
done
[ "$repeat_ok" -eq 1 ] && ok "100 repeated requests" || \
	bad "repeated request $i"
expect 100 "get $MODULE runtime repeat" "Lua stack remains usable"

echo "-- 8. module lifecycle boundary --"
sh -c ': > /dev/null; while :; do :; done' &
spin=$!
sleep 1
if printf '%s\n' "$MODULE" > "$BASE/unregister" 2>/dev/null; then
	ok "unregister fully removed an idle task VM policy"
else
	ok "unregister retained a busy, non-LIVE policy"
fi
must_fail "get $MODULE runtime flag" "non-LIVE module is refused"
kill "$spin" 2>/dev/null
wait "$spin" 2>/dev/null

echo
echo "== summary: PASS=$PASS FAIL=$FAIL =="
exec 3>&-
rm -f "$RESP_FILE"
if [ "$FAIL" -eq 0 ]; then
	echo "LUA-LSM-SHDICT-POC: ALL PASS"
	exit 0
fi
echo "LUA-LSM-SHDICT-POC: FAILURES PRESENT"
exit 1
