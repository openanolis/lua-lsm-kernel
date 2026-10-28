#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Concurrent writers, enumeration readers, hooks, and module teardown.

set -u

BASE=/sys/kernel/security/lua
SHDICT=$BASE/shdict
POLICY=${1:-$(dirname -- "$0")/shdict_stress.lua}
ROUNDS=${ROUNDS:-50}

fail()
{
	echo "FAIL: $1"
	exit 1
}

[ -f "$POLICY" ] || fail "policy $POLICY not found"
cat "$POLICY" > "$BASE/register" || fail "register stress module"

writer()
{
	i=1
	while [ "$i" -le "$ROUNDS" ]; do
		echo "set stress runtime writer_$1 number $i" > "$SHDICT" || exit 1
		echo "set stress runtime text_$1 string value $i" > "$SHDICT" || exit 1
		echo "incr stress runtime counter 1" > "$SHDICT" || exit 1
		i=$((i + 1))
	done
}

reader()
{
	i=1
	while [ "$i" -le "$ROUNDS" ]; do
		"$(dirname -- "$0")/shdict_snapshot" --check || exit 1
		cat /proc/version > /dev/null || exit 1
		i=$((i + 1))
	done
}

writer 1 & writer1=$!
writer 2 & writer2=$!
reader & reader1=$!
reader & reader2=$!

wait "$writer1" || fail "writer 1"
wait "$writer2" || fail "writer 2"
wait "$reader1" || fail "reader 1"
wait "$reader2" || fail "reader 2"

exec 3<>"$SHDICT" || fail "open control file"
printf 'get stress runtime counter\n' >&3 || fail "get counter"
counter=$(cat <&3)
exec 3>&-
[ "$counter" -eq $((ROUNDS * 2)) ] || \
	fail "counter expected $((ROUNDS * 2)), got $counter"

cat "$SHDICT" | grep -Fq "stress runtime counter number $counter" || \
	fail "counter missing from enumeration"

if printf 'stress\n' > "$BASE/unregister" 2>/dev/null; then
	echo "PASS: module unregistered after workers"
else
	echo "PASS: busy unregister safely refused after workers"
fi

# A refused unregister leaves the module in GOING state.  Both GOING and a
# fully removed module must reject subsequent shared-dictionary requests.
if echo 'get stress runtime counter' > "$SHDICT" 2>/dev/null; then
	fail "non-LIVE module accepted request"
fi
echo "PASS: non-LIVE module rejects new requests"
echo "PASS: concurrent writers/readers and lifecycle ($counter updates)"
