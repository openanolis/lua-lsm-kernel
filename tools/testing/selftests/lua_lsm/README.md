# Lua-LSM shared-dictionary text interface PoC

This PoC exposes the existing Lua shared-dictionary API through
`/sys/kernel/security/lua/shdict`. It does not define a second typed kvcache
API or require a dedicated userspace client.

The end-to-end path is:

```text
userspace text command -> securityfs parser -> Lua call bridge ->
shared.<dict>:set/get/incr -> kvcache -> Lua LSM hook
```

## Scope and RV64 validation prerequisites

This submission contains Task 2 only: shared-dictionary strings, userspace
control, enumeration and their tests. It adds no architecture setjmp/longjmp
implementation or Task 1 recovery tests. RISC-V architecture support is
submitted separately in openanolis/lua-lsm-kernel PR #33.

The recorded RV64 results were obtained on the combined integration branch
`ospp/final-submission` (through `e05ced299`), including the separate Task 1
implementation and the KASAN stack-unpoison follow-up in `aef506b09`. Apply
those architecture prerequisites when reproducing RV64 debug validation;
they are deliberately not included in this Task 2 diff. Other existing
HAS_LUA-capable architectures do not require the RISC-V support patch. The
Task 2 production code matches the tested integration revision, except for
equivalent securityfs allocation/parser style cleanups for submission.

## Request format

Each write contains one line-oriented request of at most 4096 bytes:

```text
set <module> <dict> <key> <boolean|number|string|hex> <value>
get <module> <dict> <key>
delete <module> <dict> <key>
incr <module> <dict> <key> [delta]
```

For normal administration, change to the Lua-LSM securityfs directory and
write readable commands directly:

```sh
cd /sys/kernel/security/lua
echo 'set demo runtime blocked_path string /tmp/blocked' > shdict
cat shdict
grep '^demo runtime blocked_path ' shdict
echo 'delete demo runtime blocked_path' > shdict
```

A fresh read enumerates every key in every named dictionary belonging to a
LIVE module. Each line has this format:

```text
<module> <dict> <key> <type> <escaped-value>
```

Strings use readable text directly. Backslashes and non-printable bytes are
escaped as `\xNN` in enumeration output. The `hex` input type is available for
binary-safe strings such as an embedded NUL:

```sh
echo 'set demo runtime binary_key hex 610062' > shdict
```

Programs that need one exact result can keep the file descriptor open and
read the result of `set`, `get`, `delete`, or `incr` from that same open file.
This keeps request results per-open instead of exposing a racy global
"last-result" slot.

`dup()` and `fork()` share an open-file description, including its response
and read cursor. A per-open mutex protects buffer replacement, lazy snapshot
creation, and cursor movement for each read/write syscall. It is not held
between syscalls: another writer may replace a response before its original
requester reads it. Use separate opens for independent clients, or serialize
the complete write-and-read transaction in userspace. An interrupted lock
wait is restartable; every operation still checks the calling task's capability.
The interface uses `stream_open()`: it has no file offsets or seek/pread/pwrite
protocol. Shared-FD reads and writes can enter concurrently, with the context
mutex providing protection instead of relying on VFS file-position locking.

`get` on a missing key fails at write time with `ENOENT`. An existing empty
string is successful and produces a zero-byte response on the same file
descriptor. Errors returned by the shared method are propagated as errno;
for example, incrementing a boolean value fails with `EINVAL` and leaves
the value unchanged.

The file mode is `0600`; open and every read/write also require
`CAP_MAC_ADMIN`. The parser never evaluates userspace-provided Lua source.
The bridge constructs a restricted module environment internally and invokes
the existing shared-dictionary methods by using the Lua C API.

## Reproduction

```sh
make -C /home/maomao-wang/work/lua-lsm/kernel \
  O=/home/maomao-wang/work/lua-lsm/out-riscv \
  ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- -j4 Image

/home/maomao-wang/work/lua-lsm/scripts/run-qemu.sh
```

`shdict_poc.sh` verifies:

1. boolean, number, string, embedded-NUL, overwrite, delete, and `incr`
2. dictionary creation on first `shared.<name>` access
3. enumeration across named dictionaries with safe value escaping
4. live updates to `blocked_path` changing a real `file_open` decision
5. malformed commands, unknown modules, unsupported types, and input limits
6. open-time and per-operation `CAP_MAC_ADMIN` enforcement
7. repeated requests without Lua stack contamination
8. rejection of requests after the target module leaves LIVE state

The boot log must contain no unexpected Lua traceback, BUG, WARNING, or
reference-count assertion.

`shdict_stress.sh` additionally runs two writers and two enumeration/hook
readers in parallel, verifies the final atomic counter, and unregisters the
module after all workers exit.

## Concurrent unregister test

`shdict_lifecycle.sh` runs a separate fixture named `lifecycle`. Its C test
workload generator is not a userspace administration client. Build it for
RV64 before copying the scripts, fixture and binary into the QEMU rootfs:

```sh
make -C tools/testing/selftests/lua_lsm \
  CROSS_COMPILE=riscv64-linux-gnu- USERLDFLAGS=-static USERCFLAGS=-Werror
```

Inside QEMU, with the files installed together under `/tests`:

```sh
sh /tests/shdict_lifecycle.sh
# Optional longer run; the default is three complete register/remove cycles.
LIFECYCLE_ROUNDS=5 sh /tests/shdict_lifecycle.sh
```

Two writers, one getter, one fresh-snapshot enumerator and one file-open
worker each use their own file descriptors. Before unregister starts, every
worker must finish at least 100 operations and the hook must deny its test
file. Workers remain running throughout unregister; their withdrawal-phase
attempt counts must be nonzero. This is workload overlap, not a claim that
every exact kernel instruction interleaving has been forced.

After unregister returns, every worker must finish another 100 checks:
new dictionary requests fail with `ESHUTDOWN` or `ENOENT`, fresh enumeration
omits the module, and the removed policy no longer denies the test file.
The test compares the module listing with the returned errno to distinguish
a retained non-LIVE module from a removed module. It does not require old
per-open response buffers or previously prepared snapshots to be erased.
Both writers now race on one `churn` key, repeatedly replacing embedded-NUL
and ordinary strings with numbers/booleans and deleting the key. The getter
accepts only complete known values or a legitimately deleted key; the hook
checks both a new value and its retained Lua copy from the previous open.
A saved binary get response and a partially read enumeration snapshot are
kept open across churn and complete unregister, and must remain readable
after the module is fully removed. These buffers own copies, not dictionary
node pointers. Fresh requests must still fail after removal.

`EBUSY` alone is not a pass. It can leave a ZOMBIE module while task VMs
still hold references. After joining workers, the test retries unregister,
requires the module to disappear from `modules`, and requires `ENOENT` on
a subsequent get before registering the fixture again. Unexpected errno,
worker failure, stalled progress, or new kernel diagnostics fails the test.

The wrapper checks only the new dmesg lines, so intentional tracebacks from
the separate Lua recovery test do not contaminate this test's result. It
fails if the log wraps. It does not replace KASAN, leak accounting, or
comprehensive memory-safety testing.

## Shared open-file description test

Build and install `shdict_shared_fd` with the other selftest helpers, then run:

```sh
sh /tests/shdict_shared_fd.sh
```

The private `sharedfd` fixture has two 2048-byte values. Five checks cover
dup/fork cursor and response sharing, separate-open isolation, 20 fresh
concurrent lazy snapshots (exact total bytes and byte histograms), two writers
replacing responses while two readers consume partial chunks, complete
transactions serialized by a userspace mutex, and EFAULT/invalid-request
recovery. Four workers use duplicated descriptors referencing the same open.
No response ownership across a write/read pair is promised without client
serialization. The test requires actual reader progress, checks the scalar
chunks for torn data, removes its fixture, and checks new kernel diagnostics.
Its alarm plus an external QEMU timeout bounds stuck or deadlocked tests.

## Optional performance baseline

`shdict_bench` is an optional C workload generator built by the same command
as `shdict_lifecycle`; it is not a production administration client and is
not part of the default functional test run. Run it in a fresh QEMU boot,
before other tests register policies:

```sh
/tests/shdict_bench 10000 5 500
# Arguments: measured requests per group, repetitions, warmups per thread.
```

It registers four private `perfbench_<id>` policies, creates a `runtime`
dictionary with four string keys and one counter in each, and removes only
those policies afterwards. The five workloads are 32/256-byte string
set/get and numeric incr. Each workload runs with 1/2/4 independent-FD
threads; 2/4 threads test both one shared module and separate modules.
The default measures 25 groups five times: 1,250,000 requests in total,
plus 162,500 warmup requests. Case order rotates between repetitions.

Every result and the final incr counters are checked. CSV includes group
throughput, mean request latency, P50/P95/P99 and maximum latency. Request
latency covers `write()` and all response reads through EOF, not only the
Lua bridge. FD open, initialization, warmup, thread creation, sorting and
cleanup are excluded. Per-response validation and loop/clock overhead are
included in group throughput; validation is outside request latency.
Clock-pair overhead is reported separately and is not subtracted.

Fix the kernel/config, QEMU version, TCG mode, vCPU/RAM and host load when
comparing versions. QEMU results are relative baselines, not real-board
performance or measurements of the bridge in isolation. This benchmark
does not measure enumeration, hook throughput, unregister races or shared-FD
concurrency; use the separate functional/lifecycle tests for those cases.

## Implementation boundary

- The string extension remains inside the original kvcache Lua path. String
  payloads are copied, length-aware, immutable, and reference-counted.
- securityfs parses only the public text grammar. It does not directly insert,
  overwrite, or remove kvcache nodes.
- The bridge pushes structured arguments onto the Lua stack and calls the
  original `shared` methods; it does not compile user-supplied Lua code.
- The target module and its dictionaries remain protected by `modules_ss`
  SRCU for the complete call. The VM is acquired before entering SRCU. A
  request admitted while LIVE may finish after LIVE -> GOING; unregister
  waits for the reader before freeing dictionaries. Neither the bridge nor
  enumeration acquires `modules_mutex` inside the read-side section.
  Registration/unregistration remain serialized by that mutex.
- A `lua_cpcall()` boundary includes environment construction, argument
  preparation, method invocation and response conversion. String get uses a
  protected conversion and drops C snapshot references before reporting OOM.
  Initial VM closure construction is protected as well. Errors cannot skip
  the outer C cleanup of the stack, SRCU and VM reference.
- The per-open mutex protects only that open's response. Tree/node rwlocks
  and string/node references still protect data shared by independent opens
  and hooks. Removing a key checks membership under the tree write lock so
  simultaneous deleters cannot remove/drop the tree reference twice.
- Module removal from an idle task VM reuses an existing registry-table key;
  it does not allocate or collect Lua garbage under `task_call_func()` raw
  scheduler locks. Normal VM collection/destruction reclaims unreachable
  module tables later.
- The interface remains a development PoC, not a stable userspace ABI.

## Permission and consistency decisions

The intended operator is a host administrator. Both reading and writing
require `CAP_MAC_ADMIN` in `init_user_ns`, in addition to DAC permission for
the root-owned mode-0600 file. Reads are privileged because policy data may
be sensitive. Capability checks occur at open and each operation, so a
passed/inherited FD does not grant the recipient authority. User-namespace
root is not host administration. Per-module delegation and unprivileged
read access are deliberately not implemented. This uses the project's
existing capability helper, including its kernel-thread treatment.

The maximum write is 4096 bytes including framing/newline. Scalar results
have a 4096-byte limit; enumeration has a 64-KiB buffer and returns E2BIG
instead of a successful partial snapshot. Empty dictionaries do not add
placeholder lines; `modules` is the separate module-listing interface.
Successful enumeration is a point-in-time snapshot of all exported rows.
A short IRQ-safe spinlock protects a global generation and active-writer
count, not the traversal or Lua execution. Named-dictionary insertion,
replacement, deletion and incr participate in both management and Lua-hook
paths. Dictionary publication and module LIVE/GOING transitions participate
as well. Object-property caches are not exported and do not invalidate a
snapshot. Existing SRCU, tree/node locks and references remain necessary
for memory safety; version validation alone does not replace them.

The reader first captures node and immutable-value references, then validates
the generation BEFORE formatting the text. Later updates do not invalidate
these retained copies, so formatting is outside the conflict window. Capture
storage has a row-count budget derived from the output-buffer size; it cannot
grow without bound with the number of dictionaries/keys.

The reader accepts an attempt only if no writer was active at either end
and the generation did not change. Otherwise it discards the attempt and
retries, at most eight attempts per read syscall. Sustained writes can cause
EAGAIN, with zero output bytes; retry the read (the same FD is valid) after
backoff. Allocation/size errors also expose no partial output. Once a
snapshot has been prepared successfully, partial reads on that open consume
the same copied bytes despite later updates or module removal. This is not
a multi-command update transaction or a guarantee that the data is still
current when read returns. lightuserdata addresses remain hidden.

`shdict_snapshot.sh` checks cached partial reads across delete/dictionary
creation, cross-module ordered counters, and counters updated from a Lua
inode_mkdir hook across two dictionaries. The invariant is first >= second
and first - second <= 1: a mixed traversal can violate it. EAGAIN must not
alter the user buffer, all successful snapshots must satisfy the invariant,
and fresh reads must recover once writers stop. The helper's `--check` mode
is used only by the shell stress test to perform bounded EAGAIN retries.
Lifecycle and management benchmark readers also retry with a bounded backoff;
the benchmark reports caller retries and includes them in measured latency.

Consistency trades availability and throughput for a stronger read contract:
large snapshots may be refused repeatedly during continuous updates. The
generation lock introduces short shared bookkeeping on named writes, but no
global mutex is held while traversing dictionaries, formatting output or
running Lua. The earlier performance results describe the pre-snapshot
revision and must not be reused as measurements of this change.

An error does not guarantee rollback. A dictionary update can have committed
before response conversion fails. Requests entering parsing replace the
per-open response; early capability/length rejection does not promise to
erase the previous response. Never infer write success from a later read
without checking the write's return value. Zero-length reads perform no
snapshot allocation and do not move the cursor, but still check capability.

## Final validation profiles

The additional C programs are test workload generators, not administration
clients. `shdict_boundary.sh` covers DAC/capability separation, inherited-FD
read and write checks, user namespace root, exact length boundaries,
concurrent first creation/atomic increments, same-key set/delete and
enumeration overflow/recovery.

`shdict_fault` is opt-in and **must only run in a disposable QEMU guest**.
It arms `/proc/self/fail-nth` around one target operation at a time, records
whether a failure was actually consumed, disables injection and verifies
recovery in the same task/FD. Cold VM setup, string set/get, lazy enumeration
and open allocation are swept until the first allocation beyond the request,
with a hard limit of 4096 points. Failed allocation can be internally
recovered, so injected requests need not all return ENOMEM. Lack of the
required controls, zero injected failures or reaching the cap is failure,
not PASS. `lua.lvm_pool_max=0` is required for cold-VM testing.

Use `config.debug` on top of the saved normal config for Generic KASAN,
lockdep, atomic-sleep diagnostics, task-scoped allocation faults and kprobe
trace events. Use `config.kmemleak` separately for leak checking; tracking
metadata must not contaminate the allocation-fault sweep or performance.
`shdict_kmemleak.sh` records before/after reports and requires an empty final
report after fixture cleanup and two scans. Disable VM pooling for this run.

`shdict_manage_bench` separately measures enumeration and mixed workloads
(enum/get/set/incr), with independent FDs at 1/2/4 threads. Fresh enum includes
open and close; mixed responses and final counters are checked. Default is
1000 operations per thread, five repetitions. These CSV records are separate
from `shdict_bench` scalar latency. `shdict_trace.sh` uses kprobe/kretprobe
events in tracefs for entry/exit timestamps; tracing is disabled during all
performance comparisons. This works without GCC function-graph support.

### Reproduce without changing the demo image

Run the following on the Linux development machine. Set `kernel`, `run`,
`base_root`, and `config` to absolute paths; `base_root` is an existing
BusyBox initramfs tree, not its compressed archive. Save the source commit
and actual merged config with the results.

```sh
kernel=/home/maomao-wang/work/lua-lsm/kernel
run=$(mktemp -d /home/maomao-wang/work/lua-lsm/verify-final.XXXXXX)
# Supply the saved normal config and an existing BusyBox rootfs tree:
config=/absolute/path/to/config-normal
base_root=/absolute/path/to/busybox-root
mkdir "$run/out"
cp "$config" "$run/out/.config"
make -C "$kernel" O="$run/out" ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- olddefconfig
make -C "$kernel" O="$run/out" ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- -j4 Image
sudo cp -a "$base_root" "$run/root"
make -C "$kernel/tools/testing/selftests/lua_lsm" CROSS_COMPILE=riscv64-linux-gnu- \
  USERLDFLAGS=-static USERCFLAGS=-Werror install INSTALL_PATH="$run/root/tests"
cp "$kernel/tools/testing/selftests/lua_lsm/qemu_init.sh" "$run/root/init"
chmod +x "$run/root/init"
(cd "$run/root" && sudo find . -print0 | sudo cpio --null -o --format=newc) \
  | gzip -9 > "$run/rootfs.cpio.gz"
sh "$kernel/tools/testing/selftests/lua_lsm/run_qemu.sh" \
  "$run/out/arch/riscv/boot/Image" "$run/rootfs.cpio.gz" "$run/full.log" full 2 20
```

For a debug or leak build, use a different output directory and merge the
corresponding fragment before `olddefconfig`:

```sh
ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- \
  "$kernel/scripts/kconfig/merge_config.sh" -m -O "$run/out" \
  "$config" "$kernel/tools/testing/selftests/lua_lsm/config.debug"
```

Then build normally and run with `QEMU_MEMORY=2G`; modes are `full` (debug
rounds 10), `fault`, `kmemleak`, or `trace`. The host runner checks both QEMU
status and the guest success marker and rejects unexpected kernel
diagnostics. Missing features and timeouts are not success. Keep intentional
Lua-error tests separate from assertions about unexpected Lua tracebacks.
Performance mode is `perf`, uses the normal kernel, and runs both benchmark
programs; do three A/B pairs in A-B, B-A, A-B order with identical config and
test binaries. Keep all raw logs, CSV, configuration and image checksums.
