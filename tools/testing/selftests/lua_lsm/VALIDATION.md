# Lua-LSM Task 2 integration validation — 2026-10-16

Submission scope: Task 2 only. The historical RV64 runs below used the
combined integration branch, not the standalone Task 2 branch on unmodified
upstream. Task 1 RISC-V support is separate (PR #33); RV64 KASAN runs also
used the stack-unpoison follow-up in integration commit `aef506b09`. Neither
architecture change is part of this submission. See README prerequisites.

Historical baseline, before the consistent-enumeration extension. The later
2026-10-27 snapshot validation section below supersedes its enumeration
contract; the following performance numbers are NOT results for that change.

Behavioral source revision: `fbd486345` (and the preceding two local commits).
This record and analyzer-help changes do not alter the measured kernel code.
All testing was in disposable RV64 QEMU guests, not on the host kernel.

## Correctness and safety

| Check | Result |
| --- | --- |
| Shared-dictionary PoC checks | 47/47 |
| Boundary, capability and first-creation cases | 8/8 |
| Shared open-file description cases | 5/5 |
| Original parallel update workload | 100 updates, passed |
| Normal kernel lifecycle | 20 full remove/re-register rounds at 1 CPU and at 2 CPUs |
| KASAN + lockdep kernel lifecycle | 10 rounds at 2 CPUs, full suite passed |
| Separate kmemleak profile | empty before/after reports, 10 rounds plus boundary/shared-FD checks |
| Task-scoped allocation fault sweeps | five targets passed with same-task/FD recovery |
| Tracefs diagnostic | 715 balanced request entry/exit intervals; peak overlap 4 |

Fault sweeps consumed 1068 points for cold VM/bridge setup, 15 for string set,
15 for string get, 3 for fresh enumeration and 5 for open. The sweep ends
only after reaching an unconsumed point, with a 4096-point safety bound.
The originally proposed 1024 bound was below the observed cold-VM allocation
count and was increased; reaching a bound was never accepted as success.

Initial failing runs were retained. Task 2 findings included
allocation/GC under task_call_func raw locks and loss of ENOMEM when
rethrowing a protected string conversion error.
These were fixed and the final profiles rerun. Same-key deletion now checks
tree membership under the dictionary lock to prevent double removal.

The lifecycle workload synchronizes withdrawal-phase participation before
calling unregister. Workers remain active across teardown, but the counters
do not assert every worker crossed a particular kernel instruction during
that syscall. EBUSY is not success: the fixture must disappear before reuse.

## Controlled performance comparison

GCC 13.3 / QEMU 8.2.2 / RV64 TCG multi-thread / 2 vCPU / 1 GiB. A and B use
the same normal config, fixed kernel release/build timestamp, initramfs and
benchmark binaries. A is the safe final code with only management bridge
and enumeration protection changed back to modules_mutex; B uses SRCU.
This is not a comparison against the removed typed C API.

Boot order: A1, B1, B2, A2, A3, B3. Scalar tests: 25 scenarios x 5 repeats x
10000 requests per boot, 7,500,000 measured requests across all six boots.
Separate enum/mixed tests add 420,000 measured operations. All 930 CSV rows
reported zero errors and passed response/counter checks; warmups are extra.
Tracing was disabled. No samples or slow repetitions were removed.

Each percentage below is the median of three paired throughput changes;
each pair compares medians of its five repetitions.

| Scenario | Paired throughput change |
| --- | ---: |
| Scalar set/get/incr, 1 thread | -1.51% to -4.06% across the five workloads |
| Scalar workloads, 2/4 threads | +52.15% to +64.56% across the 20 scenarios |
| Enumeration, 1 thread | -0.81% |
| Enumeration, 2 threads | +68.36% |
| Enumeration, 4 threads | +65.83% |
| Mixed, 1 thread | +4.04% |
| Mixed, 2 threads | +63.86% |
| Mixed, 4 threads | +60.35% |

No scenario regressed more than 10% in all three pairs. One single-thread
mixed pair declined 13.98%; it is retained, not discarded. Tail latencies
and pair-to-pair variation must be inspected in the raw report. Results
support improved multi-thread throughput for these emulated workloads,
not a blanket speedup: scalar single-thread throughput is slightly lower.
They do not establish real-hardware performance or isolated Lua bridge cost.

Analyze complete logs using:

```sh
python3 analyze_bench.py /absolute/output A1.log B1.log A2.log B2.log A3.log B3.log
```

The analyzer rejects missing completion markers, wrong sample counts,
duplicate records and nonzero errors, preserves raw CSV, and fails the
agreed repeated-regression threshold. See README for build/run commands,
config fragments and the protocol/ownership/permission contract.

## Limits

This is a tested development interface, not a stable production ABI.
At this baseline enumeration was not globally atomic. Shared FD write/read is not an automatic
transaction, and errors do not imply rollback. Allocation-fault and
kmemleak profiles are separate; the empty leak report is not proof for every
fault/interleaving combination. No KCSAN, exhaustive instruction-level
schedule exploration, real-board validation or fine-grained authorization
claim is made. No upstream acceptance or PR merge is implied.

## Consistent enumeration — 2026-10-27

Behavioral source: `b93381247a4177e2f7c6031546a89580aa29123b`.
Normal, KASAN/lockdep and separate kmemleak images were rebuilt from that
committed source. This section supersedes the baseline enumeration limit,
not its remaining shared-FD, authorization, rollback or hardware limits.

Named dictionary changes from both management and Lua hooks, dictionary
publication, and module LIVE/GOING transitions participate in a generation
plus overlapping-writer protocol. Readers capture node/string references
and scalar values, validate the global window, then format immutable copies.
Only compact tagged values are retained, not entire node/lock structures.
SRCU still protects module/dictionary lifetime during capture and formatting.
After eight conflicting attempts read returns EAGAIN without output; partial
reads of an accepted per-open snapshot are unaffected by later mutations.

| Check | Result |
| --- | --- |
| Normal RV64, 1 CPU | full suite, 20 complete unregister/re-register rounds |
| Normal RV64, 2 CPUs | full suite, 20 rounds |
| Generic KASAN + lockdep, 2 CPUs | full suite, 10 rounds; no unexpected diagnostics |
| New snapshot regression | 3/3 in all profiles; partial-read retention, cross-module counters, Lua-hook counters across dictionaries |
| Allocation failures | all 5 targets recovered; consumed points 1066/15/15/4/5 |
| Separate kmemleak | empty before/after reports; includes new snapshot test and 10 lifecycle rounds |
| Build/style | static selftests with -Werror, three kernel configs, git checks passed; kernel patch checkpatch 0 errors/warnings |

The new regression workload also ran against the old `e59a991df` image.
It detected impossible first/second counter pairs in both the management
and Lua-hook paths (for example 14/15 and 16/17). The final image passed the
same test. Debug testing actually returned EAGAIN, checked that the user
buffer was untouched, and recovered after updates stopped. Fault testing
now seeds a second named dictionary so later capture-allocation failure
also exercises cleanup after earlier values have acquired references.
These are workload tests, not exhaustive instruction-interleaving proofs.

### Enumeration integration performance regression

This is a NEW comparison: A = `e59a991df` with weak enumeration and SRCU;
B = `b93381247` with consistent snapshots and SRCU. It does not compare
mutex against SRCU, nor C APIs against Lua. Normal config bytes, toolchain,
test binaries, rootfs, QEMU parameters and tracing-off settings matched.
Kernel release/build metadata differs across commits, so this is an
integration regression check, not an isolated instruction-cost experiment.

Three pairs ran in A1-B1, B2-A2, A3-B3 order with five repetitions per
scenario: 930 raw rows, 7,500,000 scalar requests and 420,000 separate
enumeration/mixed operations, all without errors. Medians of the three
paired throughput changes are:

| Workload | Change |
| --- | ---: |
| Scalar scenarios, across 1/2/4 threads | -4.99% to +0.68% |
| Enumeration, 1 / 2 / 4 threads | +2.63% / -0.88% / -1.35% |
| Mixed, 1 / 2 / 4 threads | +3.71% / -3.40% / -4.31% |

No scenario declined over 10% in all three pairs. Caller backoff/retries
were included in latency; raw records and tail latencies were preserved.
Do not infer universal speedups or real-hardware performance from the small
positive changes. The purpose is a stronger snapshot contract with measured
cost, not a claim that consistency is free. Earlier experimental builds
kept formatting inside the validation window or used oversized records;
their slower results were retained separately, not mixed into final data.

Logs/images/configs and performance raw.csv/summary.json are retained in the
local `verify-enum.QsqB32` validation directory. Reproduce via the README's
private initramfs workflow and the existing host runner. The permission and
shared-FD transaction contracts have not changed.
