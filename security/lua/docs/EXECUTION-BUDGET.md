# Execution budgets for policy authors

Every live module receives a fresh execution budget when it handles a hook.
The deadline starts before looking up the module in the VM, so the first lazy
load, module initialization, hook lookup, environment and argument setup,
callback and result conversion share the same budget. Another module receives
its own deadline. A failure stops the hook's module walk.

The clock is `ktime_get_ns()` (monotonic wall time). Time spent descheduled,
in interrupts, allocating, collecting garbage or inside C helpers counts;
resuming execution does not replenish the budget. This is a latency constraint,
not a fixed number of useful instructions or CPU time.

| Entry context | Default per module and hook |
| --- | --- |
| Normal task | 20 ms |
| Softirq, preemption disabled, interrupts disabled, or preemptible RCU read section | 2 ms |

The dispatcher selects the limit when entering each module. Task context alone
does not imply the larger limit. The mechanism never sleeps or schedules to
enforce a deadline. NMI/hardirq invocation and task-VM reentry remain unsupported.
Builds without preemption counts conservatively use the shorter limit for all
contexts because they cannot identify every preemption-disabled region.
These are source defaults, with no Lua setter. They were selected using finite
kernel guest workloads, including cold loading; they are not a compatibility
promise for arbitrary policies or a deployment latency target.

The interpreter checks the deadline every 256 bytecode dispatches using a
counter shared by the whole VM, independently of `debug.sethook`. VM entry,
C returns, all VM exits and the module's final exit also check time.
Reaching the deadline is a timeout (`now >= deadline`). Callbacks, old and new
coroutines, yielding, changing debug hooks and starting a protected call cannot
reset either the deadline or the shared counter. Lua debug callbacks and error
handlers execute under the same independent interpreter checks.

## Fatal timeouts and ordinary errors

Ordinary Lua errors keep their existing semantics. This remains valid:

```lua
local ok, value = pcall(function() return string.byte({}) end)
assert(not ok) -- ordinary argument error
return true
```

A timeout cannot be converted into success:

```lua
pcall(function() while true do end end)
return true -- unreachable after a timeout
```

`xpcall` error handlers do not handle a timeout. A handler already running when
the deadline expires is stopped as well. `coroutine.resume` cannot deliver a
timeout back to Lua as an ordinary `false, error` result. Internally, protected
frames still unwind so the VM can restore its state; the expired flag remains
set until the trusted dispatcher exits. Timeout propagation allocates no error
string and does not depend on an error object's contents.

Timeouts use Lua status `LUA_ERRTIME` and the existing hook failure mapping:
errno/BOOLERR/special output hooks return `-EIO`; pure bool hooks use their
predicate-specific failure value; void hooks stop dispatch and log but cannot
reject an operation. See [API](API.md#hook-return-values-errno-hooks). An expired
deadline takes precedence over another error observed at the dispatch exit.

## Recovery and policy structure

The dispatcher restores its stack, environments, C debug-hook settings and VM
ownership, and runs the existing postpone/SRCU cleanup. It clears the deadline
even after an ordinary error, so the next hook gets a fresh budget. A module's
deadline remains active through protected C-frame completion, including return
hooks and GC; it ends when entering the next module or leaving the protected
dispatch. Main-thread
Lua debug hooks and callback references are cleared before each module's
deadline ends, including hooks armed by the policy's own return event. They
cannot run on the dispatcher's later C return or affect the next module.
Allocated `inode_getsecurity` output stays owned by the dispatcher until all
protected completion checks succeed; failures free it and leave the caller's
buffer unchanged. Length-only queries do not allocate output.
A coroutine that errored remains
errored; a yielded coroutine can be resumed by a later invocation under that
invocation's new budget.

Policy data, shared dictionaries, kernel side effects and coroutine-local
state are not rolled back. Do not rely on a Lua error handler to release kernel
resources after a timeout. In particular, explicit `kernel.rcu_read_lock()` /
`kernel.rcu_read_unlock()` pairs spanning Lua execution cannot provide safe
cleanup for fatal deadlines. Prefer C helpers that own and release their
resources within a single call.

Keep initialization small: a module that loaded at registration is still
initialized separately on its first invocation in each VM. Avoid large rule
generation in atomic hooks; precompute compact data when preparing the policy.
Bound loops and input sizes, keep callbacks short, and account for cold loading
when validating normal and atomic hook paths.

## Enforcement boundary

This is cooperative enforcement at safe execution checkpoints. A C helper,
GC phase, parser, string operation or other C-only region can run beyond the
deadline before the next check. No timer interrupts or longjmps out of an
arbitrary C stack are used. Consequently, the configured limit is not a hard
upper bound on hook wall time, interrupt latency, C stack use or memory use.
The independent string-work PR is not included in this implementation.

Policy registration/compilation, VM creation before dispatch and VM teardown
are outside the per-hook module budget. Internal registry mutation is outside
the policy API contract. Existing registration-writer OOM and architecture
setjmp/longjmp limitations are unchanged. Measure complete hook latency on the
target architecture and configuration; guest measurements do not establish
native performance on other systems.
