# API

## Module format

A module is a Lua chunk that returns a table with metadata and hook functions.

Required fields:
- `name` (string)
- `author` (string)
- `description` (string)
- `license` (string)
- `version` (number)

Hook functions are keyed by the supported LSM hook name (e.g. `file_open`).
Use `kernel.lsm_funcs()` to enumerate the supported set. Lua-LSM does not
expose unsupported hooks through its module APIs or observability output;
the current unsupported set includes `getprocattr`, `setprocattr`, and
`lsmprop_to_secctx`.

Example:

```lua
local errno = require("errno")

return {
  name = "demo",
  author = "example",
  description = "Example module",
  license = "GPL-2.0",
  version = 1,

  file_open = function(file, cred)
    local path = file:path()
    if path and path:match("^/etc/shadow$") then
      return false, errno.EPERM
    end
    return true
  end,
}
```

## Hook return values (errno hooks)

- `nil` or no return: default value
- `true`: allow (0)
- `false`: deny (-EPERM)
- `false, errno`: deny (-errno)
- `nil, errno`: deny (-errno)

Use `require("errno")` to access errno constants.

Hook results and execution failures follow the kernel caller's contract:

| Hooks | Lua results | Uncaught execution failure |
| --- | --- | --- |
| Errno hooks, including `file_open` | As above | `-EIO` / `-ENOMEM` |
| `inode_xattr_skipcap` | Boolean: whether to omit the capability check | 0: retain the capability check |
| `ismaclabel` | Boolean: whether the name is a MAC label | 1: exclude the attribute from generic xattr listings |
| `audit_rule_known` | Boolean: whether an audit field is known | 0: no known field |
| `inode_need_killpriv`, `audit_rule_match` | Boolean, or `false/nil, errno` | `-EIO` / `-ENOMEM` |
| `capget`, `inode_init_security`, `inode_getsecurity`, `inode_listsecurity` | Capability, xattr or length results; existing boolean/errno forms also apply | `-EIO` / `-ENOMEM` |
| Void hooks | Ignored | Stop dispatch and log; cannot reject the operation |

`-EIO` denotes a Lua execution error; `-ENOMEM` denotes Lua allocation failure
or an unavailable VM. Mapping uses the Lua status, not the error object.
For `vm_enough_memory`, a negative result removes the privileged allocation
exemption; the kernel's memory check decides whether to allow the allocation.
`fs_context_parse_param` and `task_prctl` return execution errors rather than
their normal "not handled" defaults.

## Execution failures and recovery

An uncaught Lua error stops the current hook's module walk; later modules
cannot overwrite the failure. This
covers lazy loading, hook lookup, task/environment setup, argument construction,
callbacks and result conversion. Missing or non-function registered hooks also
fail. Failed lazy loads are not cached and may be retried. Logs are rate-limited
and identify the hook; the policy's `debug.traceback` is not called.

`pcall`, `xpcall` and `coroutine.resume` retain ordinary Lua semantics: policies
may catch errors and return an allow decision. Rethrow coroutine errors to fail
the outer dispatch. There is no whole-policy time or instruction budget.

On success and failure, dispatch restores the Lua stack, thread/current-policy
environments and C debug-hook settings. Main-thread Lua debug hooks and their
callback references are cleared on exit. Policy/shared-dictionary writes,
kernel side effects and coroutine-local state are not rolled back.

Kernel resources acquired by policies or C helpers require their own cleanup.
Pair `kernel.rcu_read_lock()` with `kernel.rcu_read_unlock()`; catch errors
inside the critical section, unlock, then rethrow. Internal registry mutation,
task-VM reentry and NMI/hardirq invocation remain unsupported.

## Listing hook names

From Lua:

```lua
local kernel = require("kernel")
local hooks = kernel.lsm_funcs()
```

From userspace (if stats enabled):

```
cat /sys/kernel/security/lua/lsm_funcs
```

Both interfaces list only hooks that Lua-LSM actually supports and registers.

## Built-in libraries

Lua-LSM preloads these libraries (use `require()`):

- `kernel`: task, cred, printk, time, and helper utilities
- `fs`: file/dentry/inode/path helpers
- `net`: socket and address helpers
- `errno`: errno constants + `errname()`
- `capability`: kernel capability helpers
- `signal`: signal helpers

## Common object methods (examples)

Task (`task`):
- `task:pids()` -> pid, tgid
- `task:comm()` -> comm string
- `task:cred()` -> cred object

File (`file`):
- `file:path()` -> path string or nil, err
- `file:inode()` -> inode object

Inode (`inode`):
- `inode:ino()` -> inode number
- `inode:mode()` -> table or boolean checks
- `inode:ids()` -> uid, gid

Dentry (`dentry`):
- `dentry:path()` -> path string

For a full list, see the method tables in `lua_kernel.c` and `lua_fs.c`.
