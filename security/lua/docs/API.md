# API

## Module format

A module is a Lua chunk that returns a table with metadata and hook functions.

Required fields:
- `name` (string)
- `author` (string)
- `description` (string)
- `license` (string)
- `version` (number)

Hook functions are keyed by the LSM hook name (e.g. `file_open`).

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

## Hook return values (int-return hooks)

- `nil` or no return: default value
- `true`: allow (0)
- `false`: deny (-EPERM)
- `false, errno`: deny (-errno)
- `nil, errno`: deny (-errno)

Use `require("errno")` to access errno constants.

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
