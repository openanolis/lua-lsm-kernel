# Lua-LSM

Scriptable operating systems with Lua.

Lua-LSM runs LSM hooks inside an embedded Lua VM so you can ship, load, and
update security policy at runtime via securityfs.

```lua
local logo = [==[
 __                                 __       ____
/\ \                               /\ \     /\  _`\   /'\_/`\
\ \ \      __  __     __           \ \ \    \ \,\L\_\/\      \
 \ \ \  __/\ \/\ \  /'__`\   _______\ \ \  __\/_\__ \\ \ \__\ \
  \ \ \L\ \ \ \_\ \/\ \L\.\_/\______\\ \ \L\ \ /\ \L\ \ \ \_/\ \
   \ \____/\ \____/\ \__/\.\_\/______/ \ \____/ \ `\____\ \_\\ \_\
    \/___/  \/___/  \/__/\/_/          \/___/   \/_____/\/_/ \/_/
]==]
```


## Quick start

1) Enable kernel config options:

- `CONFIG_SECURITY_LUA_LSM=y`
- Optional: `CONFIG_SECURITY_LUA_LSM_STATS=y`
- Optional: `CONFIG_SECURITY_LUA_LSM_DEBUG=y`

2) Ensure `lua` is in the active LSM list (CONFIG_LSM or `lsm=` on the kernel
   command line). See `Documentation/security/lsm.rst` for details.

3) Mount securityfs if it is not already mounted:

```
mount -t securityfs securityfs /sys/kernel/security
```

4) Load a module:

```
cat demo.lua > /sys/kernel/security/lua/register
```

5) Verify and unload:

```
cat /sys/kernel/security/lua/modules
echo demo > /sys/kernel/security/lua/unregister
```

## Example module

```lua
local errno = require("errno")

local M = {
  name = "demo",
  author = "example",
  description = "Deny reads of /etc/shadow",
  license = "GPL-2.0",
  version = 1,
}

function M.file_open(file, cred)
  local path = file:path()
  if path and path:match("^/etc/shadow$") then
    return false, errno.EPERM
  end
  return true
end

return M
```

## Docs

- `USAGE.md` - build/enable and runtime management
- `API.md` - module format, hook returns, and core APIs
- `OBSERVABILITY.md` - stats, debug logs, and troubleshooting data
