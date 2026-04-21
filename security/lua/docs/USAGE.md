# Usage

## Build and enable

- Enable `CONFIG_LUA`.
- Enable `CONFIG_SECURITY_LUA_LSM`.
- Include `lua` in the LSM order (CONFIG_LSM or kernel cmdline `lsm=`).
- Optional:
  - `CONFIG_SECURITY_LUA_LSM_STATS` for stats files
  - `CONFIG_SECURITY_LUA_LSM_DEBUG` for debug logging

## Runtime control (securityfs)

Mount securityfs (if needed):

```
mount -t securityfs securityfs /sys/kernel/security
```

Load a module:

```
cat policy.lua > /sys/kernel/security/lua/register
```

Unload a module:

```
echo policy > /sys/kernel/security/lua/unregister
```

List modules:

```
cat /sys/kernel/security/lua/modules
```

Check version:

```
cat /sys/kernel/security/lua/version
```

## Boot-time tuning

The per-CPU Lua VM pool size is controlled by the kernel command line
parameter `lua.lvm_pool_max=`. The default is `8`.

Examples:

```
lua.lvm_pool_max=64
lua.lvm_pool_max=0
```

Notes:

- `0` disables returning Lua VMs to the per-CPU pool.
- The current implementation accepts decimal values in the range `0..256`.
- This is a boot-time setting only; there is no runtime knob in securityfs.

## Permissions

Loading and unloading modules requires `CAP_MAC_ADMIN`.

## Error handling

- Register/unregister return negative errno on failure.
- Hook return values map to LSM errors; see `docs/API.md`.
