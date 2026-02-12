# Usage

## Build and enable

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

## Permissions

Loading and unloading modules requires `CAP_MAC_ADMIN`.

## Error handling

- Register/unregister return negative errno on failure.
- Hook return values map to LSM errors; see `docs/API.md`.
