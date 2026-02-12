# Observability

## Debug logging

Enable with `CONFIG_SECURITY_LUA_LSM_DEBUG`. Debug logs are on by default and
can be disabled with the kernel cmdline `lua.nodebug`.

Logs are tagged with the current task and function name (see `debug.h`).

## Stats (CONFIG_SECURITY_LUA_LSM_STATS)

### VM + memory stats

```
cat /sys/kernel/security/lua/stats
```

Fields:
- `lvm.nalloc` / `lvm.nfree` / `lvm.nusage`
- `lmem.nalloc` / `lmem.nrealloc` / `lmem.nfree`
- `lmem.total` / `lmem.average` / `lmem.minimum` / `lmem.maximum`
- `kvcache.nalloc` / `kvcache.nfree` / `kvcache.nusage`

### Hook timing stats

```
cat /sys/kernel/security/lua/lsm_funcs
```

Output columns:
- `name`: LSM hook name
- `nlsm`: number of modules implementing the hook
- `count`: invocation count
- `total`: total time (ns)
- `average`: average time (ns)
- `maxtime`: max time (ns)

## Module list

```
cat /sys/kernel/security/lua/modules
```

Shows: name, license, size, number of hooks, load count, shdict count,
kvnode count, and author.
