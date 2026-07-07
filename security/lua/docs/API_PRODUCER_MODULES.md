# Lua API producer modules

Lua-LSM policy code can load Lua-visible API libraries with
`require()`.  The built-in tree already provides libraries such as
`kernel`, `fs`, `net`, `errno`, `capability`, and `signal`.

New libraries can be added in two ways:

- In-tree: add the producer under `security/lua/` and wire it into the
  kernel `Kconfig`/`Makefile`.
- Out-of-tree: build a normal external GPL kernel module that calls
  `lua_api_lib_register()`.

This document focuses on the out-of-tree case.

## Requirements

The target kernel must be built with:

```text
CONFIG_SECURITY_LUA_LSM=y
CONFIG_MODULES=y
```

If the kernel enables signed API enforcement:

```text
CONFIG_LUA_LSM_REQUIRE_SIGNED_API=y
```

then the producer module must be signed before loading.

Out-of-tree producers must use a GPL-compatible module license because
the Lua-LSM producer ABI is exported with `EXPORT_SYMBOL_GPL()`.

## Example: `time` library

This example adds a `time` library that policy code can use as:

```lua
local time = require("time")
local now = time.ktime_get_ns()
```

Directory layout:

```text
lua-lsm-time/
  Makefile
  lua_time.c
```

`lua_time.c`:

```c
// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/timekeeping.h>
#include <linux/lua.h>
#include <linux/lauxlib.h>
#include <linux/lua_lsm_api.h>

static int time_ktime_get_ns(lua_State *L)
{
	lua_pushinteger(L, ktime_get_ns());
	return 1;
}

static const luaL_Reg time_lib[] = {
	{ "ktime_get_ns", time_ktime_get_ns },
	{ NULL, NULL }
};

static struct lua_api_lib time_desc = {
	.name		= "time",
	.funcs		= time_lib,
	.owner		= THIS_MODULE,
	.abi_version	= LUA_API_LIB_ABI_VERSION,
};

static int __init lua_time_lib_init(void)
{
	int err;

	err = lua_api_lib_register(&time_desc);
	if (err)
		pr_err("lua-lsm: failed to register 'time' library: %d\n", err);
	return err;
}

static void __exit lua_time_lib_exit(void)
{
}

module_init(lua_time_lib_init);
module_exit(lua_time_lib_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("lua-lsm time API library");
```

`Makefile`:

```make
obj-m += lua_time.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
```

Build and load:

```sh
make
insmod lua_time.ko
```

For a different target kernel build tree:

```sh
make KDIR=/path/to/kernel/build
```

## Use from policy code

After `lua_time.ko` registers successfully, existing and future Lua-LSM
policy VMs can use it with `require("time")`.

Example:

```lua
local time = require("time")

return {
	file_open = function(file)
		local now = time.ktime_get_ns()
		return 0
	end,
}
```

## Notes

- The library name in `.name` is the string passed to `require()`.
- The library name must not collide with standard Lua libraries opened
  by the kernel VM: `_G`, `coroutine`, `table`, `string`, or `debug`.
- `funcs` must be a NULL-terminated `luaL_Reg` array.
- `init_table`, when provided, runs after `funcs` are installed with the
  library table on top of the Lua stack.  It must not sleep, pop, or
  replace that table.
- `owner` must be `THIS_MODULE` for loadable producers.
- `abi_version` must be `LUA_API_LIB_ABI_VERSION`.
- A duplicate library name is rejected.
- Build against the same kernel headers/config used by the target
  kernel, or module loading may fail with `invalid module format`.
- If loading fails with `Unknown symbol lua_api_lib_register`, the
  running kernel does not provide the Lua-LSM producer ABI.
