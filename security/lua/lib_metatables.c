// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Core-owned metatable bootstrap for lua-lsm.  Holds the only callers
 * of luaL_newmetatable / createmeta / createmeta3, none of which are
 * exported, so loadable producers cannot create or hijack metatables.
 *
 * Copyright (C) 2026 lua-lsm contributors.
 */

#include <linux/errno.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/lua.h>
#include <linux/lauxlib.h>
#include <linux/lua_lsm_api.h>

#include "auxlib.h"
#include "kvcache.h"
#include "lsm.h"
#include "lua_object.h"

struct lib_meta_creator {
	const char *name;
	void (*create)(lua_State *L,
		       const luaL_Reg *funcs,
		       const luaL_Reg *gc);
};

/* shdict has only a single registry metatable, not the createmeta3 triple. */
static void create_shdict_meta(lua_State *L,
			       const luaL_Reg *funcs,
			       const luaL_Reg *gc)
{
	(void)gc;
	createmeta(L, METH_SHARED_DICT, "shdict", funcs, NULL, 1);
}

/*
 * Hand-written dispatch table: a missing LUA_OBJECTS_LIST entry here
 * fails to link rather than silently skipping a metatable.
 */
#define MC(name) { #name, create_ ## name ## _meta }
static const struct lib_meta_creator lib_meta_creators[] = {
	MC(task),       MC(cred),       MC(userns),     MC(perfevent),
	MC(ipc),        MC(msgmsg),     MC(sock),       MC(ib),
	MC(tundev),     MC(socket),     MC(skb),        MC(sockaddr),
	MC(key),        MC(bdev),       MC(inode),      MC(file),
	MC(superblock), MC(dentry),     MC(binprm),     MC(path),
	MC(fscontext),  MC(vfsmount),   MC(mntidmap),   MC(cap),
	{ "shdict", create_shdict_meta },
};

#undef MC

int lib_metatables_init(lua_State *L)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(lib_meta_creators); i++)
		lib_meta_creators[i].create(L, NULL, NULL);

	return 0;
}

/**
 * lua_api_lib_meta_install - attach method tables to a core-owned metatable
 * @L:        Lua state; metatables must already exist via lib_metatables_init().
 * @name:     metatable identifier from LUA_OBJECTS_LIST.
 * @funcs:    %NULL-terminated methods for the regular metatable, or %NULL.
 * @gc_funcs: %NULL-terminated methods for the gc metatable; installed only
 *            when both @funcs and @gc_funcs are non-%NULL.
 *
 * The gc metatable is created lazily on first install.  Allocation
 * failures longjmp through Lua's allocator, so callers must run inside
 * a pcall frame (the registry install path provides one).
 *
 * Returns 0 on success, -EINVAL on bad arguments, or -ENOENT when @name
 * is not in LUA_OBJECTS_LIST.
 */
int lua_api_lib_meta_install(lua_State *L, const char *name,
			     const luaL_Reg *funcs,
			     const luaL_Reg *gc_funcs)
{
	size_t i;

	if (!L || !name)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(lib_meta_creators); i++) {
		if (!strcmp(lib_meta_creators[i].name, name)) {
			lib_meta_creators[i].create(L, funcs, gc_funcs);
			return 0;
		}
	}
	return -ENOENT;
}
EXPORT_SYMBOL_GPL(lua_api_lib_meta_install);
