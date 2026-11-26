/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#define pr_fmt(fmt)	"lua-lsm: " fmt

#include "debug.h"
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/kstrtox.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/compiler.h>
#include <linux/cpu.h>
#include <linux/rwlock.h>
#include <linux/cred.h>
#include <linux/percpu.h>
#include <linux/syscalls.h>	/* for __MAP */
#include <linux/timekeeping.h>	/* for ktime_get */
#include <linux/lsm_hooks.h>
#include <uapi/linux/lsm.h>
#include <linux/lua.h>
#include <linux/lualib.h>
#include <linux/lauxlib.h>
#include <linux/lockdep.h>
#include <linux/srcu.h>
#include "lsm.h"
#include "lua_object.h"
#include "lsm_defs.h"

/********************************** sandbox **********************************/

static struct lua_lsm_module_shdict *
lua_lsm_module_find_shdict(struct lua_lsm_module *module, const char *name)
{
	struct lua_lsm_module_shdict *shdict;

	list_for_each_entry(shdict, &module->shdicts, list) {
		if (strcmp(shdict->name, name) == 0)
			return shdict;
	}
	return NULL;
}

static struct lua_lsm_module_shdict *
lua_lsm_module_get_shdict(struct lua_lsm_module *module, const char *name,
			  bool *found)
{
	struct lua_lsm_module_shdict *shdict = NULL;
	unsigned long flags;

	*found = false;
	spin_lock_irqsave(&module->shdict_lock, flags);
	shdict = lua_lsm_module_find_shdict(module, name);
	if (shdict) {
		*found = true;
		if (!READ_ONCE(shdict->dead))
			lua_lsm_shdict_get(shdict);
		else
			shdict = NULL;
	}
	spin_unlock_irqrestore(&module->shdict_lock, flags);
	return shdict;
}

static struct lua_lsm_module_shdict *
lua_lsm_module_alloc_shdict(const char *name)
{
	struct lua_lsm_module_shdict *shdict;
	size_t len = strlen(name);

	shdict = kzalloc(struct_size(shdict, name, len + 1), lua_lsm_gfp());
	if (!shdict)
		return NULL;

	refcount_init(&shdict->refcount, 1);
	kvcache_dict_init(&shdict->dict);
	memcpy(shdict->name, name, len);
	shdict->name[len] = '\0';
	return shdict;
}

static struct lua_lsm_module_shdict *
lua_lsm_module_publish_shdict(struct lua_lsm_module *module,
			      struct lua_lsm_module_shdict *new,
			      const char *name)
{
	struct lua_lsm_module_shdict *shdict;
	unsigned long flags;

	spin_lock_irqsave(&module->shdict_lock, flags);
	shdict = lua_lsm_module_find_shdict(module, name);
	if (shdict) {
		if (READ_ONCE(shdict->dead))
			shdict = NULL;
		else
			lua_lsm_shdict_get(shdict);
	} else if (READ_ONCE(module->state) == LMS_STATE_LIVE) {
		atomic_inc(&module->shdict_count);
		list_add_tail(&new->list, &module->shdicts);
		lua_lsm_shdict_get(new);
		shdict = new;
	}
	spin_unlock_irqrestore(&module->shdict_lock, flags);
	return shdict;
}

int lua_shared_index(lua_State *L)
{
	const char *name = luaL_checkstring(L, 2);
	struct lua_lsm_module_shdict *shdict, *new = NULL;
	struct lua_lsm_module_shdict **slot;
	struct lua_lsm_module *module;
	bool found;

	__log_info_ratelimited("READ shared table, [%s] %s\n",
			       luaL_typename(L, 2),
			       lua_tostring(L, 2) ?: "(null)");

	lua_pushlightuserdata(L, MODULE_KEY);
	lua_gettable(L, LUA_ENVIRONINDEX);	/* env.MODULE_KEY */
	if (!lua_islightuserdata(L, -1)) {
		__log_err("NO fenv module\n");
		return 0;
	}
	module = lua_touserdata(L, -1);
	if (READ_ONCE(module->state) != LMS_STATE_LIVE)
		return 0;

	lua_pushvalue(L, 2);
	slot = newshdict(L);

	shdict = lua_lsm_module_get_shdict(module, name, &found);

	if (found && !shdict)
		goto err_pop_userdata;

	if (!shdict) {
		new = lua_lsm_module_alloc_shdict(name);
		if (!new) {
			__log_err("No memory\n");
			goto err_pop_userdata;
		}

		shdict = lua_lsm_module_publish_shdict(module, new, name);
		if (shdict != new)
			lua_lsm_shdict_put(new);
	}

	if (!shdict)
		goto err_pop_userdata;

	/* shared[name] = shdict */
	*slot = shdict;
	lua_rawset(L, 1);

	lua_settop(L, 2);
	lua_rawget(L, 1);
	return 1;

err_pop_userdata:
	lua_settop(L, 2);
	return 0;
}

int lua_shared_newindex(lua_State *L)
{
	__log_err("Invalid operation: WRITE shared table, [%s] %s - [%s] %s\n",
		  luaL_typename(L, 2), lua_tostring(L, 2) ?: "(null)",
		  luaL_typename(L, 3), lua_tostring(L, 3) ?: "(null)");
	return 0;
}
