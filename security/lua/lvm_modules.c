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

static int loaded_modules_key;


static void lvm_get_loaded_modules_table(lua_State *L)
{
	lua_pushlightuserdata(L, &loaded_modules_key);
	lua_rawget(L, LUA_REGISTRYINDEX);
	if (lua_istable(L, -1))
		return;

	lua_pop(L, 1);
	lua_pushlightuserdata(L, &loaded_modules_key);
	lua_newtable(L);
	lua_rawset(L, LUA_REGISTRYINDEX);
	lua_pushlightuserdata(L, &loaded_modules_key);
	lua_rawget(L, LUA_REGISTRYINDEX);
}

static bool lvm_remember_module(lua_State *L,
				struct lua_lsm_module *module)
{
	bool remembered;

	lvm_get_loaded_modules_table(L);
	lua_pushlightuserdata(L, module);
	lua_rawget(L, -2);
	remembered = lua_toboolean(L, -1);
	lua_pop(L, 1);
	if (remembered) {
		lua_pop(L, 1);
		return false;
	}

	lua_pushlightuserdata(L, module);
	lua_pushboolean(L, 1);
	lua_rawset(L, -3);
	lua_pop(L, 1);
	return true;
}

static bool lvm_forget_module_ref(lua_State *L,
				  struct lua_lsm_module *module)
{
	bool found;

	lua_pushlightuserdata(L, &loaded_modules_key);
	lua_rawget(L, LUA_REGISTRYINDEX);
	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		return false;
	}

	lua_pushlightuserdata(L, module);
	lua_rawget(L, -2);
	found = lua_toboolean(L, -1);
	lua_pop(L, 1);
	lua_pushlightuserdata(L, module);
	lua_pushnil(L);
	lua_rawset(L, -3);
	lua_pop(L, 1);
	return found;
}

static bool lvm_forget_module(lua_State *L, struct lua_lsm_module *module)
{
	int modules_idx;

	/*
	 * Clear only the Lua registry entries.  The caller owns garbage
	 * collection and the loaded-VM count.
	 */
	lua_getfield(L, LUA_REGISTRYINDEX, "_MODULES");
	if (lua_istable(L, -1)) {
		modules_idx = lua_gettop(L);
		lua_pushstring(L, module->name);
		lua_rawget(L, modules_idx);
		if (lua_istable(L, -1)) {
			lua_pop(L, 1);

			lua_pushstring(L, module->name);
			lua_pushnil(L);
			lua_rawset(L, modules_idx);

			lua_getfield(L, LUA_REGISTRYINDEX, "_LOADED");
			if (lua_istable(L, -1)) {
				lua_pushstring(L, module->name);
				lua_pushnil(L);
				lua_rawset(L, -3);
			}
			lua_pop(L, 1);

		} else {
			lua_pop(L, 1);
		}
	}
	lua_pop(L, 1);

	return lvm_forget_module_ref(L, module);
}

bool lvm_drop_module(lua_State *L, struct lua_lsm_module *module)
{
	if (!lvm_forget_module(L, module))
		return false;

	lua_gc(L, LUA_GCCOLLECT, 0);
	__log_info("dropped module <%s>, loaded_vms = %d\n",
		   module->name, atomic_read(&module->loaded_vm_count) - 1);
	lua_lsm_module_put_loaded_vm(module);
	return true;
}

static struct lua_lsm_module *lvm_next_loaded_module(lua_State *L)
{
	struct lua_lsm_module *module;

	lvm_get_loaded_modules_table(L);
	lua_pushnil(L);
	if (lua_next(L, -2) != 0) {
		module = lua_touserdata(L, -2);
		lua_pop(L, 3);
		return module;
	}

	lua_pop(L, 1);
	return NULL;
}

static int lua_module_fenv_newindex(lua_State *L)
{
	/* args: t, k, v */
	__log_warn("Warning: set global variable, [%s] %s - [%s] %s\n",
		   luaL_typename(L, 2), lua_tostring(L, 2) ?: "(null)",
		   luaL_typename(L, 3), lua_tostring(L, 3) ?: "(null)");

	/* XXX: t[k] = v, Warning it, but still perform assignment */
	lua_rawset(L, 1);
	return 0;
}

static int module_load(lua_State *L, struct lua_lsm_module *module)
{
	int err;

	lua_newtable(L);			/* env */
	lua_pushvalue(L, -1);
	lua_replace(L, LUA_ENVIRONINDEX);

	/* Must be after lua_replace(LUA_ENVIRONINDEX) to ensure correct env */
	lua_pushlightuserdata(L, MODULE_KEY);
	lua_pushlightuserdata(L, module);
	lua_settable(L, -3);			/* env.MODULE_KEY = module */
	*newtask_nomain(L) = current;
	lua_setfield(L, -2, "current");		/* env.current = current */

	lua_newtable(L);			/* shared table */
	lua_createtable(L, 0, 2);		/* shared metatable */
	lua_pushcfunction(L, lua_shared_index);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction(L, lua_shared_newindex);
	lua_setfield(L, -2, "__newindex");
	lua_setmetatable(L, -2);		/* setmetatable(shared, mt) */
	lua_setfield(L, -2, "shared");		/* env.shared = shared */

	/* setmetatable(env, { __index = _G, __newindex = func }) */
	lua_createtable(L, 0, 2);		/* metatable */
	lua_pushvalue(L, LUA_GLOBALSINDEX);
	lua_setfield(L, -2, "__index");		/* metatable.__index = _G */
	lua_pushcfunction(L, lua_module_fenv_newindex);
	lua_setfield(L, -2, "__newindex");	/* metatable.__newindex = func */
	lua_setmetatable(L, -2);		/* setmetatable(env, metatable) */

	lua_pushcfunction(L, lua_traceback);
	err = luaL_loadbuffer_wrap(L, module->chunk,
				   module->chunk_len, module->name);
	if (err) {
		lua_pop(L, 2);
		return err;
	}

	/* stack: [env, traceback, modfunc] */
	lua_pushvalue(L, -3);
	lua_setfenv(L, -2);			/* setfenv(modfunc, env) */

	err = lua_pcall_wrap(L, 0, 1, -2);
	if (err) {
		lua_pop(L, 2);
		return err;
	}

	/* stack: [env, traceback, _M] */
	if (!lua_istable(L, -1)) {
		__log_err("module <%s> is not a table: top = %d [%s]\n",
			  module->name, lua_gettop(L), luaL_typename(L, -1));
		lua_pop(L, 3);
		return -EBADF;
	}

	lua_remove(L, -2);			/* remove traceback */
	lua_remove(L, -2);			/* remove env */
	/* NO error, only _M is returned */
	return 0;
}

int lua_modules_index(lua_State *L)
{
	const char *key = luaL_checkstring(L, 2);
	struct lua_lsm_module *module;
	bool remembered;
	int err;

	/* module queries are always run with a read lock */
	list_for_each_entry_srcu(module, &lsm_modules, list,
				 srcu_read_lock_held(&modules_ss)) {
		if (READ_ONCE(module->state) != LMS_STATE_LIVE)
			continue;
		if (strcmp(module->name, key) != 0)
			continue;

		lvm_mark_dirty(L);
		err = module_load(L, module);
		if (err) {
			__log_err("load: %s, err = %d, top = %d\n",
				  key, err, lua_gettop(L));
			return 0;
		}

		remembered = lvm_remember_module(L, module);
		if (remembered)
			atomic_inc(&module->loaded_vm_count);

		/*
		 * A pre-existing SRCU reader can race with unregister after the
		 * state check above.  Recheck after taking the VM reference so a
		 * late per-CPU load cannot outlive the per-CPU drain.
		 */
		smp_mb__after_atomic();
		if (READ_ONCE(module->state) != LMS_STATE_LIVE) {
			if (remembered && lvm_forget_module(L, module))
				lua_lsm_module_put_loaded_vm(module);
			lua_pop(L, 1);
			return 0;
		}

		lua_insert(L, -2);
		lua_pushvalue(L, -2);
		/* stack: [table, thunk, key, thunk] */
		lua_rawset(L, 1);		/* table[key] = thunk */

		return 1;			/* return the thunk */
	}

	__log_err("'%s' NOT found, top = %d\n", key, lua_gettop(L));
	return 0;
}

/*
 * Drop each module reference owned by a Lua VM.  Each pointer stays valid
 * until its loaded-VM reference is released after garbage collection.
 */
void lvm_put_loaded_modules(lua_State *L)
{
	struct lua_lsm_module *module;

	while ((module = lvm_next_loaded_module(L)))
		lvm_drop_module(L, module);
}

/********************************** Lua VM **********************************/
