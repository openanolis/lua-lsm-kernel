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


void lvm_get_loaded_modules_table(lua_State *L)
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

/*
 * Remember a module in this VM's cache: loaded_modules[module] = _M.
 *
 * Creating an entry must always be paired with taking a loaded-VM
 * reference for this VM when true is returned: entry present <=> count
 * held (the pairing invariant).
 */
static bool lvm_remember_module(lua_State *L, struct lua_lsm_module *module)
{
	int t, m;
	bool fresh;

	lvm_get_loaded_modules_table(L);
	t = lua_gettop(L);
	m = t - 1;

	lua_pushlightuserdata(L, module);
	lua_rawget(L, t);
	fresh = lua_isnil(L, -1);
	lua_pop(L, 1);

	if (fresh) {
		lua_pushlightuserdata(L, module);
		lua_pushvalue(L, m);
		lua_rawset(L, t);
	}
	lua_pop(L, 1);
	return fresh;
}

/*
 * Remove a module's cache entry.
 *
 * Removing an entry must always be paired with dropping this VM's
 * loaded-VM reference when true is returned: entry present <=> count
 * held (the pairing invariant).
 */
static bool lvm_forget_module(lua_State *L, struct lua_lsm_module *module)
{
	int t;
	bool found;

	lua_pushlightuserdata(L, &loaded_modules_key);
	lua_rawget(L, LUA_REGISTRYINDEX);
	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		return false;
	}
	t = lua_gettop(L);

	lua_pushlightuserdata(L, module);
	lua_rawget(L, t);
	found = !lua_isnil(L, -1);
	lua_pop(L, 1);

	lua_pushlightuserdata(L, module);
	lua_pushnil(L);
	lua_rawset(L, t);
	lua_pop(L, 1);
	return found;
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

/*
 * Load a module into a VM: build the module environment, run the chunk
 * inside it, and leave the chunk's result — the module table _M — on top.
 *
 * Must be called from inside a Lua-called C frame (L->ci != L->base_ci):
 * it writes LUA_ENVIRONINDEX, which lua_replace() rejects otherwise.  The
 * only caller is the pcall'ed lvm_module_load_thunk(), which guarantees
 * the frame and cleans up leftover slots via poscall truncation.
 *
 * in:  any stack (the thunk's module argument sits below)
 * out: success: +1, _M on top;  failure: leftovers possible, caller
 *      cleans up
 */
static int module_load(lua_State *L, struct lua_lsm_module *module)
{
	int env, modfunc, trace, err;

	/*
	 * Module environment: the chunk's globals.  Reads miss here and
	 * resolve in _G (metatable __index); writes land in env itself
	 * (the __newindex handler warns, then stores).
	 */
	lua_newtable(L);
	env = lua_gettop(L);
	lua_pushvalue(L, env);
	lua_replace(L, LUA_ENVIRONINDEX);

	/* env.MODULE_KEY = module: kvcache/shdict resolve their owner. */
	lua_pushlightuserdata(L, MODULE_KEY);
	lua_pushlightuserdata(L, module);
	lua_settable(L, env);

	*newtask_nomain(L) = current;
	lua_setfield(L, env, "current");

	/* env.shared = shared dict table with lazy metamethods */
	lua_newtable(L);				/* shared table */
	lua_createtable(L, 0, 2);			/* its metatable */
	lua_pushcfunction(L, lua_shared_index);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction(L, lua_shared_newindex);
	lua_setfield(L, -2, "__newindex");
	lua_setmetatable(L, -2);			/* setmetatable(shared, mt) */
	lua_setfield(L, env, "shared");

	lua_createtable(L, 0, 2);
	lua_pushvalue(L, LUA_GLOBALSINDEX);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction(L, lua_module_fenv_newindex);
	lua_setfield(L, -2, "__newindex");
	lua_setmetatable(L, env);

	/* Run the chunk with env as its fenv, traceback as errfunc. */
	lua_pushcfunction(L, lua_traceback);
	trace = lua_gettop(L);
	err = luaL_loadbuffer_wrap(L, module->chunk,
				   module->chunk_len, module->name);
	if (err) {
		lua_pop(L, 2);				/* traceback, env */
		return err;
	}
	modfunc = lua_gettop(L);

	lua_pushvalue(L, env);
	lua_setfenv(L, modfunc);

	err = lua_pcall_wrap(L, 0, 1, trace);
	if (err) {
		lua_pop(L, 2);				/* traceback, env */
		return err;
	}

	/* The chunk must return its module table. */
	if (!lua_istable(L, -1)) {
		__log_err("module <%s> is not a table: top = %d [%s]\n",
			  module->name, lua_gettop(L), luaL_typename(L, -1));
		lua_pop(L, 3);				/* traceback, env, result */
		return -EBADF;
	}

	/* stack: [.., env, traceback, _M] */
	lua_remove(L, trace);
	lua_remove(L, env);
	return 0;
}

/*
 * Trampoline that gives module_load() a Lua-called C frame.  Only ever
 * invoked through lua_pcall_wrap() by lvm_load_module(): the frame makes
 * the LUA_ENVIRONINDEX write legal, the pcall turns any Lua API error
 * into an errno instead of an unprotected kernel panic, and poscall
 * truncation discards module_load()'s leftovers on failure.
 */
static int lvm_module_load_thunk(lua_State *L)
{
	struct lua_lsm_module *module = lua_touserdata(L, 1);

	return module_load(L, module) ? 0 : 1;
}

static bool lvm_cache_lookup(lua_State *L, struct lua_lsm_module *module)
{
	lvm_get_loaded_modules_table(L);
	lua_pushlightuserdata(L, module);
	lua_rawget(L, -2);
	if (lua_istable(L, -1)) {
		lua_remove(L, -2);
		return true;
	}
	lua_pop(L, 2);
	return false;
}

static bool lvm_load_module(lua_State *L, struct lua_lsm_module *module)
{
	int base = lua_gettop(L);
	int err;

	lua_pushlightuserdata(L, module);
	lua_pushcfunction(L, lvm_module_load_thunk);
	lua_insert(L, -2);
	err = lua_pcall_wrap(L, 1, 1, 0);
	if (err) {
		__log_err("load: %s, err = %d, top = %d\n",
			  module->name, err, lua_gettop(L));
		lua_settop(L, base);
		return false;
	}

	/* A failed load returns no result, nil-padded by the pcall. */
	if (!lua_istable(L, -1)) {
		lua_settop(L, base);
		return false;
	}
	return true;
}

int lvm_get_module_table(lua_State *L, struct lua_lsm_module *module)
{
	int base = lua_gettop(L);
	bool fresh;

	if (lvm_cache_lookup(L, module))
		return 1;

	if (READ_ONCE(module->state) != LMS_STATE_LIVE)
		return 0;

	/* A load dirties the VM: pooled VMs must be reset, not reused. */
	lvm_mark_dirty(L);

	if (!lvm_load_module(L, module))
		return 0;

	/* Install into the cache and take the matching VM reference. */
	fresh = lvm_remember_module(L, module);
	if (fresh)
		atomic_inc(&module->loaded_vm_count);

	/*
	 * Unregister can race with the load.  Recheck after the reference
	 * is taken: either we see GOING and undo the reference we just
	 * took, or unregister's barrier makes the late unload wait for our
	 * SRCU read section to finish first.
	 */
	smp_mb__after_atomic();
	if (READ_ONCE(module->state) != LMS_STATE_LIVE) {
		if (fresh && lvm_forget_module(L, module))
			lua_lsm_module_put_loaded_vm(module);
		lua_settop(L, base);
		return 0;
	}

	return 1;
}

int lua_modules_index(lua_State *L)
{
	const char *key = luaL_checkstring(L, 2);
	struct lua_lsm_module *module;

	list_for_each_entry_srcu(module, &lsm_modules, list,
				 srcu_read_lock_held(&modules_ss)) {
		if (READ_ONCE(module->state) != LMS_STATE_LIVE)
			continue;
		if (strcmp(module->name, key) != 0)
			continue;

		return lvm_get_module_table(L, module);
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
