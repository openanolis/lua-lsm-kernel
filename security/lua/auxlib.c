/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#define pr_fmt(fmt)	"lua-lsm: " fmt

#include "debug.h"
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/lua.h>
#include <linux/lauxlib.h>
#include <linux/lualib.h>
#include "auxlib.h"


void lua_stack_dump(lua_State *L)
{
	int top = lua_gettop(L);
	int i;

	__log_info("-------- stack dump start --------\n");
	for (i = 1; i <= top; i++) {
		int type = lua_type(L, i);
		const char * __maybe_unused name = lua_typename(L, type);

		if (type == LUA_TSTRING)
			__log_info("    %2d [%s] %s\n", i, name, lua_tostring(L, i));
		else
			__log_info("    %2d [%s]\n", i, name);
	}
	__log_info("-------- stack dump end   --------\n");
}

void lua_table_dump(lua_State *L, const char *prefix)
{
	int i = 1;
	if (!lua_istable(L, -1)) {
		__log_err("%s: not a table, type = %s\n",
			prefix, luaL_typename(L, -1));
		return;
	}
	__log_info("-------- %s: table dump start --------\n", prefix);
	/* table is in the stack at index 't' */
	lua_pushnil(L);  /* first key */
	while (lua_next(L, -2) != 0) {
		/* uses 'key' (at index -2) and 'value' (at index -1) */
		__log_info("    %2d: [%s] %s\t- [%s] %s\n", i,
			luaL_typename(L, -2), lua_tostring(L, -2) ?: "(null)",
			luaL_typename(L, -1), lua_tostring(L, -1) ?: "(null)");
		/* removes 'value'; keeps 'key' for next iteration */
		lua_pop(L, 1);
		i += 1;
	}
	__log_info("-------- %s: table dump end   --------\n", prefix);
}

/* borrowed from lua.c */
int lua_traceback(lua_State *L)
{
	pr_err("@_@ LuaVM: top = %d\n", lua_gettop(L));
	if (!lua_isstring(L, 1))  /* 'message' not a string? */
		return 1;  /* keep it intact */
	pr_err("@_@ LuaVM: %s\n", lua_tostring(L, -1));
	lua_getfield(L, LUA_GLOBALSINDEX, "debug");
	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		return 1;
	}
	lua_getfield(L, -1, "traceback");
	if (!lua_isfunction(L, -1)) {
		lua_pop(L, 2);
		return 1;
	}
	lua_pushvalue(L, 1);  /* pass error message */
	lua_pushinteger(L, 2);  /* skip this function and traceback */
	lua_call(L, 2, 1);  /* call debug.traceback */
	pr_err("@_@ LuaVM stack:\n%s\n", lua_tostring(L, -1));

	__log_err("------------------ C stack dump start ------------------\n");
	dump_stack();
	__log_err("------------------  C stack dump end  ------------------\n");
	return 1;
}

int luaL_loadbuffer_wrap(lua_State *L, const char *buff,
		size_t sz, const char *name)
{
	int status;

	status = luaL_loadbuffer(L, buff, sz, name);
	if (status != 0) {
		const char * __maybe_unused error = lua_tostring(L, -1);
		int err;
		__log_err("load: status = %d, top = %d, %s\n",
			status, lua_gettop(L), error);
		switch (status) {
		case LUA_ERRMEM:	err = -ENOMEM;	break;
		case LUA_ERRSYNTAX:	err = -EDOM;	break;
		default:		err = -EINVAL;	break;
		}
		lua_pop(L, 1);
		return err;
	}
	return 0;
}

int lua_pcall_wrap(lua_State *L, int nargs, int nresults, int errfunc)
{
	int status;

	status = lua_pcall(L, nargs, nresults, errfunc);
	if (status != 0) {
		int err;
		const char *error = lua_tostring(L, -1);
		if (!error)
			error = "unknown error";
		__log_err("pcall: status = %d, top = %d [%s]\n\t%s\n",
			status, lua_gettop(L), luaL_typename(L, -1), error);
		switch (status) {
		case LUA_ERRMEM:	err = -ENOMEM;	break;
		case LUA_ERRRUN:	err = -ENOEXEC;	break;
		case LUA_ERRERR:	err = -EFAULT;	break;
		default:		err = -EINVAL;	break;
		}
		lua_pop(L, 1);
		return err;
	}
	return 0;
}

/*
 ** Stripped-down 'require': After checking "loaded" table, calls 'openf'
 ** to open a module, registers the result in 'package.loaded' table and,
 ** if 'glb' is true, also registers the result in the global table.
 ** Leaves resulting module on the top.
 */
void luaL_requiref(lua_State *L, const char *modname,
		lua_CFunction openf, int glb)
{
	luaL_findtable(L, LUA_REGISTRYINDEX, "_LOADED", 1);
	lua_getfield(L, -1, modname);  /* _LOADED[modname] */
	if (!lua_toboolean(L, -1)) {  /* package not already loaded? */
		lua_pop(L, 1);  /* remove field */
		lua_pushcfunction(L, openf);
		lua_pushstring(L, modname);  /* argument to open function */
		lua_call(L, 1, 1);  /* call 'openf' to open module */
		lua_pushvalue(L, -1);  /* make copy of module (call result) */
		lua_setfield(L, -3, modname);  /* _LOADED[modname] = module */
	}
	lua_remove(L, -2);  /* remove _LOADED table */
	if (glb) {
		lua_pushvalue(L, -1);  /* copy of module */
		lua_setglobal(L, modname);  /* _G[modname] = module */
	}
}

void settopfenvfrom(lua_State *L, int from)
{
	lua_getfenv(L, from);
	lua_setfenv(L, -2);
}

unsigned int tocflags(lua_State *L, int idx, int top,
		const struct cflag_opt *opts, unsigned int d)
{
	unsigned int flags = 0;
	const char *s;
	int k, i;

	if (top == -1)
		top = idx;

	for ( ; idx <= top; idx++) {
		switch (lua_type(L, idx)) {
		case LUA_TSTRING:
			s = lua_tostring(L, idx);
			for (i = 0; opts[i].name; i++) {
				if (strcasecmp(s, opts[i].name) != 0)
					continue;
				flags |= opts[i].flag;
				break;
			}
			break;

		case LUA_TTABLE:
			for (k = 1, lua_rawgeti(L, idx, k);
					!lua_isnil(L, -1);
					lua_pop(L, 1), lua_rawgeti(L, idx, ++k)) {
				if (lua_type(L, -1) != LUA_TSTRING)
					continue;
				s = lua_tostring(L, -1);
				for (i = 0; opts[i].name; i++) {
					if (strcasecmp(s, opts[i].name) != 0)
						continue;
					flags |= opts[i].flag;
					break;
				}
			}
			lua_pop(L, 1);
			break;

		case LUA_TNUMBER:
			flags |= (unsigned int)lua_tointeger(L, idx);
			break;

		case LUA_TBOOLEAN:
			if (lua_toboolean(L, idx))
				break;
			/* else fall through */
			fallthrough;
		case LUA_TNONE:
		case LUA_TNIL:
			flags = d;	/* default flags */
			break;
		}
	}

	return flags;
}

const char *
fromcflags(const struct cflag_opt *opts, unsigned int flag, const char *d)
{
	int i;
	for (i = 0; opts[i].name; i++) {
		if (opts[i].flag == flag)
			return opts[i].name;
	}
	return d;
}

void table_fromopts(lua_State *L, const struct cflag_opt *opts,
		unsigned int bitfield, unsigned int mask)
{
	int i;
	int hw;
	if (!bitfield) {
		for (i = 0; opts[i].name; i++)
			bitfield |= opts[i].flag;
	}
	hw = (int)hweight_long((unsigned long)(mask & bitfield));
	lua_createtable(L, 0, hw);
	for (i = 0; opts[i].name; i++) {
		if (mask & opts[i].flag) {
			lua_pushboolean(L, 1);
			lua_setfield(L, -2, opts[i].name);
		}
	}
}

void **newcptr(lua_State *L, const char *metatable)
{
	void **p = (void **)lua_newuserdata(L, sizeof(void *));
	*p = NULL;
	luaL_getmetatable(L, metatable);
	lua_setmetatable(L, -2);
	return p;
}

void createmeta(lua_State *L, const char *name,
		const luaL_Reg *meth, int index, int pop)
{
	luaL_newmetatable(L, name);
	lua_pushstring(L, "cannot get a protected metatable");
	lua_setfield(L, -2, "__metatable");	/* metatable.__metatable = msg */
	if (index) {
		lua_pushvalue(L, -1);
		lua_setfield(L, -2, "__index");	/* metatable.__index = metatable */
	}
	if (meth)
		luaL_register(L, NULL, meth);
	if (pop)
		lua_pop(L, 1);
}

void *checkudata(lua_State *L, int ud, const char *name)
{
	void *p = lua_touserdata(L, ud);
	if (p != NULL) {  /* value is a userdata? */
		if (lua_getmetatable(L, ud)) {  /* does it have a metatable? */
			lua_getfield(L, LUA_REGISTRYINDEX, name);  /* get correct metatable */
			if (lua_rawequal(L, -1, -2)) {  /* does it have the correct mt? */
				lua_pop(L, 2);  /* remove both metatables */
				return p;
			}
		}
	}
	return NULL;
}

void setconst(lua_State *L, const struct const_value *cv)
{
	for ( ; cv->name; cv++) {
		lua_pushstring(L, cv->name);
		lua_pushnumber(L, cv->value);
		lua_settable(L, -3);
	}
}
