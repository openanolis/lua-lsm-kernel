/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#ifndef _SECURITY_LUA_LSM_AUXLIB_H
#define _SECURITY_LUA_LSM_AUXLIB_H

#include <linux/lua.h>
#include <linux/lauxlib.h>


#define luaL_newlibtable(L, l)						\
	(lua_createtable((L), 0, sizeof((l)) / sizeof(*(l)) - 1))

#define luaL_newlib(L, l)						\
	(luaL_newlibtable((L), (l)), luaL_register((L), NULL, (l)))

/* debug functions */

void lua_stack_dump(lua_State *L);
void lua_table_dump(lua_State *L, const char *prefix);

/* aux functions */

int lua_traceback(lua_State *L);
int luaL_loadbuffer_wrap(lua_State *L, const char *buff,
		size_t sz, const char *name);
int lua_pcall_wrap(lua_State *L, int nargs, int nresults, int errfunc);

void luaL_requiref(lua_State *L, const char *modname,
		lua_CFunction openf, int glb);

void settopfenvfrom(lua_State *L, int from);

struct cflag_opt {
	const char *name;
	unsigned int flag;
};

unsigned int tocflags(lua_State *L, int idx, int top,
		const struct cflag_opt *opts, unsigned int d);

const char *
fromcflags(const struct cflag_opt *opts, unsigned int flag, const char *d);

void table_fromopts(lua_State *L, const struct cflag_opt *opts,
		unsigned int bitfield, unsigned int mask);

void **newcptr(lua_State *L, const char *metatable);
void createmeta(lua_State *L, const char *name,
		const luaL_Reg *meth, int index, int pop);
void *checkudata(lua_State *L, int ud, const char *name);

struct const_value {
	const char *name;
	intptr_t value;
};

#define CONST_DEFINE(name)	{ #name, name }

void setconst(lua_State *L, const struct const_value *cv);

#endif /* ! _SECURITY_LUA_LSM_AUXLIB_H */
