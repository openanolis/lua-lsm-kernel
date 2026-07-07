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

struct cred;
struct dentry;
struct file;
struct mm_struct;
struct task_struct;
struct user_namespace;

static inline gfp_t lua_lsm_gfp(void)
{
	/*
	 * Sleeping function is not allowed in atomic, rcu and
	 * softirq context.
	 */
	if (in_atomic() || rcu_preempt_depth() > 0)
		return GFP_ATOMIC;

	return GFP_NOFS;
}

#define luaL_newlibtable(L, l)						\
	(lua_createtable((L), 0, sizeof((l)) / sizeof(*(l)) - 1))

#define luaL_newlib(L, l)						\
	(luaL_newlibtable((L), (l)), luaL_register((L), NULL, (l)))

/* debug functions */

void lua_table_dump(lua_State *L, int idx, int level, int max);
void lua_stack_dump(lua_State *L);

/* aux functions */

int lua_traceback(lua_State *L);
int luaL_loadbuffer_wrap(lua_State *L, const char *buff,
			 size_t sz, const char *name);
int lua_pcall_wrap(lua_State *L, int nargs, int nresults, int errfunc);

void luaL_requiref(lua_State *L, const char *modname,
		   lua_CFunction openf, int glb);

struct cflag_opt {
	const char *name;
	unsigned int flag;
};

extern const struct cflag_opt lua_lsm_cap_opts[];
extern const unsigned int lua_lsm_cap_opt_flags;

unsigned int tocflags(lua_State *L, int idx, int top,
		      const struct cflag_opt *opts, unsigned int d);

const char *
fromcflags(const struct cflag_opt *opts, unsigned int flag, const char *d);

void table_fromopts(lua_State *L, const struct cflag_opt *opts,
		    unsigned int bitfield, unsigned int mask);

void **newcptr(lua_State *L, const char *metatable);
void createmeta(lua_State *L, const char *tname, const char *name,
		const luaL_Reg *meth, const luaL_Reg *base, int pop);
void *checkudata(lua_State *L, int ud, const char *name);

void createmeta3(lua_State *L, const char *name, const luaL_Reg *base,
		 const char *tname_gc, const luaL_Reg *funcs_gc,
		 const char *tname, const luaL_Reg *funcs,
		 const char *tname_raw, const luaL_Reg *funcs_raw);
void *checkudata3(lua_State *L, int ud, const char *tname);

struct const_value {
	const char *name;
	intptr_t value;
};

#define CONST_DEFINE(name)	{ #name, name }

void setconst(lua_State *L, const struct const_value *cv);

int aux_file_path(lua_State *L, struct file *filp);
int aux_dentry_path(lua_State *L, struct dentry *dentry, int rawpath);

int arg2cap(lua_State *L, int idx);
int aux_capable(lua_State *L, const struct cred *cred,
		struct user_namespace *default_ns, int idx);

struct task_struct *aux_find_get_task_by_vpid(pid_t nr);
struct file *aux_get_task_exe_file(struct task_struct *task);
struct file *aux_get_mm_exe_file(struct mm_struct *mm);

#endif /* ! _SECURITY_LUA_LSM_AUXLIB_H */
