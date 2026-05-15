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
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/errname.h>
#include <linux/security.h>
#include <linux/capability.h>
#include <linux/lua.h>
#include <linux/lauxlib.h>
#include <linux/lualib.h>
#include "auxlib.h"
#include "lua_object.h"

void lua_table_dump(lua_State *L, int idx, int level, int max)
{
	int i = 1;

	if (idx < 0)
		idx = lua_gettop(L) + 1 + idx;
	if (!lua_istable(L, idx)) {
		pr_err("%*s    <Not a table, type = %s>\n",
		       level * 4, "", luaL_typename(L, -1));
		return;
	}
	if (level > 10) {
		pr_err("%*s    <Table nesting is out of scope, level = %d>\n",
		       level * 4, "", level);
		return;
	}
	/* table is in the stack at index 't' */
	lua_pushnil(L);  /* first key */
	while (lua_next(L, idx) != 0) {
		if (max != -1 && i > max) {
			pr_info("%*s     ... ...\n", level * 4, "");
			lua_pop(L, 2);
			break;
		}

		/* To avoid changing the key in lua_tostring */
		lua_pushvalue(L, -2);
		/* stack: [key, value, key2] */
		switch (lua_type(L, -2)) {
		case LUA_TTABLE:
			pr_info("%*s    %2d: [%s] %s\n", level * 4, "", i,
				luaL_typename(L, -1), lua_tostring(L, -1) ?: "(null)");
			lua_table_dump(L, -2, level + 1, 5);
			break;
		default:
			/* uses 'key' (at index -2) and 'value' (at index -1) */
			pr_info("%*s    %2d: [%s] %s\t- [%s] %s\n",
				level * 4, "", i,
				luaL_typename(L, -1), lua_tostring(L, -1) ?: "(null)",
				luaL_typename(L, -2), lua_tostring(L, -2) ?: "(null)");
			break;
		}

		/* removes 'value' and 'key2'; keeps 'key' for next iteration */
		lua_pop(L, 2);
		i += 1;
	}
}

void lua_stack_dump(lua_State *L)
{
	int top = lua_gettop(L);
	int i;

	for (i = 1; i <= top; i++) {
		switch (lua_type(L, i)) {
		case LUA_TTABLE:
			pr_info("    %2d: [table]\n", i);
			lua_table_dump(L, i, 1, 6);
			break;
		default:
			lua_pushvalue(L, i);
			pr_info("    %2d: [%s] %s\n", i,
				luaL_typename(L, -1), lua_tostring(L, -1) ?: "(null)");
			lua_pop(L, 1);
			break;
		}
	}
}

/* borrowed from lua.c */
int lua_traceback(lua_State *L)
{
	pr_err("@_@ LuaVM traceback: %s [%d] Lua stacktop = %d\n",
	       current->comm, task_pid_nr(current), lua_gettop(L));
	if (!lua_isstring(L, 1))  /* 'message' not a string? */
		return 1;  /* keep it intact */
	pr_err("@_@ LuaVM: %s\n", lua_tostring(L, -1));

	/* Lua stack */
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

	pr_err("----------------------------------------\n");
	/* C stack */
	dump_stack();
	pr_err("----------------------------------------\n");
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
		case LUA_ERRMEM:
			err = -ENOMEM;
			break;
		case LUA_ERRSYNTAX:
			err = -EDOM;
			break;
		default:
			err = -EINVAL;
			break;
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
		case LUA_ERRMEM:
			err = -ENOMEM;
			break;
		case LUA_ERRRUN:
			err = -ENOEXEC;
			break;
		case LUA_ERRERR:
			err = -EFAULT;
			break;
		default:
			err = -EINVAL;
			break;
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

const struct cflag_opt lua_lsm_cap_opts[] = {
	{ "noaudit",	CAP_OPT_NOAUDIT		},
	{ "insetid",	CAP_OPT_INSETID		},
	{ NULL, 0 }
};

const unsigned int lua_lsm_cap_opt_flags = CAP_OPT_NOAUDIT |
	CAP_OPT_INSETID;

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

void createmeta(lua_State *L, const char *tname, const char *name,
		const luaL_Reg *meth, const luaL_Reg *base, int pop)
{
	luaL_newmetatable(L, tname);
	/* metatable.__metatable = error_message */
	lua_pushstring(L, "cannot set a protected metatable");
	lua_setfield(L, -2, "__metatable");

	/* metatable.__index = metatable */
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	if (base)
		luaL_register(L, NULL, base);

	if (meth)
		luaL_register(L, NULL, meth);

	if (pop)
		lua_pop(L, 1);
}

void *checkudata(lua_State *L, int ud, const char *name)
{
	void *p = lua_touserdata(L, ud);

	if (p) {  /* value is a userdata? */
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

/*
 *           meta           meta
 * [ [ gc ] ------> regular ] ------> raw
 */
void createmeta3(lua_State *L, const char *name, const luaL_Reg *base,
		 const char *tname_gc, const luaL_Reg *funcs_gc,
		 const char *tname, const luaL_Reg *funcs,
		 const char *tname_raw, const luaL_Reg *funcs_raw)
{
	if (funcs_gc && funcs)
		createmeta(L, tname_gc, name, funcs_gc, base, 0);

	/* Always create regular metatable and raw metatable. */
	createmeta(L, tname, name, funcs, base, 0);
	createmeta(L, tname_raw, name, funcs_raw, base, 0);
	lua_setmetatable(L, -2);

	if (funcs_gc && funcs)
		lua_setmetatable(L, -2);

	lua_pop(L, 1);
}

void *checkudata3(lua_State *L, int ud, const char *tname)
{
	int idx, n;
	void *p = lua_touserdata(L, ud);

	if (!p)
		return NULL;

	luaL_getmetatable(L, tname);
	idx = ud;
	for (n = 1; lua_getmetatable(L, idx); n++) {
		if (lua_rawequal(L, -1, -1 - n)) {
			lua_pop(L, n + 1);
			return p;
		}
		idx = -1;
	}
	lua_pop(L, n);

	luaL_typerror(L, ud, tname);
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

int aux_file_path(lua_State *L, struct file *filp)
{
	char buffer[256];
	char *buf = NULL;
	char *path;
	int nres;

	if (unlikely(!filp || !current->fs)) {
		lua_pushnil(L);
		lua_pushstring(L, errname(-ESRCH));
		return 2;
	}

	if (unlikely(!filp->f_path.dentry)) {
		lua_pushnil(L);
		lua_pushstring(L, errname(-ENOENT));
		return 2;
	}

	path = file_path(filp, buffer, sizeof(buffer));
	if (PTR_ERR(path) == -ENAMETOOLONG) {
		buf = kmalloc(PATH_MAX, lua_lsm_gfp());
		if (!buf) {
			lua_pushnil(L);
			lua_pushstring(L, errname(-ENOMEM));
			return 2;
		}
		path = file_path(filp, buf, PATH_MAX);
	}
	if (IS_ERR(path)) {
		lua_pushnil(L);
		lua_pushstring(L, errname(PTR_ERR(path)));
		nres = 2;
	} else {
		lua_pushstring(L, path);
		nres = 1;
	}
	if (buf)
		kfree(buf);
	return nres;
}

int aux_dentry_path(lua_State *L, struct dentry *dentry, int rawpath)
{
	char buffer[256];
	char *buf = NULL;
	char *path;
	int nres;

	if (rawpath)
		path = dentry_path_raw(dentry, buffer, sizeof(buffer));
	else
		path = dentry_path(dentry, buffer, sizeof(buffer));
	if (PTR_ERR(path) == -ENAMETOOLONG) {
		buf = kmalloc(PATH_MAX, lua_lsm_gfp());
		if (!buf) {
			lua_pushnil(L);
			lua_pushstring(L, errname(-ENOMEM));
			return 2;
		}
		if (rawpath)
			path = dentry_path_raw(dentry, buf, PATH_MAX);
		else
			path = dentry_path(dentry, buf, PATH_MAX);
	}
	if (IS_ERR(path)) {
		lua_pushnil(L);
		lua_pushstring(L, errname(PTR_ERR(path)));
		nres = 2;
	} else {
		lua_pushstring(L, path);
		nres = 1;
	}
	if (buf)
		kfree(buf);
	return nres;
}

int arg2cap(lua_State *L, int idx)
{
	static const struct cflag_opt caps[] = {
		{ "chown",              CAP_CHOWN		},
		{ "dac_override",       CAP_DAC_OVERRIDE	},
		{ "dac_read_search",    CAP_DAC_READ_SEARCH	},
		{ "fowner",             CAP_FOWNER		},
		{ "fsetid",             CAP_FSETID		},
		{ "kill",               CAP_KILL		},
		{ "setgid",             CAP_SETGID		},
		{ "setuid",             CAP_SETUID		},
		{ "setpcap",            CAP_SETPCAP		},
		{ "linux_immutable",    CAP_LINUX_IMMUTABLE	},
		{ "net_bind_service",   CAP_NET_BIND_SERVICE	},
		{ "net_broadcast",      CAP_NET_BROADCAST	},
		{ "net_admin",          CAP_NET_ADMIN		},
		{ "net_raw",            CAP_NET_RAW		},
		{ "ipc_lock",           CAP_IPC_LOCK		},
		{ "ipc_owner",          CAP_IPC_OWNER		},
		{ "sys_module",         CAP_SYS_MODULE		},
		{ "sys_rawio",          CAP_SYS_RAWIO		},
		{ "sys_chroot",         CAP_SYS_CHROOT		},
		{ "sys_ptrace",         CAP_SYS_PTRACE		},
		{ "sys_pacct",          CAP_SYS_PACCT		},
		{ "sys_admin",          CAP_SYS_ADMIN		},
		{ "sys_boot",           CAP_SYS_BOOT		},
		{ "sys_nice",           CAP_SYS_NICE		},
		{ "sys_resource",       CAP_SYS_RESOURCE	},
		{ "sys_time",           CAP_SYS_TIME		},
		{ "sys_tty_config",     CAP_SYS_TTY_CONFIG	},
		{ "mknod",              CAP_MKNOD		},
		{ "lease",              CAP_LEASE		},
		{ "audit_write",        CAP_AUDIT_WRITE		},
		{ "audit_control",      CAP_AUDIT_CONTROL	},
		{ "setfcap",            CAP_SETFCAP		},
		{ "mac_override",       CAP_MAC_OVERRIDE	},
		{ "mac_admin",          CAP_MAC_ADMIN		},
		{ "syslog",             CAP_SYSLOG		},
		{ "wake_alarm",         CAP_WAKE_ALARM		},
		{ "block_suspend",      CAP_BLOCK_SUSPEND	},
		{ "audit_read",         CAP_AUDIT_READ		},
		{ "perfmon",            CAP_PERFMON		},
		{ "bpf",                CAP_BPF			},
		{ "checkpoint_restore", CAP_CHECKPOINT_RESTORE	},
		{ NULL, 0 }
	};
	int tt = lua_type(L, idx);
	int cap;

	switch (tt) {
	case LUA_TNUMBER:
		cap = luaL_checkinteger(L, idx);
		break;
	case LUA_TSTRING:
		cap = (int)tocflags(L, idx, idx, caps, -1);
		if (cap == -1)
			return luaL_argerror(L, idx, "invalid capability");
		break;
	default:
		return luaL_argerror(L, idx, "integer or string expected");
	}
	if (!cap_valid(cap))
		return luaL_argerror(L, idx, "invalid capability");
	return cap;
}

/*
 * [task:]capable(CAP_MAC_ADMIN)
 * [task:]capable('mac_admin')
 * [task:]capable(ns, CAP_MAC_ADMIN)
 * [task:]capable(task, 'mac_admin')
 * [task:]capable(task, 'mac_admin', 'noaudit', 'insetid')
 */
int aux_capable(lua_State *L, const struct cred *cred,
		struct user_namespace *default_ns, int idx)
{
	struct user_namespace *ns = default_ns;
	unsigned int opt = CAP_OPT_NONE;
	int top = lua_gettop(L);
	int cap;
	int err;

	if (top < idx)
		return luaL_error(L, "At least %d argument is required.", idx);

	if (top == idx) {
		cap = arg2cap(L, idx);
		err = cap_capable(cred, ns, cap, opt);
	} else if (tousernsp(L, idx)) {
		ns = touserns(L, idx);
		cap = arg2cap(L, idx + 1);
		if (top >= idx + 2)
			opt = tocflags(L, idx + 2, top,
				       lua_lsm_cap_opts, CAP_OPT_NONE);
		err = cap_capable(cred, ns, cap, opt);
	} else {
		struct task_struct *task = totask(L, idx);

		cap = arg2cap(L, idx + 1);
		if (top >= idx + 2)
			opt = tocflags(L, idx + 2, top,
				       lua_lsm_cap_opts, CAP_OPT_NONE);

		rcu_read_lock();
		err = cap_capable(cred, __task_cred(task)->user_ns, cap, opt);
		rcu_read_unlock();
	}

	lua_pushboolean(L, err == 0);
	return 1;
}
