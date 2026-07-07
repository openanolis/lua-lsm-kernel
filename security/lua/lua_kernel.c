/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM - kernel API library.
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#define LUA_API_KMOD

#include "debug.h"
#include <linux/version.h>
#include <linux/args.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/security.h>
#include <linux/ptrace.h>
#include <linux/user_namespace.h>
#include <linux/lua.h>
#include <linux/lualib.h>
#include <linux/lauxlib.h>
#include <linux/lua_lsm_api.h>
#include <linux/securebits.h>
#include "auxlib.h"
#include "kvcache.h"
#include "lua_object.h"

/**********************************  cred **********************************/

static int kernel_cred_uids(lua_State *L)
{
	const struct cred *cred = tocred(L, 1);

	lua_pushinteger(L, cred->uid.val);
	lua_pushinteger(L, cred->euid.val);
	lua_pushinteger(L, cred->suid.val);
	lua_pushinteger(L, cred->fsuid.val);
	return 4;
}

static int kernel_cred_gids(lua_State *L)
{
	const struct cred *cred = tocred(L, 1);

	lua_pushinteger(L, cred->gid.val);
	lua_pushinteger(L, cred->egid.val);
	lua_pushinteger(L, cred->sgid.val);
	lua_pushinteger(L, cred->fsgid.val);
	return 4;
}

static int kernel_cred_cap_eip(lua_State *L)
{
	struct cred *cred = tocred(L, 1);
	int top = lua_gettop(L);

	if (top > 4)
		return luaL_error(L, "wrong number of arguments");
	if (top == 1) {
		/* get caps */
		*newcap(L) = cred->cap_effective;
		*newcap(L) = cred->cap_inheritable;
		*newcap(L) = cred->cap_permitted;
		return 3;
	}
	/* set caps */
	if (top >= 2 && !lua_isnil(L, 2))
		cred->cap_effective = tocap(L, 2);
	if (top >= 3 && !lua_isnil(L, 3))
		cred->cap_inheritable = tocap(L, 3);
	if (top == 4 && !lua_isnil(L, 4))
		cred->cap_permitted = tocap(L, 4);
	lua_settop(L, 1);
	return 1;
}

static int kernel_cred_cap_bset(lua_State *L)
{
	struct cred *cred = tocred(L, 1);

	if (lua_gettop(L) == 1) {
		*newcap(L) = cred->cap_bset;
		return 1;
	}

	cred->cap_bset = tocap(L, 2);
	lua_settop(L, 1);
	return 1;
}

static int kernel_cred_cap_ambient(lua_State *L)
{
	struct cred *cred = tocred(L, 1);

	if (lua_gettop(L) == 1) {
		*newcap(L) = cred->cap_ambient;
		return 1;
	}

	cred->cap_ambient = tocap(L, 2);
	lua_settop(L, 1);
	return 1;
}

/*
 * table = cred:securebits()
 * bool = cred:securebits('keep_caps')
 * bool = cred:securebits(true, 'keep_caps', 'noroot')
 */
static int kernel_cred_securebits(lua_State *L)
{
	static const struct cflag_opt opts[] = {
		{ "noroot",			SECBIT_NOROOT			},
		{ "no_setuid_fixup",		SECBIT_NO_SETUID_FIXUP		},
		{ "keep_caps",			SECBIT_KEEP_CAPS		},
		{ "no_cap_ambient_raise",	SECBIT_NO_CAP_AMBIENT_RAISE	},
		{ "exec_restrict_file",		SECBIT_EXEC_RESTRICT_FILE	},
		{ "exec_deny_interactive",	SECBIT_EXEC_DENY_INTERACTIVE	},
		{ NULL, 0 }
	};
	struct cred *cred = tocred(L, 1);
	int top = lua_gettop(L);

	if (top >= 2) {
		int start = (top == 2) ? 2 : 3;
		int and = lua_isboolean(L, 2) && lua_toboolean(L, 2);
		unsigned int flags = tocflags(L, start, top, opts, 0);
		unsigned int res = cred->securebits & flags;

		lua_pushboolean(L, and ? res == flags : (int)res);
		return 1;
	}
	if (top == 1) {
		table_fromopts(L, opts, 0, (unsigned int)cred->securebits);
		return 1;
	}
	return 0;
}

static int kernel_cred_userns(lua_State *L)
{
	const struct cred *cred = tocred(L, 1);

	*newgcuserns(L) = get_user_ns(cred->user_ns);
	return 1;
}

static int kernel_cred_capable(lua_State *L)
{
	const struct cred *cred = tocred(L, 1);

	return aux_capable(L, cred, cred->user_ns, 2);
}

static const luaL_Reg cred_meth[] = {
	{ "uids",		kernel_cred_uids	},
	{ "gids",		kernel_cred_gids	},
	{ "cap_eip",		kernel_cred_cap_eip	},
	{ "cap_bset",		kernel_cred_cap_bset	},
	{ "cap_ambient",	kernel_cred_cap_ambient	},
	{ "securebits",		kernel_cred_securebits	},
	{ "userns",		kernel_cred_userns	},
	{ "capable",		kernel_cred_capable	},
	{ NULL, NULL }
};

/********************************* userns *********************************/

static int kernel_userns_is_initial(lua_State *L)
{
	struct user_namespace *ns = touserns(L, 1);

	lua_pushboolean(L, ns == &init_user_ns);
	return 1;
}

static int kernel_userns_level(lua_State *L)
{
	struct user_namespace *ns = touserns(L, 1);

	lua_pushinteger(L, ns->level);
	return 1;
}

static int kernel_userns_owner_uid(lua_State *L)
{
	struct user_namespace *ns = touserns(L, 1);

	lua_pushinteger(L, (lua_Integer)ns->owner.val);
	return 1;
}

static int kernel_userns_owner_gid(lua_State *L)
{
	struct user_namespace *ns = touserns(L, 1);

	lua_pushinteger(L, (lua_Integer)ns->group.val);
	return 1;
}

static int kernel_userns_inum(lua_State *L)
{
	struct user_namespace *ns = touserns(L, 1);

	lua_pushinteger(L, (lua_Integer)ns->ns.inum);
	return 1;
}

static int kernel_userns_same(lua_State *L)
{
	struct user_namespace *ns = touserns(L, 1);
	struct user_namespace *other = touserns(L, 2);

	lua_pushboolean(L, ns == other);
	return 1;
}

static int meth_userns_tostring(lua_State *L)
{
	struct user_namespace *ns = touserns(L, 1);

	lua_pushfstring(L, "userns: <inum = %d, level = %d>",
			(int)ns->ns.inum, ns->level);
	return 1;
}

static const luaL_Reg userns_meth[] = {
	{ "is_initial",	kernel_userns_is_initial	},
	{ "level",	kernel_userns_level		},
	{ "owner_uid",	kernel_userns_owner_uid		},
	{ "owner_gid",	kernel_userns_owner_gid		},
	{ "inum",	kernel_userns_inum		},
	{ "same",	kernel_userns_same		},
	{ "__tostring",	meth_userns_tostring		},
	{ NULL, NULL }
};

static int meth_userns_gc(lua_State *L)
{
	struct user_namespace **nsp = togcusernsp(L, 1);

	if (*nsp) {
		put_user_ns(*nsp);
		*nsp = NULL;
	}
	return 0;
}

static const luaL_Reg userns_gc_meth[] = {
	{ "__tostring",	meth_userns_tostring		},
	{ "__gc",	meth_userns_gc			},
	{ NULL, NULL }
};

/**********************************  task **********************************/

static int kernel_task_pids(lua_State *L)
{
	struct task_struct *task = totask(L, 1);

	lua_pushinteger(L, task->pid);
	lua_pushinteger(L, task->tgid);
	return 2;
}

static int kernel_task_cred(lua_State *L)
{
	struct task_struct *task = totask(L, 1);
	*(const struct cred **)newcred(L) = get_task_cred(task);
	return 1;
}

static int kernel_task_userns(lua_State *L)
{
	struct task_struct *task = totask(L, 1);
	const struct cred *cred = get_task_cred(task);

	*newgcuserns(L) = get_user_ns(cred->user_ns);
	put_cred(cred);
	return 1;
}

static int kernel_task_comm(lua_State *L)
{
	struct task_struct *task = totask(L, 1);

	lua_pushstring(L, task->comm);
	return 1;
}

static int kernel_task_nr_threads(lua_State *L)
{
	struct task_struct *task = totask(L, 1);

	lua_pushinteger(L, get_nr_threads(task));
	return 1;
}

static int kernel_task_group_leader(lua_State *L)
{
	struct task_struct *task = totask(L, 1);

	if (!thread_group_leader(task))
		*newtask(L) = rcu_dereference(task->group_leader);
	else
		lua_settop(L, 1);

	return 1;
}

static int kernel_task_thread_group_leader(lua_State *L)
{
	struct task_struct *task = totask(L, 1);

	lua_pushboolean(L, thread_group_leader(task));
	return 1;
}

static int kernel_task_same_thread_group(lua_State *L)
{
	struct task_struct *task1 = totask(L, 1);
	struct task_struct *task2 = totask(L, 2);

	lua_pushboolean(L, same_thread_group(task1, task2));
	return 1;
}

static int kernel_task_same_group_ptracer(lua_State *L)
{
	struct task_struct *tracee = totask(L, 1);
	struct task_struct *tracer = totask(L, 2);
	struct task_struct *parent;
	int res = 0;

	rcu_read_lock();
	parent = ptrace_parent(tracee);
	if (parent && same_thread_group(parent, tracer))
		res = 1;
	rcu_read_unlock();
	lua_pushboolean(L, res);
	return 1;
}

static int kernel_task_is_idle(lua_State *L)
{
	struct task_struct *task = totask(L, 1);

	lua_pushboolean(L, is_idle_task(task));
	return 1;
}

static int kernel_task_exe_file(lua_State *L)
{
	struct task_struct *task = totask(L, 1);
	struct file *exe_file;

	if (spin_is_locked(&task->alloc_lock)) {
		lua_pushnil(L);
		lua_pushstring(L, "busy");
		return 2;
	}
	exe_file = aux_get_task_exe_file(task);
	if (!exe_file)
		return 0;
	*newgcfile(L) = exe_file;
	return 1;
}

static int kernel_task_exepath(lua_State *L)
{
	struct task_struct *task = totask(L, 1);
	struct file *file;
	int nres = 0;

	if (task == current) {
		struct mm_struct *mm = current->mm;

		if (!mm)
			return 0;
		file = aux_get_mm_exe_file(mm);
	} else {
		if (spin_is_locked(&task->alloc_lock)) {
			lua_pushnil(L);
			lua_pushstring(L, "busy");
			return 2;
		}
		file = aux_get_task_exe_file(task);
	}
	if (file) {
		nres = aux_file_path(L, file);
		fput(file);
	}
	return nres;
}

static int kernel_task_cmdline(lua_State *L)
{
	struct task_struct *task = totask(L, 1);
	char *cmdline = kstrdup_quotable_cmdline(task, lua_lsm_gfp());

	lua_pushstring(L, cmdline);
	kfree(cmdline);
	return 1;
}

static int kernel_task_capable(lua_State *L)
{
	struct task_struct *task = totask(L, 1);
	const struct cred *cred;
	int nres;

	rcu_read_lock();
	cred = __task_cred(task);
	nres = aux_capable(L, cred, cred->user_ns, 2);
	rcu_read_unlock();
	return nres;
}

static int kernel_task_is_descendant(lua_State *L)
{
	struct task_struct *child = totask(L, 1);
	struct task_struct *parent;
	struct task_struct *parent_ref = NULL;
	int tt = lua_type(L, 2);
	int res = 0;

	switch (tt) {
	case LUA_TNUMBER:
		parent_ref = aux_find_get_task_by_vpid((pid_t)lua_tointeger(L, 2));
		if (!parent_ref)
			return luaL_argerror(L, 2, "invalid pid");
		parent = parent_ref;
		break;
	case LUA_TUSERDATA:
		parent = totask(L, 2);
		break;
	default:
		return luaL_argerror(L, 2, "task or pid expected");
	}

	rcu_read_lock();
	if (!thread_group_leader(parent))
		parent = rcu_dereference(parent->group_leader);
	while (child->pid > 0) {
		if (!thread_group_leader(child))
			child = rcu_dereference(child->group_leader);
		if (child == parent) {
			res = 1;
			break;
		}
		child = rcu_dereference(child->real_parent);
	}
	rcu_read_unlock();

	if (parent_ref)
		put_task_struct(parent_ref);

	lua_pushboolean(L, res);
	return 1;
}

static int kernel_task_pid_alive(lua_State *L)
{
	struct task_struct *task = totask(L, 1);

	lua_pushboolean(L, pid_alive(task));
	return 1;
}

static int meth_task_tostring(lua_State *L)
{
	struct task_struct *task = totask(L, 1);

	lua_pushfstring(L, "task: '%s'", task->comm);
	return 1;
}

static const luaL_Reg task_meth[] = {
	{ "pids",			kernel_task_pids		},
	{ "cred",			kernel_task_cred		},
	{ "userns",			kernel_task_userns		},
	{ "comm",			kernel_task_comm		},
	{ "nr_threads",			kernel_task_nr_threads		},
	{ "group_leader",		kernel_task_group_leader	},
	{ "thread_group_leader",	kernel_task_thread_group_leader	},
	{ "same_thread_group",		kernel_task_same_thread_group	},
	{ "same_group_ptracer",		kernel_task_same_group_ptracer	},
	{ "is_idle",			kernel_task_is_idle		},
	{ "exe_file",			kernel_task_exe_file		},
	{ "exepath",			kernel_task_exepath		},
	{ "cmdline",			kernel_task_cmdline		},
	{ "capable",			kernel_task_capable		},
	{ "is_descendant",		kernel_task_is_descendant	},
	{ "pid_alive",			kernel_task_pid_alive		},
	{ "__tostring",			meth_task_tostring		},
	{ NULL, NULL }
};

static int meth_task_gc(lua_State *L)
{
	struct task_struct **taskp = togctaskp(L, 1);

	if (*taskp) {
		put_task_struct(*taskp);
		*taskp = NULL;
	}
	return 0;
}

static const luaL_Reg task_gc_meth[] = {
	{ "__tostring",			meth_task_tostring		},
	{ "__gc",			meth_task_gc			},
	{ NULL, NULL }
};

/**********************************  lib  **********************************/

static int kernel_version(lua_State *L)
{
	lua_pushinteger(L, LINUX_VERSION_MAJOR);
	lua_pushinteger(L, LINUX_VERSION_PATCHLEVEL);
	lua_pushinteger(L, LINUX_VERSION_SUBLEVEL);
	return 3;
}

static int kernel_lsm_funcs(lua_State *L)
{
	static const struct {
		const char *funcname;
		const char *rtype;
		int nargs;
	} lsm_funcs[] = {
		#define LSM_HOOK(RET, DEFAULT, NAME, ...)		\
			{ #NAME, #RET, COUNT_ARGS(__VA_ARGS__) },
		#include <linux/lsm_hook_defs.h>
		#undef LSM_HOOK
	};
	int i;
	int n = 0;

	for (i = 0; i < ARRAY_SIZE(lsm_funcs); i++) {
		if (lua_lsm_hook_supported(i))
			n++;
	}

	lua_createtable(L, n, 0);
	n = 0;
	for (i = 0; i < ARRAY_SIZE(lsm_funcs); i++) {
		if (!lua_lsm_hook_supported(i))
			continue;

		lua_createtable(L, 3, 0);
		lua_pushstring(L, lsm_funcs[i].funcname);
		lua_rawseti(L, -2, 1);
		lua_pushstring(L, lsm_funcs[i].rtype);
		lua_rawseti(L, -2, 2);
		lua_pushinteger(L, lsm_funcs[i].nargs);
		lua_rawseti(L, -2, 3);
		/* res[n + 1] = { funcname, rtype, nargs } */
		lua_rawseti(L, -2, ++n);
	}
	return 1;
}

static int kernel_random(lua_State *L)
{
	int l, u;
	u32 r;

	switch (lua_gettop(L)) {
	case 0:
		r = get_random_u32();
		break;
	case 1:
		u = luaL_checkint(L, 1);
		luaL_argcheck(L, 0 <= u, 1, "interval is empty");
		/* r: [1, u] */
		r = get_random_u32_below((u32)u) + 1;
		break;
	case 2:
		l = luaL_checkint(L, 1);
		u = luaL_checkint(L, 2);
		luaL_argcheck(L, l <= u, 2, "interval is empty");
		/* r: [l, u] */
		r = get_random_u32_inclusive((u32)l, (u32)u);
		break;
	default:
		return luaL_error(L, "wrong number of arguments");
	}
	lua_pushinteger(L, r);
	return 1;
}

static int kernel_ktime_seconds(lua_State *L)
{
	int monotonic = lua_toboolean(L, 1);
	time64_t sec;

	if (monotonic)
		sec = ktime_get_seconds();
	else
		sec = ktime_get_real_seconds();
	lua_pushnumber(L, sec);
	return 1;
}

static int kernel_rcu_read_lock(lua_State *L)
{
	rcu_read_lock();
	return 0;
}

static int kernel_rcu_read_unlock(lua_State *L)
{
	rcu_read_unlock();
	return 0;
}

static int kernel_task_from_pid(lua_State *L)
{
	pid_t nr = (pid_t)luaL_checkinteger(L, 1);
	struct task_struct *task = aux_find_get_task_by_vpid(nr);

	if (!task)
		return 0;
	*newgctask(L) = task;
	return 1;
}

static int kernel_printk(lua_State *L)
{
	const char *s = luaL_checkstring(L, 1);

	pr_info("%s\n", s);
	return 0;
}

#define DEF_PRINTK_LEVEL(name)						\
	static int kernel_pr_ ## name(lua_State *L)			\
	{								\
		const char *s = luaL_checkstring(L, 1);			\
		pr_ ## name("%s\n", s);					\
		return 0;						\
	}

#define PRINTK_LEVEL_LISTS						\
	XX(emerg)							\
	XX(alert)							\
	XX(crit)							\
	XX(err)								\
	XX(warn)							\
	XX(notice)							\
	XX(info)							\
	XX(cont)							\
	XX(devel)							\
	XX(debug)

#define XX(name)	DEF_PRINTK_LEVEL(name)
PRINTK_LEVEL_LISTS
#undef XX

static const luaL_Reg kernellib[] = {
	{ "version",		kernel_version		},
	{ "lsm_funcs",		kernel_lsm_funcs	},
	{ "random",		kernel_random		},
	{ "ktime_seconds",	kernel_ktime_seconds	},
	{ "rcu_read_lock",	kernel_rcu_read_lock	},
	{ "rcu_read_unlock",	kernel_rcu_read_unlock	},
	{ "task_from_pid",	kernel_task_from_pid	},
	{ "printk",		kernel_printk		},

#define XX(name)    { "pr_" #name, kernel_pr_ ## name },
	PRINTK_LEVEL_LISTS
#undef XX

	{ NULL, NULL }
};

static int kernel_init_table(lua_State *L)
{
	static const struct {
		const char *name;
		const luaL_Reg *meth;
		const luaL_Reg *gc_meth;
	} metas[] = {
		{ "task",	task_meth,	task_gc_meth },
		{ "cred",	cred_meth,	NULL },
		{ "userns",	userns_meth,	userns_gc_meth },
		{ "perfevent",	NULL,		NULL },
		{ "ipc",	NULL,		NULL },
		{ "msgmsg",	NULL,		NULL },
		{ "key",	NULL,		NULL },
		{ "bdev",	NULL,		NULL },
	};
	size_t i;
	int err;

	for (i = 0; i < ARRAY_SIZE(metas); i++) {
		err = lua_api_lib_meta_install(L, metas[i].name,
					       metas[i].meth,
					       metas[i].gc_meth);
		if (err)
			return err;
	}
	return 0;
}

static struct lua_api_lib kernel_desc = {
	.name		= "kernel",
	.funcs		= kernellib,
	.init_table	= kernel_init_table,
	.owner		= THIS_MODULE,
	.abi_version	= LUA_API_LIB_ABI_VERSION,
};

static int __init lua_kernel_lib_init(void)
{
	int err;

#ifdef MODULE
	err = lua_api_lib_register(&kernel_desc);
#else
	err = __lua_api_lib_register(&kernel_desc);
#endif
	if (err)
		pr_err("lua-lsm: failed to register 'kernel' library: %d\n",
		       err);
	return err;
}

static void __exit lua_kernel_lib_exit(void)
{
}

module_init(lua_kernel_lib_init);
module_exit(lua_kernel_lib_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("lua-lsm kernel API library");
