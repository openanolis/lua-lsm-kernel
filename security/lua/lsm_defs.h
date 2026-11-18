/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#ifndef _SECURITY_LUA_LSM_LSM_DEFS_H
#define _SECURITY_LUA_LSM_LSM_DEFS_H

#include "lsm.h"
#include "lua_object.h"
#include <linux/lualib.h>
#include <linux/slab.h>


#define LSM_RET_DEFAULT(NAME)	(NAME##_default)

/* Wall time, including descheduling; selected at each module's entry. */
#define LUA_LSM_BUDGET_TASK_NS (20ULL * NSEC_PER_MSEC)
#define LUA_LSM_BUDGET_ATOMIC_NS (2ULL * NSEC_PER_MSEC)

static inline u64 lua_lsm_budget_ns(void)
{
	/* Without preempt counts, conservatively use the shorter deadline. */
	return !IS_ENABLED(CONFIG_PREEMPT_COUNT) || !in_task() || in_atomic() ||
	       irqs_disabled() || rcu_preempt_depth() > 0 ?
		LUA_LSM_BUDGET_ATOMIC_NS : LUA_LSM_BUDGET_TASK_NS;
}

#define LSM_HOOK(RET, DEFAULT, NAME, ...)						\
	extern const int __maybe_unused LSM_RET_DEFAULT(NAME);
#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK


#ifdef CONFIG_SECURITY_LUA_LSM_STATS

#define DECLARE_STATS_VARS()								\
	u64 ___stats_start = 0

#define START_STATS(NAME)								\
	do {										\
		___stats_start = ktime_get_ns();					\
	} while (0)

#define END_STATS(NAME)									\
	do {										\
		lua_lsm_hook_stats_record(__LL_NR_ ## NAME,				\
			ktime_get_ns() - ___stats_start);				\
	} while (0)

#else

#define DECLARE_STATS_VARS()
#define START_STATS(NAME)
#define END_STATS(NAME)

#endif


#define DECL_ARGS_0	void
#define DECL_ARGS_1
#define DECL_ARGS_2
#define DECL_ARGS_3
#define DECL_ARGS_4
#define DECL_ARGS_5
#define DECL_ARGS_6

#define DECL_RETP_ARGS_0	int *retp
#define DECL_RETP_ARGS_1	int *retp,
#define DECL_RETP_ARGS_2	int *retp,
#define DECL_RETP_ARGS_3	int *retp,
#define DECL_RETP_ARGS_4	int *retp,
#define DECL_RETP_ARGS_5	int *retp,
#define DECL_RETP_ARGS_6	int *retp,

#define CALL_RETP_ARGS_0	(&ret)
#define CALL_RETP_ARGS_1	(&ret),
#define CALL_RETP_ARGS_2	(&ret),
#define CALL_RETP_ARGS_3	(&ret),
#define CALL_RETP_ARGS_4	(&ret),
#define CALL_RETP_ARGS_5	(&ret),
#define CALL_RETP_ARGS_6	(&ret),

#define ASSIGN_FROM_FUNC_void(ret)
#define ASSIGN_FROM_FUNC_int(ret)	ret =

#define CALL_RES_void(L, top, ret)	do {} while (0)

static inline void lua_lsm_result_errno(lua_State *L, int idx, int *retp)
{
	int errnum = lua_tointeger(L, idx);

	if (errnum > 0 && errnum <= MAX_ERRNO)
		*retp = -errnum;
}

/*
 * hooks result format:
 *   [none]       : default value
 *   nil          : default value
 *   true         : 0
 *   false        : -EPERM
 *   false, errno : -errno
 *   nil, errno   : -errno
 */
static inline void lua_lsm_result_int(lua_State *L, int top, int *retp)
{
	int nres = lua_gettop(L) - top + 1;

	/* stack: [..., _M, res1, ...] */
	switch (nres) {
	case 0:
		break;
	case 1:
		if (lua_type(L, top) == LUA_TBOOLEAN)
			*retp = lua_toboolean(L, top) ? 0 : -EPERM;
		break;
	default:
		if (!lua_toboolean(L, top))
			lua_lsm_result_errno(L, top + 1, retp);
		break;
	}
	lua_pop(L, nres);
}

static inline void lua_lsm_result_bool(lua_State *L, int top, int *retp)
{
	int nres = lua_gettop(L) - top + 1;

	if (nres > 0 && lua_type(L, top) == LUA_TBOOLEAN)
		*retp = lua_toboolean(L, top) ? 1 : 0;
	lua_pop(L, nres);
}

static inline void lua_lsm_result_boolerr(lua_State *L, int top, int *retp)
{
	int nres = lua_gettop(L) - top + 1;
	int tt;

	switch (nres) {
	case 0:
		break;
	case 1:
		tt = lua_type(L, top);
		if (tt == LUA_TBOOLEAN)
			*retp = lua_toboolean(L, top) ? 1 : 0;
		break;
	default:
		tt = lua_type(L, top);
		if (tt == LUA_TBOOLEAN) {
			if (lua_toboolean(L, top))
				*retp = 1;
			else
				lua_lsm_result_errno(L, top + 1, retp);
		} else if (tt == LUA_TNIL) {
			lua_lsm_result_errno(L, top + 1, retp);
		}
		break;
	}
	lua_pop(L, nres);
}

#define CALL_RES_int(L, top, ret)	lua_lsm_result_int(L, top, &(ret))
#define CALL_RES_bool(L, top, ret)	lua_lsm_result_bool(L, top, &(ret))
#define CALL_RES_boolerr(L, top, ret)	lua_lsm_result_boolerr(L, top, &(ret))

#define LCALL_NRES_void		0
#define LCALL_NRES_int		LUA_MULTRET
#define LCALL_NRES_bool		LUA_MULTRET
#define LCALL_NRES_boolerr	LUA_MULTRET

/* All Lua work, including result conversion, runs inside lua_cpcall. */
#define LUA_CALL(rettype, L, top, ret)							\
	do {										\
		int nargs = lua_gettop(L) - top;				\
		lua_pushvalue(L, -nargs - 4);		/* env */		\
		lua_setfenv(L, -nargs - 6);		/* restore thread.env */	\
		lua_call(L, nargs, LCALL_NRES_ ## rettype);			\
		CALL_RES_ ## rettype(L, top, ret);				\
	} while (0)

#define END_VM_CALL_void(rettype, L, top, ret)	LUA_CALL(rettype, L, top, ret)
#define END_VM_CALL_int(rettype, L, top, ret)	lua_settop(L, (top) - 1)

#define RET_CHECK_void(NAME, ret)	do {} while (0)

#define RET_CHECK_int(NAME, ret)							\
	if ((ret) != LSM_RET_DEFAULT(NAME))						\
		break

#define RET_CHECK_bool(NAME, ret)	RET_CHECK_int(NAME, ret)
#define RET_CHECK_boolerr(NAME, ret)	RET_CHECK_int(NAME, ret)

/* Boolean hooks cannot carry errno: use each caller's predicate contract. */
static inline int lua_lsm_dispatch_failret_bool(unsigned int nr)
{
	switch (nr) {
	case __LL_NR_ismaclabel:
		return 1; /* Keep an unclassified security xattr out of generic lists. */
	default:
		/* No capability exemption, no known audit field, no flow match. */
		return 0;
	}
}

#define LUA_LSM_DISPATCH_FAILRET_DEFAULT(NAME, err) LSM_RET_DEFAULT(NAME)
#define LUA_LSM_DISPATCH_FAILRET_ERRNO(NAME, err) (err)
#define LUA_LSM_DISPATCH_FAILRET_GETSECURITY(NAME, err) (err)
#define LUA_LSM_DISPATCH_FAILRET_BOOL(NAME, err) \
	lua_lsm_dispatch_failret_bool(__LL_NR_ ## NAME)

/*
 * Root the original thread environment and registry key before entering the
 * protected call. CURR_ENV is a lightuserdata key with a permanent false entry
 * when idle: saving/restoring it cannot allocate, run GC or invoke policy code.
 * lua_cpcall also protects allocation of its own C closure and call frame.
 */
static inline int lua_lsm_dispatch(lua_State *L, lua_CFunction dispatch,
				   void *args, const char *hook)
{
	int top = lua_gettop(L);
	lua_Hook oldhook = lua_gethook(L);
	int oldmask = lua_gethookmask(L);
	int oldcount = lua_gethookcount(L);
	int status;

	lua_pushthread(L);
	lua_getfenv(L, -1);
	lua_pushlightuserdata(L, CURR_ENV);
	lua_pushvalue(L, -1);
	lua_rawget(L, LUA_REGISTRYINDEX);
	status = lua_cpcall(L, dispatch, args);
	if (lua_budget_end(L))
		status = LUA_ERRTIME;
	lua_resetdebughook(L);
	lua_sethook(L, oldhook, oldmask, oldcount);
	lua_pushvalue(L, top + 3);
	lua_pushvalue(L, top + 4);
	lua_rawset(L, LUA_REGISTRYINDEX);
	lua_pushvalue(L, top + 2);
	lua_setfenv(L, top + 1);
	lua_settop(L, top);
	if (!status)
		return 0;

	/* The decision never depends on the error object's type or contents. */
	pr_err_ratelimited("hook %s failed: Lua status %d\n", hook, status);
	return status == LUA_ERRMEM ? -ENOMEM : -EIO;
}

/* __MAP uses commas; context members need a separator-free variant. */
#define __LUA_FIELDS0()
#define __LUA_FIELDS1(t, a) t a;
#define __LUA_FIELDS2(t, a, ...) t a; __LUA_FIELDS1(__VA_ARGS__)
#define __LUA_FIELDS3(t, a, ...) t a; __LUA_FIELDS2(__VA_ARGS__)
#define __LUA_FIELDS4(t, a, ...) t a; __LUA_FIELDS3(__VA_ARGS__)
#define __LUA_FIELDS5(t, a, ...) t a; __LUA_FIELDS4(__VA_ARGS__)
#define __LUA_FIELDS6(t, a, ...) t a; __LUA_FIELDS5(__VA_ARGS__)
#define __LUA_INIT(t, a) .a = a
#define __LUA_ARG(t, a) args->a

#define LUA_LSM_DISPATCH_INIT_DEFAULT(args)
#define LUA_LSM_DISPATCH_INIT_ERRNO(args)
#define LUA_LSM_DISPATCH_INIT_BOOL(args)
#define LUA_LSM_DISPATCH_FINISH_DEFAULT(args, err) do {} while (0)
#define LUA_LSM_DISPATCH_FINISH_ERRNO(args, err) do {} while (0)
#define LUA_LSM_DISPATCH_FINISH_BOOL(args, err) do {} while (0)

/* Keep allocated output private until every protected completion check passes. */
#define LUA_LSM_DISPATCH_INIT_GETSECURITY(args)					\
	void *security_value = NULL;						\
	void **security_buffer = (args).buffer;					\
	if ((args).alloc)							\
		(args).buffer = &security_value

#define LUA_LSM_DISPATCH_FINISH_GETSECURITY(args, err)				\
	do {									\
		if ((args).alloc) {						\
			if ((err) || (args).ret < 0)				\
				kfree(security_value);				\
			else							\
				*security_buffer = security_value;			\
		}								\
	} while (0)

static inline bool lua_lsm_hook_active(unsigned int nr)
{
	return static_branch_unlikely(&lua_lsm_modules_active) &&
	       atomic_read(&lua_lsm_hook_stats[nr].nhooks) != 0;
}

static inline bool lua_lsm_hook_has_inactive_cleanup(unsigned int nr)
{
	switch (nr) {
	case __LL_NR_sb_free_security:
	case __LL_NR_inode_free_security_rcu:
	case __LL_NR_file_free_security:
	case __LL_NR_task_free:
	case __LL_NR_cred_free:
	case __LL_NR_msg_msg_free_security:
	case __LL_NR_msg_queue_free_security:
	case __LL_NR_shm_free_security:
	case __LL_NR_sem_free_security:
#ifdef CONFIG_SECURITY_NETWORK
	case __LL_NR_sk_free_security:
#endif
	case __LL_NR_bdev_free_security:
		return true;
	default:
		return false;
	}
}

#define LUA_LSM_INACTIVE_CLEANUP(x, NAME, ...)						\
	do {										\
		if (static_branch_unlikely(&lua_lsm_inactive_cleanup_armed) &&	\
		    lua_lsm_hook_has_inactive_cleanup(__LL_NR_ ## NAME)) {		\
			int idx = srcu_read_lock(&modules_ss);				\
			__postpone_ ## NAME(__MAP(x, __SC_ARGS, __VA_ARGS__));		\
			srcu_read_unlock(&modules_ss, idx);				\
		}									\
	} while (0)

/*
 * Each hook is split into a thin wrapper (lua_lsm_##NAME) and a noinline slow
 * path (__lua_lsm_slow_##NAME). With no policy loaded, both static branches are
 * patched to nops, so the wrapper takes no local's address and needs no
 * callee-saved registers: the compiler emits neither a stack frame nor a
 * -fstack-protector canary, making the idle per-hook cost a couple of nops plus
 * a constant return. Keeping the srcu walk, VM dispatch and inactive-object
 * cleanup in the slow path is what avoids paying that scaffolding on every
 * guarded syscall while Lua-LSM is dormant.
 */
#define LUA_LSM_DEFINEx(x, NAME, rettype, vmtype, pcalltype, failret, ...)		\
	static inline vmtype __lua_lsm_vm_ ## NAME(lua_State *L	__VA_OPT__(,)		\
					__MAP(x, __SC_DECL, __VA_ARGS__));		\
	struct __lua_lsm_args_ ## NAME {						\
		int ret;								\
		__LUA_FIELDS ## x(__VA_ARGS__)					\
	};										\
	static int __lua_lsm_dispatch_ ## NAME(lua_State *L)			\
	{										\
		struct __lua_lsm_args_ ## NAME *args = lua_touserdata(L, 1);	\
		struct lua_lsm_module *module;						\
		int ret = LSM_RET_DEFAULT(NAME);					\
		lua_settop(L, 0);							\
		lua_pushthread(L);							\
		lua_getfenv(L, -1);			/* save thread.fenv */		\
		lua_getfield(L, LUA_REGISTRYINDEX, "_MODULES");				\
		/* stack: [thread, env, _MODULES] */				\
		list_for_each_entry_srcu(module, &lsm_modules, list,			\
					srcu_read_lock_held(&modules_ss)) {		\
			if (!__BITMAP_ISSET(__LL_NR_ ## NAME, &module->hookfuncs))	\
				continue;						\
			if (module->state != LMS_STATE_LIVE)				\
				continue;						\
			if (lua_budget_end(L))					\
				return lua_rethrow(L, LUA_ERRTIME);			\
			lua_budget_begin(L, lua_lsm_budget_ns());			\
			lua_getfield(L, -1, module->name);				\
			lua_getfield(L, -1, #NAME);					\
			WARN_ON(lua_gettop(L) != 5);					\
			/* stack: [thread, env, _MODULES, _M, lfunc] */	\
			if (lua_isfunction(L, -1)) {					\
				int top = lua_gettop(L);				\
				lua_getfenv(L, -1);					\
				*newtask_nomain(L) = current;				\
				lua_setfield(L, -2, "current");				\
				lua_lsm_set_current_env(L);				\
				ASSIGN_FROM_FUNC_ ## vmtype(ret)			\
					__lua_lsm_vm_ ## NAME(L __VA_OPT__(,)		\
						__MAP(x, __LUA_ARG, __VA_ARGS__));	\
				END_VM_CALL_ ## vmtype(pcalltype, L, top, ret);		\
			} else {							\
				return luaL_error(L, "hook '%s' is not a function", #NAME);\
			}								\
			/* No debug callback may outlive its module deadline. */	\
			lua_resetdebughook(L);					\
			/* Keep the deadline active through C return and GC. */	\
			lua_pop(L, 1);			/* pop _M */			\
			RET_CHECK_ ## pcalltype(NAME, ret);				\
		}									\
		args->ret = ret;							\
		return 0;								\
	}										\
	static inline int __lua_lsm_ ## NAME(DECL_RETP_ARGS_ ## x			\
					__MAP(x, __SC_DECL, __VA_ARGS__))		\
	{										\
		struct __lua_lsm_args_ ## NAME args = {				\
			.ret = LSM_RET_DEFAULT(NAME),				\
			__MAP(x, __LUA_INIT, __VA_ARGS__)				\
		};									\
		lua_State *L;								\
		int err = 0;								\
		LUA_LSM_DISPATCH_INIT_ ## failret(args);				\
		if (!lua_lsm_hook_active(__LL_NR_ ## NAME))				\
			goto out;							\
		L = lvm_get();								\
		if (!L) {								\
			if (!lvm_current_task_teardown()) {				\
				err = -ENOMEM;						\
				pr_err_ratelimited("hook %s failed: VM unavailable\n", #NAME);\
			}								\
			goto out;							\
		}									\
		err = lua_lsm_dispatch(L, __lua_lsm_dispatch_ ## NAME, &args, #NAME);\
		lvm_put(L);								\
out:											\
		LUA_LSM_DISPATCH_FINISH_ ## failret(args, err);		\
		*retp = args.ret;							\
		return err;								\
	}										\
	static noinline rettype __lua_lsm_slow_ ## NAME(DECL_ARGS_ ## x		\
				__MAP(x, __SC_DECL, __VA_ARGS__))			\
	{										\
		int ret;								\
		DECLARE_STATS_VARS();							\
		if (!lua_lsm_hook_active(__LL_NR_ ## NAME)) {				\
			LUA_LSM_INACTIVE_CLEANUP(x, NAME, ##__VA_ARGS__);		\
			return (rettype)LSM_RET_DEFAULT(NAME);				\
		}									\
		START_STATS(NAME);							\
		ret = __prepare_ ## NAME(__MAP(x, __SC_ARGS, __VA_ARGS__));		\
		if (ret >= 0) {								\
			int idx = srcu_read_lock(&modules_ss);				\
			if (static_branch_unlikely(&lua_lsm_modules_active)) {		\
				int err = __lua_lsm_ ## NAME(CALL_RETP_ARGS_ ## x	\
					__MAP(x, __SC_ARGS, __VA_ARGS__));		\
				if (err)						\
					ret = LUA_LSM_DISPATCH_FAILRET_ ## failret(NAME, err);\
			} else {							\
				ret = LSM_RET_DEFAULT(NAME);				\
			}								\
			__postpone_ ## NAME(__MAP(x, __SC_ARGS, __VA_ARGS__));		\
			srcu_read_unlock(&modules_ss, idx);				\
		}									\
		END_STATS(NAME);							\
		return (rettype)ret;							\
	}										\
	rettype lua_lsm_ ## NAME(DECL_ARGS_ ## x					\
				__MAP(x, __SC_DECL, __VA_ARGS__))			\
	{										\
		if (static_branch_unlikely(&lua_lsm_modules_active))			\
			return __lua_lsm_slow_ ## NAME(__MAP(x, __SC_ARGS, __VA_ARGS__));\
		if (static_branch_unlikely(&lua_lsm_inactive_cleanup_armed))		\
			return __lua_lsm_slow_ ## NAME(__MAP(x, __SC_ARGS, __VA_ARGS__));\
		return (rettype)LSM_RET_DEFAULT(NAME);					\
	}										\
	static inline vmtype __lua_lsm_vm_ ## NAME(lua_State *L __VA_OPT__(,)		\
					__MAP(x, __SC_DECL, __VA_ARGS__))

/*****************************************************************************/

#define LUA_LSM_VOID_DEFINE0(name, ...)					\
	LUA_LSM_DEFINEx(0, name, void, void, void, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_VOID_DEFINE1(name, ...)					\
	LUA_LSM_DEFINEx(1, name, void, void, void, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_VOID_DEFINE2(name, ...)					\
	LUA_LSM_DEFINEx(2, name, void, void, void, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_VOID_DEFINE3(name, ...)					\
	LUA_LSM_DEFINEx(3, name, void, void, void, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_VOID_DEFINE4(name, ...)					\
	LUA_LSM_DEFINEx(4, name, void, void, void, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_VOID_DEFINE5(name, ...)					\
	LUA_LSM_DEFINEx(5, name, void, void, void, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_VOID_DEFINE6(name, ...)					\
	LUA_LSM_DEFINEx(6, name, void, void, void, DEFAULT, ##__VA_ARGS__)

#define LUA_LSM_VOID_NAKED_DEFINE0(name, ...)				\
	LUA_LSM_DEFINEx(0, name, void, int, int, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_VOID_NAKED_DEFINE1(name, ...)				\
	LUA_LSM_DEFINEx(1, name, void, int, int, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_VOID_NAKED_DEFINE2(name, ...)				\
	LUA_LSM_DEFINEx(2, name, void, int, int, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_VOID_NAKED_DEFINE3(name, ...)				\
	LUA_LSM_DEFINEx(3, name, void, int, int, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_VOID_NAKED_DEFINE4(name, ...)				\
	LUA_LSM_DEFINEx(4, name, void, int, int, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_VOID_NAKED_DEFINE5(name, ...)				\
	LUA_LSM_DEFINEx(5, name, void, int, int, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_VOID_NAKED_DEFINE6(name, ...)				\
	LUA_LSM_DEFINEx(6, name, void, int, int, DEFAULT, ##__VA_ARGS__)

#define LUA_LSM_INT_DEFINE0(name, ...)					\
	LUA_LSM_DEFINEx(0, name, int, void, int, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_DEFINE1(name, ...)					\
	LUA_LSM_DEFINEx(1, name, int, void, int, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_DEFINE2(name, ...)					\
	LUA_LSM_DEFINEx(2, name, int, void, int, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_DEFINE3(name, ...)					\
	LUA_LSM_DEFINEx(3, name, int, void, int, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_DEFINE4(name, ...)					\
	LUA_LSM_DEFINEx(4, name, int, void, int, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_DEFINE5(name, ...)					\
	LUA_LSM_DEFINEx(5, name, int, void, int, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_DEFINE6(name, ...)					\
	LUA_LSM_DEFINEx(6, name, int, void, int, ERRNO, ##__VA_ARGS__)

#define LUA_LSM_INT_BOOL_DEFINE0(name, ...)				\
	LUA_LSM_DEFINEx(0, name, int, void, bool, BOOL, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOL_DEFINE1(name, ...)				\
	LUA_LSM_DEFINEx(1, name, int, void, bool, BOOL, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOL_DEFINE2(name, ...)				\
	LUA_LSM_DEFINEx(2, name, int, void, bool, BOOL, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOL_DEFINE3(name, ...)				\
	LUA_LSM_DEFINEx(3, name, int, void, bool, BOOL, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOL_DEFINE4(name, ...)				\
	LUA_LSM_DEFINEx(4, name, int, void, bool, BOOL, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOL_DEFINE5(name, ...)				\
	LUA_LSM_DEFINEx(5, name, int, void, bool, BOOL, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOL_DEFINE6(name, ...)				\
	LUA_LSM_DEFINEx(6, name, int, void, bool, BOOL, ##__VA_ARGS__)

#define LUA_LSM_INT_BOOLERR_DEFINE0(name, ...)				\
	LUA_LSM_DEFINEx(0, name, int, void, boolerr, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOLERR_DEFINE1(name, ...)				\
	LUA_LSM_DEFINEx(1, name, int, void, boolerr, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOLERR_DEFINE2(name, ...)				\
	LUA_LSM_DEFINEx(2, name, int, void, boolerr, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOLERR_DEFINE3(name, ...)				\
	LUA_LSM_DEFINEx(3, name, int, void, boolerr, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOLERR_DEFINE4(name, ...)				\
	LUA_LSM_DEFINEx(4, name, int, void, boolerr, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOLERR_DEFINE5(name, ...)				\
	LUA_LSM_DEFINEx(5, name, int, void, boolerr, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOLERR_DEFINE6(name, ...)				\
	LUA_LSM_DEFINEx(6, name, int, void, boolerr, ERRNO, ##__VA_ARGS__)

#define LUA_LSM_INT_NAKED_DEFINE0(name, ...)				\
	LUA_LSM_DEFINEx(0, name, int, int, int, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_NAKED_DEFINE1(name, ...)				\
	LUA_LSM_DEFINEx(1, name, int, int, int, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_NAKED_DEFINE2(name, ...)				\
	LUA_LSM_DEFINEx(2, name, int, int, int, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_NAKED_DEFINE3(name, ...)				\
	LUA_LSM_DEFINEx(3, name, int, int, int, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_NAKED_DEFINE4(name, ...)				\
	LUA_LSM_DEFINEx(4, name, int, int, int, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_NAKED_DEFINE5(name, ...)				\
	LUA_LSM_DEFINEx(5, name, int, int, int, ERRNO, ##__VA_ARGS__)
#define LUA_LSM_INT_NAKED_DEFINE6(name, ...)				\
	LUA_LSM_DEFINEx(6, name, int, int, int, ERRNO, ##__VA_ARGS__)

/* inode_getsecurity transfers an allocation only after dispatch completes. */
#define LUA_LSM_INT_GETSECURITY_DEFINE5(name, ...)				\
	LUA_LSM_DEFINEx(5, name, int, int, int, GETSECURITY, ##__VA_ARGS__)


/* prepare and postpone function macro */

#define LUA_LSM_PREPARE_DEFINEx(x, NAME, ...)						\
	inline int __prepare_ ## NAME(DECL_ARGS_ ## x					\
					__MAP(x, __SC_DECL, __VA_ARGS__))

#define LUA_LSM_POSTPONE_DEFINEx(x, NAME, ...)						\
	inline void __postpone_ ## NAME(DECL_ARGS_ ## x					\
					__MAP(x, __SC_DECL, __VA_ARGS__))

#define LUA_LSM_PREPARE_DEFINE0(NAME, ...)	LUA_LSM_PREPARE_DEFINEx(0, NAME, ##__VA_ARGS__)
#define LUA_LSM_PREPARE_DEFINE1(NAME, ...)	LUA_LSM_PREPARE_DEFINEx(1, NAME, ##__VA_ARGS__)
#define LUA_LSM_PREPARE_DEFINE2(NAME, ...)	LUA_LSM_PREPARE_DEFINEx(2, NAME, ##__VA_ARGS__)
#define LUA_LSM_PREPARE_DEFINE3(NAME, ...)	LUA_LSM_PREPARE_DEFINEx(3, NAME, ##__VA_ARGS__)
#define LUA_LSM_PREPARE_DEFINE4(NAME, ...)	LUA_LSM_PREPARE_DEFINEx(4, NAME, ##__VA_ARGS__)
#define LUA_LSM_PREPARE_DEFINE5(NAME, ...)	LUA_LSM_PREPARE_DEFINEx(5, NAME, ##__VA_ARGS__)
#define LUA_LSM_PREPARE_DEFINE6(NAME, ...)	LUA_LSM_PREPARE_DEFINEx(6, NAME, ##__VA_ARGS__)

#define LUA_LSM_POSTPONE_DEFINE0(NAME, ...)	LUA_LSM_POSTPONE_DEFINEx(0, NAME, ##__VA_ARGS__)
#define LUA_LSM_POSTPONE_DEFINE1(NAME, ...)	LUA_LSM_POSTPONE_DEFINEx(1, NAME, ##__VA_ARGS__)
#define LUA_LSM_POSTPONE_DEFINE2(NAME, ...)	LUA_LSM_POSTPONE_DEFINEx(2, NAME, ##__VA_ARGS__)
#define LUA_LSM_POSTPONE_DEFINE3(NAME, ...)	LUA_LSM_POSTPONE_DEFINEx(3, NAME, ##__VA_ARGS__)
#define LUA_LSM_POSTPONE_DEFINE4(NAME, ...)	LUA_LSM_POSTPONE_DEFINEx(4, NAME, ##__VA_ARGS__)
#define LUA_LSM_POSTPONE_DEFINE5(NAME, ...)	LUA_LSM_POSTPONE_DEFINEx(5, NAME, ##__VA_ARGS__)
#define LUA_LSM_POSTPONE_DEFINE6(NAME, ...)	LUA_LSM_POSTPONE_DEFINEx(6, NAME, ##__VA_ARGS__)


#define LSM_HOOK(RET, DEFAULT, NAME, ...)	RET lua_lsm_ ## NAME(__VA_ARGS__);
#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK

#endif /* ! _SECURITY_LUA_LSM_LSM_DEFS_H */
