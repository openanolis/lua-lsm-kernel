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


#define LSM_RET_DEFAULT(NAME)	(NAME##_default)

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

#define PCALL_RES_void(L, top, ret)	do {} while (0)

static inline void lua_lsm_pcall_res_errno(lua_State *L, int idx, int *retp)
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
static inline void lua_lsm_pcall_res_int(lua_State *L, int top, int *retp)
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
			lua_lsm_pcall_res_errno(L, top + 1, retp);
		break;
	}
	lua_pop(L, nres);
}

static inline void lua_lsm_pcall_res_bool(lua_State *L, int top, int *retp)
{
	int nres = lua_gettop(L) - top + 1;

	if (nres > 0 && lua_type(L, top) == LUA_TBOOLEAN)
		*retp = lua_toboolean(L, top) ? 1 : 0;
	lua_pop(L, nres);
}

static inline void lua_lsm_pcall_res_boolerr(lua_State *L, int top, int *retp)
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
				lua_lsm_pcall_res_errno(L, top + 1, retp);
		} else if (tt == LUA_TNIL) {
			lua_lsm_pcall_res_errno(L, top + 1, retp);
		}
		break;
	}
	lua_pop(L, nres);
}

#define PCALL_RES_int(L, top, ret)	lua_lsm_pcall_res_int(L, top, &(ret))
#define PCALL_RES_bool(L, top, ret)	lua_lsm_pcall_res_bool(L, top, &(ret))
#define PCALL_RES_boolerr(L, top, ret)	lua_lsm_pcall_res_boolerr(L, top, &(ret))

#define LCALL_NRES_void		0
#define LCALL_NRES_int		LUA_MULTRET
#define LCALL_NRES_bool		LUA_MULTRET
#define LCALL_NRES_boolerr	LUA_MULTRET

#define LUA_PCALL(rettype, L, top, ret)							\
	do {										\
		int status, nargs = lua_gettop(L) - top;				\
		lua_pushvalue(L, -nargs - 4);		/* env */			\
		lua_setfenv(L, -nargs - 6);		/* restore thread.env */	\
		status = lua_pcall(L, nargs, LCALL_NRES_ ## rettype, -nargs - 6);	\
		if (status != 0) {							\
			const char * __maybe_unused error = lua_tostring(L, -1);	\
			__log_err("pcall: status = %d, top = %d, %s\n",			\
				status, lua_gettop(L), error);				\
			lua_pop(L, 1);							\
		} else {								\
			PCALL_RES_ ## rettype(L, top, ret);				\
		}									\
	} while (0)


#define END_VM_CALL_void(rettype, L, top, ret)	LUA_PCALL(rettype, L, top, ret)
#define END_VM_CALL_int(rettype, L, top, ret)	lua_settop(L, (top) - 1)

#define RET_CHECK_void(NAME, ret)	do {} while (0)

#define RET_CHECK_int(NAME, ret)							\
	if ((ret) != LSM_RET_DEFAULT(NAME))						\
		break

#define RET_CHECK_bool(NAME, ret)	RET_CHECK_int(NAME, ret)
#define RET_CHECK_boolerr(NAME, ret)	RET_CHECK_int(NAME, ret)

static inline int lua_lsm_dispatch_failret_default(int default_ret)
{
	return default_ret;
}

static inline int lua_lsm_dispatch_failret_errno(int default_ret __maybe_unused)
{
	return -ENOMEM;
}

#define LUA_LSM_DISPATCH_FAILRET_DEFAULT(NAME)			\
	lua_lsm_dispatch_failret_default(LSM_RET_DEFAULT(NAME))
#define LUA_LSM_DISPATCH_FAILRET_ERRNO(NAME)			\
	lua_lsm_dispatch_failret_errno(LSM_RET_DEFAULT(NAME))

#define LUA_LSM_DEFINEx(x, NAME, rettype, vmtype, pcalltype, failret, ...)		\
	static inline vmtype __lua_lsm_vm_ ## NAME(lua_State *L	__VA_OPT__(,)		\
					__MAP(x, __SC_DECL, __VA_ARGS__));		\
	static inline int __lua_lsm_ ## NAME(DECL_RETP_ARGS_ ## x		\
					__MAP(x, __SC_DECL, __VA_ARGS__))		\
	{										\
		struct lua_lsm_module *module;						\
		lua_State *L;								\
		int ret = LSM_RET_DEFAULT(NAME);					\
		if (atomic_read(&lua_lsm_hook_stats[__LL_NR_ ## NAME].nhooks) == 0)	\
			goto out;							\
		L = lvm_get();								\
		if (WARN_ON_ONCE(!L))							\
			return -ENOMEM;							\
		lua_pushcfunction(L, lua_traceback);					\
		lua_pushthread(L);							\
		lua_getfenv(L, -1);			/* save thread.fenv */		\
		lua_getfield(L, LUA_REGISTRYINDEX, "_MODULES");				\
		/* stack: [traceback, thread, env, _MODULES] */				\
		list_for_each_entry_srcu(module, &lsm_modules, list,			\
					srcu_read_lock_held(&modules_ss)) {		\
			if (!__BITMAP_ISSET(__LL_NR_ ## NAME, &module->hookfuncs))	\
				continue;						\
			if (module->state != LMS_STATE_LIVE)				\
				continue;						\
			lua_getfield(L, -1, module->name);				\
			lua_getfield(L, -1, #NAME);					\
			WARN_ON(lua_gettop(L) != 6);					\
			/* stack: [traceback, thread, env, _MODULES, _M, lfunc] */	\
			if (lua_isfunction(L, -1)) {					\
				int top = lua_gettop(L);				\
				lua_getfenv(L, -1);					\
				*newtask_nomain(L) = current;				\
				lua_setfield(L, -2, "current");				\
				lua_setfield(L, LUA_REGISTRYINDEX, CURR_ENV);		\
				ASSIGN_FROM_FUNC_ ## vmtype(ret)			\
					__lua_lsm_vm_ ## NAME(L __VA_OPT__(,)		\
						__MAP(x, __SC_ARGS, __VA_ARGS__));	\
				END_VM_CALL_ ## vmtype(pcalltype, L, top, ret);		\
			} else {							\
				lua_pop(L, 1);		/* pop lfunc */			\
			}								\
			lua_pop(L, 1);			/* pop _M */			\
			RET_CHECK_ ## pcalltype(NAME, ret);				\
		}									\
		lua_pushnil(L);								\
		lua_setfield(L, LUA_REGISTRYINDEX, CURR_ENV);				\
		lua_pop(L, 4);								\
		lvm_put(L);								\
out:											\
		*retp = ret;								\
		return 0;								\
	}										\
	rettype lua_lsm_ ## NAME(DECL_ARGS_ ## x					\
				__MAP(x, __SC_DECL, __VA_ARGS__))			\
	{										\
		int ret;								\
		DECLARE_STATS_VARS();							\
		START_STATS(NAME);							\
		ret = __prepare_ ## NAME(__MAP(x, __SC_ARGS, __VA_ARGS__));		\
		if (ret >= 0) {								\
			int idx = srcu_read_lock(&modules_ss);				\
			if (static_branch_unlikely(&lua_lsm_modules_active)) {		\
				int err = __lua_lsm_ ## NAME(CALL_RETP_ARGS_ ## x	\
					__MAP(x, __SC_ARGS, __VA_ARGS__));		\
				if (err)						\
					ret = LUA_LSM_DISPATCH_FAILRET_ ## failret(NAME);\
			} else {							\
				ret = LSM_RET_DEFAULT(NAME);				\
			}								\
			__postpone_ ## NAME(__MAP(x, __SC_ARGS, __VA_ARGS__));		\
			srcu_read_unlock(&modules_ss, idx);				\
		}									\
		END_STATS(NAME);							\
		return (rettype)ret;							\
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
	LUA_LSM_DEFINEx(0, name, int, void, bool, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOL_DEFINE1(name, ...)				\
	LUA_LSM_DEFINEx(1, name, int, void, bool, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOL_DEFINE2(name, ...)				\
	LUA_LSM_DEFINEx(2, name, int, void, bool, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOL_DEFINE3(name, ...)				\
	LUA_LSM_DEFINEx(3, name, int, void, bool, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOL_DEFINE4(name, ...)				\
	LUA_LSM_DEFINEx(4, name, int, void, bool, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOL_DEFINE5(name, ...)				\
	LUA_LSM_DEFINEx(5, name, int, void, bool, DEFAULT, ##__VA_ARGS__)
#define LUA_LSM_INT_BOOL_DEFINE6(name, ...)				\
	LUA_LSM_DEFINEx(6, name, int, void, bool, DEFAULT, ##__VA_ARGS__)

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
