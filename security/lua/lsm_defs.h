/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#ifndef _SECURITY_LUA_LSM_LSM_DEFS_H
#define _SECURITY_LUA_LSM_LSM_DEFS_H

#include "lsm.h"


#define LSM_RET_DEFAULT(NAME)	(NAME##_default)

#define LSM_HOOK(RET, DEFAULT, NAME, ...)						\
	extern const int __maybe_unused LSM_RET_DEFAULT(NAME);
#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK


#ifdef CONFIG_SECURITY_LUA_LSM_STATS

#define START_STATS(NAME)								\
	do {										\
		ktime_t ___start = ktime_get();						\
		s64 ___delta;								\
		atomic_inc(&lua_lsm_hook_stats[__LL_NR_ ## NAME].count);

#define END_STATS(NAME)									\
		___delta = ktime_to_ns(ktime_get()) - ktime_to_ns(___start);		\
		if (atomic64_read(&lua_lsm_hook_stats[__LL_NR_ ## NAME].maxtime) < ___delta)	\
			atomic64_set(&lua_lsm_hook_stats[__LL_NR_ ## NAME].maxtime, ___delta);	\
		atomic64_add(___delta, &lua_lsm_hook_stats[__LL_NR_ ## NAME].time);	\
	} while (0)

#else

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

#define ASSIGN_FROM_FUNC_void(ret)
#define ASSIGN_FROM_FUNC_int(ret)	ret =

#define PCALL_RES_void(L, top, ret)	do {} while (0)

/*
 * hooks result format:
 *   [none]       : default value
 *   nil          : default value
 *   true         : 0
 *   false        : -EPERM
 *   false, errno : -errno
 *   nil, errno   : -errno
 */
#define PCALL_RES_int(L, top, ret)							\
	do {										\
		/* stack: [..., _M, res1, ...] */					\
		int nres = lua_gettop(L) - top + 1;					\
		switch (nres) {								\
		case 0:									\
			break;								\
		case 1:									\
			if (lua_type(L, top) == LUA_TBOOLEAN)				\
				ret = lua_toboolean(L, top) ? 0 : -EPERM;		\
			break;								\
		default:								\
			if (!lua_toboolean(L, top)) {					\
				int errno = lua_tointeger(L, top + 1);			\
				if (errno > 0 && errno <= MAX_ERRNO)			\
					ret = -errno;					\
			}								\
			break;								\
		}									\
		lua_pop(L, nres);							\
	} while (0)

#define LCALL_NRES_void		0
#define LCALL_NRES_int		LUA_MULTRET

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
	if ((ret) && (ret) != LSM_RET_DEFAULT(NAME))					\
		break


#define LUA_LSM_DEFINEx(x, NAME, rettype, vmtype, ...)					\
	static inline vmtype __lua_lsm_vm_ ## NAME(lua_State *L	__VA_OPT__(,)		\
					__MAP(x, __SC_DECL, __VA_ARGS__));		\
	static inline int __lua_lsm_ ## NAME(DECL_ARGS_ ## x				\
					__MAP(x, __SC_DECL, __VA_ARGS__))		\
	{										\
		lua_State *L = lua_lsm_task(current)->L;				\
		struct lua_module *module;						\
		int ret = LSM_RET_DEFAULT(NAME);					\
		if (atomic_read(&lua_lsm_hook_stats[__LL_NR_ ## NAME].nhooks) == 0)	\
			return ret;							\
		lua_pushcfunction(L, lua_traceback);					\
		lua_pushthread(L);							\
		lua_getfenv(L, -1);			/* save thread.fenv */		\
		lua_getfield(L, LUA_REGISTRYINDEX, "_MODULES");				\
		/* stack: [traceback, thread, env, _MODULES] */				\
		list_for_each_entry(module, &lsm_modules, list) {			\
			if (!__BITMAP_ISSET(__LL_NR_ ## NAME, &module->hookfuncs))	\
				continue;						\
			lua_getfield(L, -1, module->name);				\
			lua_getfield(L, -1, #NAME);					\
			/* stack: [traceback, thread, env, _MODULES, _M, lfunc] */	\
			if (lua_isfunction(L, -1)) {					\
				int top = lua_gettop(L);				\
				lua_getfenv(L, -1);					\
				lua_setfenv(L, -6);	/* thread.fenv = lfunc.fenv */	\
				ASSIGN_FROM_FUNC_ ## vmtype(ret)			\
					__lua_lsm_vm_ ## NAME(L __VA_OPT__(,)		\
						__MAP(x, __SC_ARGS, __VA_ARGS__));	\
				END_VM_CALL_ ## vmtype(rettype, L, top, ret);		\
			} else {							\
				lua_pop(L, 1);		/* pop lfunc */			\
			}								\
			lua_pop(L, 1);			/* pop _M */			\
			RET_CHECK_ ## rettype(NAME, ret);				\
		}									\
		lua_pop(L, 4);								\
		return ret;								\
	}										\
	rettype lua_lsm_ ## NAME(DECL_ARGS_ ## x					\
				__MAP(x, __SC_DECL, __VA_ARGS__))			\
	{										\
		int ret;								\
		START_STATS(NAME);							\
		read_lock_bh(&modules_lock);						\
		ret = __prepare_ ## NAME(__MAP(x, __SC_ARGS, __VA_ARGS__));		\
		if (ret >= 0) {								\
			ret = __lua_lsm_ ## NAME(__MAP(x, __SC_ARGS, __VA_ARGS__));	\
			__postpone_ ## NAME(__MAP(x, __SC_ARGS, __VA_ARGS__));		\
		}									\
		read_unlock_bh(&modules_lock);						\
		END_STATS(NAME);							\
		return (rettype)ret;							\
	}										\
	static inline vmtype __lua_lsm_vm_ ## NAME(lua_State *L __VA_OPT__(,)		\
					__MAP(x, __SC_DECL, __VA_ARGS__))

/*****************************************************************************/

#define LUA_LSM_VOID_DEFINE0(name, ...)		LUA_LSM_DEFINEx(0, name, void, void, ##__VA_ARGS__)
#define LUA_LSM_VOID_DEFINE1(name, ...)		LUA_LSM_DEFINEx(1, name, void, void, ##__VA_ARGS__)
#define LUA_LSM_VOID_DEFINE2(name, ...)		LUA_LSM_DEFINEx(2, name, void, void, ##__VA_ARGS__)
#define LUA_LSM_VOID_DEFINE3(name, ...)		LUA_LSM_DEFINEx(3, name, void, void, ##__VA_ARGS__)
#define LUA_LSM_VOID_DEFINE4(name, ...)		LUA_LSM_DEFINEx(4, name, void, void, ##__VA_ARGS__)
#define LUA_LSM_VOID_DEFINE5(name, ...)		LUA_LSM_DEFINEx(5, name, void, void, ##__VA_ARGS__)
#define LUA_LSM_VOID_DEFINE6(name, ...)		LUA_LSM_DEFINEx(6, name, void, void, ##__VA_ARGS__)

#define LUA_LSM_VOID_NAKED_DEFINE0(name, ...)	LUA_LSM_DEFINEx(0, name, void, int, ##__VA_ARGS__)
#define LUA_LSM_VOID_NAKED_DEFINE1(name, ...)	LUA_LSM_DEFINEx(1, name, void, int, ##__VA_ARGS__)
#define LUA_LSM_VOID_NAKED_DEFINE2(name, ...)	LUA_LSM_DEFINEx(2, name, void, int, ##__VA_ARGS__)
#define LUA_LSM_VOID_NAKED_DEFINE3(name, ...)	LUA_LSM_DEFINEx(3, name, void, int, ##__VA_ARGS__)
#define LUA_LSM_VOID_NAKED_DEFINE4(name, ...)	LUA_LSM_DEFINEx(4, name, void, int, ##__VA_ARGS__)
#define LUA_LSM_VOID_NAKED_DEFINE5(name, ...)	LUA_LSM_DEFINEx(5, name, void, int, ##__VA_ARGS__)
#define LUA_LSM_VOID_NAKED_DEFINE6(name, ...)	LUA_LSM_DEFINEx(6, name, void, int, ##__VA_ARGS__)

#define LUA_LSM_INT_DEFINE0(name, ...)		LUA_LSM_DEFINEx(0, name, int, void, ##__VA_ARGS__)
#define LUA_LSM_INT_DEFINE1(name, ...)		LUA_LSM_DEFINEx(1, name, int, void, ##__VA_ARGS__)
#define LUA_LSM_INT_DEFINE2(name, ...)		LUA_LSM_DEFINEx(2, name, int, void, ##__VA_ARGS__)
#define LUA_LSM_INT_DEFINE3(name, ...)		LUA_LSM_DEFINEx(3, name, int, void, ##__VA_ARGS__)
#define LUA_LSM_INT_DEFINE4(name, ...)		LUA_LSM_DEFINEx(4, name, int, void, ##__VA_ARGS__)
#define LUA_LSM_INT_DEFINE5(name, ...)		LUA_LSM_DEFINEx(5, name, int, void, ##__VA_ARGS__)
#define LUA_LSM_INT_DEFINE6(name, ...)		LUA_LSM_DEFINEx(6, name, int, void, ##__VA_ARGS__)

#define LUA_LSM_INT_NAKED_DEFINE0(name, ...)	LUA_LSM_DEFINEx(0, name, int, int, ##__VA_ARGS__)
#define LUA_LSM_INT_NAKED_DEFINE1(name, ...)	LUA_LSM_DEFINEx(1, name, int, int, ##__VA_ARGS__)
#define LUA_LSM_INT_NAKED_DEFINE2(name, ...)	LUA_LSM_DEFINEx(2, name, int, int, ##__VA_ARGS__)
#define LUA_LSM_INT_NAKED_DEFINE3(name, ...)	LUA_LSM_DEFINEx(3, name, int, int, ##__VA_ARGS__)
#define LUA_LSM_INT_NAKED_DEFINE4(name, ...)	LUA_LSM_DEFINEx(4, name, int, int, ##__VA_ARGS__)
#define LUA_LSM_INT_NAKED_DEFINE5(name, ...)	LUA_LSM_DEFINEx(5, name, int, int, ##__VA_ARGS__)
#define LUA_LSM_INT_NAKED_DEFINE6(name, ...)	LUA_LSM_DEFINEx(6, name, int, int, ##__VA_ARGS__)


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
