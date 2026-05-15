/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#include "debug.h"
#include <linux/capability.h>
#include <linux/cred.h>
#include "lsm.h"
#include "auxlib.h"
#include "lua_object.h"

static const struct const_value capabilities[] = {
	CONST_DEFINE(CAP_CHOWN),
	CONST_DEFINE(CAP_DAC_OVERRIDE),
	CONST_DEFINE(CAP_DAC_READ_SEARCH),
	CONST_DEFINE(CAP_FOWNER),
	CONST_DEFINE(CAP_FSETID),
	CONST_DEFINE(CAP_KILL),
	CONST_DEFINE(CAP_SETGID),
	CONST_DEFINE(CAP_SETUID),
	CONST_DEFINE(CAP_SETPCAP),
	CONST_DEFINE(CAP_LINUX_IMMUTABLE),
	CONST_DEFINE(CAP_NET_BIND_SERVICE),
	CONST_DEFINE(CAP_NET_BROADCAST),
	CONST_DEFINE(CAP_NET_ADMIN),
	CONST_DEFINE(CAP_NET_RAW),
	CONST_DEFINE(CAP_IPC_LOCK),
	CONST_DEFINE(CAP_IPC_OWNER),
	CONST_DEFINE(CAP_SYS_MODULE),
	CONST_DEFINE(CAP_SYS_RAWIO),
	CONST_DEFINE(CAP_SYS_CHROOT),
	CONST_DEFINE(CAP_SYS_PTRACE),
	CONST_DEFINE(CAP_SYS_PACCT),
	CONST_DEFINE(CAP_SYS_ADMIN),
	CONST_DEFINE(CAP_SYS_BOOT),
	CONST_DEFINE(CAP_SYS_NICE),
	CONST_DEFINE(CAP_SYS_RESOURCE),
	CONST_DEFINE(CAP_SYS_TIME),
	CONST_DEFINE(CAP_SYS_TTY_CONFIG),
	CONST_DEFINE(CAP_MKNOD),
	CONST_DEFINE(CAP_LEASE),
	CONST_DEFINE(CAP_AUDIT_WRITE),
	CONST_DEFINE(CAP_AUDIT_CONTROL),
	CONST_DEFINE(CAP_SETFCAP),
	CONST_DEFINE(CAP_MAC_OVERRIDE),
	CONST_DEFINE(CAP_MAC_ADMIN),
	CONST_DEFINE(CAP_SYSLOG),
	CONST_DEFINE(CAP_WAKE_ALARM),
	CONST_DEFINE(CAP_BLOCK_SUSPEND),
	CONST_DEFINE(CAP_AUDIT_READ),
	CONST_DEFINE(CAP_PERFMON),
	CONST_DEFINE(CAP_BPF),
	CONST_DEFINE(CAP_CHECKPOINT_RESTORE),
	{ NULL }
};

/********************************** meth **********************************/

static int capability_add(lua_State *L)
{
	kernel_cap_t cap1 = tocap(L, 1);
	int tt = lua_type(L, 2);
	int cap;

	if (tt == LUA_TUSERDATA) {
		const kernel_cap_t cap2 = tocap(L, 2);

		*newcap(L) = cap_combine(cap1, cap2);
		return 1;
	}

	cap = arg2cap(L, 2);
	cap_raise(cap1, cap);
	*newcap(L) = cap1;
	return 1;
}

static int capability_sub(lua_State *L)
{
	kernel_cap_t cap1 = tocap(L, 1);
	int tt = lua_type(L, 2);
	int cap;

	if (tt == LUA_TUSERDATA) {
		const kernel_cap_t cap2 = tocap(L, 2);

		*newcap(L) = cap_drop(cap1, cap2);
		return 1;
	}

	cap = arg2cap(L, 2);
	cap_lower(cap1, cap);
	*newcap(L) = cap1;
	return 1;
}

static int capability_mul(lua_State *L)
{
	const kernel_cap_t cap1 = tocap(L, 1);
	const kernel_cap_t cap2 = tocap(L, 2);
	*newcap(L) = cap_intersect(cap1, cap2);
	return 1;
}

static int capability_eq(lua_State *L)
{
	const kernel_cap_t cap1 = tocap(L, 1);
	const kernel_cap_t cap2 = tocap(L, 2);

	lua_pushboolean(L, cap_isidentical(cap1, cap2));
	return 1;
}

static int capability_le(lua_State *L)
{
	const kernel_cap_t cap1 = tocap(L, 1);
	const kernel_cap_t cap2 = tocap(L, 2);

	lua_pushboolean(L, cap_issubset(cap1, cap2));
	return 1;
}

static int capability_lt(lua_State *L)
{
	const kernel_cap_t cap1 = tocap(L, 1);
	const kernel_cap_t cap2 = tocap(L, 2);
	bool b = cap_issubset(cap1, cap2) && !cap_isidentical(cap1, cap2);

	lua_pushboolean(L, b);
	return 1;
}

static const luaL_Reg cap_meth[] = {
	{ "__add",	capability_add	},	/* combine/raise */
	{ "__sub",	capability_sub	},	/* drop/lower */
	{ "__mul",	capability_mul	},	/* intersect */
	{ "__eq",	capability_eq	},	/* isidentical */
	{ "__le",	capability_le	},	/* issubset */
	{ "__lt",	capability_lt	},	/* issubset && !isidentical */
	{ NULL, NULL }
};

/**********************************  lib  **********************************/

static int capability_cap_empty(lua_State *L)
{
	*newcap(L) = CAP_EMPTY_SET;
	return 1;
}

static int capability_cap_full(lua_State *L)
{
	*newcap(L) = CAP_FULL_SET;
	return 1;
}

static int capability_capable(lua_State *L)
{
	return aux_capable(L, current_cred(), current_user_ns(), 1);
}

static const luaL_Reg capabilitylib[] = {
	{ "cap_empty",	capability_cap_empty	},
	{ "cap_full",	capability_cap_full	},
	{ "capable",	capability_capable	},
	{ NULL, NULL }
};

int luaopen_capability(lua_State *L)
{
	luaL_newlib(L, capabilitylib);
	create_cap_meta(L, cap_meth, NULL);
	setconst(L, capabilities);
	return 1;
}
