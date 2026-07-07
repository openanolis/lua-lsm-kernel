/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM - errno API library.
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#define LUA_API_KMOD

#include "debug.h"
#include <linux/errno.h>
#include <linux/errname.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/lua.h>
#include <linux/lauxlib.h>
#include <linux/lua_lsm_api.h>
#include "auxlib.h"

static const struct const_value errnos[] = {
	CONST_DEFINE(EPERM),
	CONST_DEFINE(ENOENT),
	CONST_DEFINE(ESRCH),
	CONST_DEFINE(EINTR),
	CONST_DEFINE(EIO),
	CONST_DEFINE(ENXIO),
	CONST_DEFINE(E2BIG),
	CONST_DEFINE(ENOEXEC),
	CONST_DEFINE(EBADF),
	CONST_DEFINE(ECHILD),
	CONST_DEFINE(EAGAIN),
	CONST_DEFINE(ENOMEM),
	CONST_DEFINE(EACCES),
	CONST_DEFINE(EFAULT),
	CONST_DEFINE(ENOTBLK),
	CONST_DEFINE(EBUSY),
	CONST_DEFINE(EEXIST),
	CONST_DEFINE(EXDEV),
	CONST_DEFINE(ENODEV),
	CONST_DEFINE(ENOTDIR),
	CONST_DEFINE(EISDIR),
	CONST_DEFINE(EINVAL),
	CONST_DEFINE(ENFILE),
	CONST_DEFINE(EMFILE),
	CONST_DEFINE(ENOTTY),
	CONST_DEFINE(ETXTBSY),
	CONST_DEFINE(EFBIG),
	CONST_DEFINE(ENOSPC),
	CONST_DEFINE(ESPIPE),
	CONST_DEFINE(EROFS),
	CONST_DEFINE(EMLINK),
	CONST_DEFINE(EPIPE),
	CONST_DEFINE(EDOM),
	CONST_DEFINE(ERANGE),
	{ NULL }
};

static int errno_errname(lua_State *L)
{
	int err = luaL_checkinteger(L, 1);

	lua_pushstring(L, errname(err));
	return 1;
}

static const luaL_Reg errno_lib[] = {
	{ "errname",	errno_errname	},
	{ NULL, NULL }
};

static int errno_init_table(lua_State *L)
{
	setconst(L, errnos);
	return 0;
}

static struct lua_api_lib errno_desc = {
	.name		= "errno",
	.funcs		= errno_lib,
	.init_table	= errno_init_table,
	.owner		= THIS_MODULE,
	.abi_version	= LUA_API_LIB_ABI_VERSION,
};

static int __init lua_errno_lib_init(void)
{
	int err;

#ifdef MODULE
	err = lua_api_lib_register(&errno_desc);
#else
	err = __lua_api_lib_register(&errno_desc);
#endif
	if (err)
		pr_err("lua-lsm: failed to register 'errno' library: %d\n", err);
	return err;
}

static void __exit lua_errno_lib_exit(void)
{
}

module_init(lua_errno_lib_init);
module_exit(lua_errno_lib_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("lua-lsm errno API library");
