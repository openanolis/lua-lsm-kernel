/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#include "debug.h"
#include <linux/errno.h>
#include <linux/errname.h>
#include "lsm.h"
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

static const luaL_Reg errnolib[] = {
	{ "errname",	errno_errname	},
	{ NULL, NULL }
};

int luaopen_errno(lua_State *L)
{
	luaL_newlib(L, errnolib);
	setconst(L, errnos);
	return 1;
}
