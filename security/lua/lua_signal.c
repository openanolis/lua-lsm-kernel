/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM - signal API library.
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#define LUA_API_KMOD

#include "debug.h"
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/signal.h>
#include <linux/lua.h>
#include <linux/lauxlib.h>
#include <linux/lua_lsm_api.h>
#include "auxlib.h"

static const struct const_value signals[] = {
	CONST_DEFINE(SIGHUP),
	CONST_DEFINE(SIGINT),
	CONST_DEFINE(SIGQUIT),
	CONST_DEFINE(SIGILL),
	CONST_DEFINE(SIGTRAP),
	CONST_DEFINE(SIGABRT),
	CONST_DEFINE(SIGIOT),
	CONST_DEFINE(SIGBUS),
	CONST_DEFINE(SIGFPE),
	CONST_DEFINE(SIGKILL),
	CONST_DEFINE(SIGUSR1),
	CONST_DEFINE(SIGSEGV),
	CONST_DEFINE(SIGUSR2),
	CONST_DEFINE(SIGPIPE),
	CONST_DEFINE(SIGALRM),
	CONST_DEFINE(SIGTERM),
	CONST_DEFINE(SIGSTKFLT),
	CONST_DEFINE(SIGCHLD),
	CONST_DEFINE(SIGCONT),
	CONST_DEFINE(SIGSTOP),
	CONST_DEFINE(SIGTSTP),
	CONST_DEFINE(SIGTTIN),
	CONST_DEFINE(SIGTTOU),
	CONST_DEFINE(SIGURG),
	CONST_DEFINE(SIGXCPU),
	CONST_DEFINE(SIGXFSZ),
	CONST_DEFINE(SIGVTALRM),
	CONST_DEFINE(SIGPROF),
	CONST_DEFINE(SIGWINCH),
	CONST_DEFINE(SIGIO),
	CONST_DEFINE(SIGPOLL),
	CONST_DEFINE(SIGPWR),
	CONST_DEFINE(SIGSYS),
	{ NULL }
};

/*
 * Empty funcs sentinel - the signal library exposes constants only,
 * but the registration ABI requires a non-NULL funcs table.  Constants
 * are published on the library table from init_table() after the
 * (empty) funcs registration has been performed by the core.
 */
static const luaL_Reg signal_lib[] = {
	{ NULL, NULL }
};

static int signal_init_table(lua_State *L)
{
	setconst(L, signals);
	return 0;
}

static struct lua_api_lib signal_desc = {
	.name		= "signal",
	.funcs		= signal_lib,
	.init_table	= signal_init_table,
	.owner		= THIS_MODULE,
	.abi_version	= LUA_API_LIB_ABI_VERSION,
};

static int __init lua_signal_lib_init(void)
{
	int err;

#ifdef MODULE
	err = lua_api_lib_register(&signal_desc);
#else
	err = __lua_api_lib_register(&signal_desc);
#endif
	if (err)
		pr_err("lua-lsm: failed to register 'signal' library: %d\n", err);
	return err;
}

static void __exit lua_signal_lib_exit(void)
{
}

module_init(lua_signal_lib_init);
module_exit(lua_signal_lib_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("lua-lsm signal API library");
