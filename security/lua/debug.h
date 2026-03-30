/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#ifndef _SECURITY_LUA_LSM_DEBUG_H
#define _SECURITY_LUA_LSM_DEBUG_H

#ifdef DEBUG

#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/pid.h>

extern bool lua_lsm_debug;

#define __log_level(level, fmt, ...)					\
	do {								\
		if (lua_lsm_debug)					\
			pr_ ## level("%s [%d]: %d %s - " fmt,		\
				current->comm, task_pid_nr(current),	\
				__LINE__, __func__, ##__VA_ARGS__);	\
	} while (0)

#define __log_emerg(fmt, ...)	__log_level(emerg, fmt, ##__VA_ARGS__)
#define __log_err(fmt, ...)	__log_level(err,   fmt, ##__VA_ARGS__)
#define __log_warn(fmt, ...)	__log_level(warn,  fmt, ##__VA_ARGS__)
#define __log_info(fmt, ...)	__log_level(info,  fmt, ##__VA_ARGS__)
#define __log_info_ratelimited(fmt, ...)				\
	__log_level(info_ratelimited, fmt, ##__VA_ARGS__)

#else

#define __log_emerg(fmt, ...)			do {} while (0)
#define __log_err(fmt, ...)			do {} while (0)
#define __log_warn(fmt, ...)			do {} while (0)
#define __log_info(fmt, ...)			do {} while (0)
#define __log_info_ratelimited(fmt, ...)	do {} while (0)

#endif

#endif  /* ! _SECURITY_LUA_LSM_DEBUG_H */
