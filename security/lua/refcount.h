/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#ifndef _SECURITY_LUA_LSM_REFCOUNT_H
#define _SECURITY_LUA_LSM_REFCOUNT_H

#include "debug.h"
#include <linux/kernel.h>

#define KASSERT(exp, msg)						\
	do {								\
		if (!(exp)) {						\
			__log_err msg;					\
		}							\
	} while (0)

static inline void
refcount_init(atomic_t *count, long value)
{
	atomic_set(count, value);
}

static inline int
refcount_acquire(atomic_t *count)
{
	KASSERT(atomic_read(count) < UINT_MAX, ("refcount %p overflowed", count));
	return atomic_inc_return(count);
}

static inline int
refcount_release(atomic_t *count)
{
	int n = atomic_dec_return(count);

	KASSERT(n >= 0, ("negative refcount %p", count));
	return n;
}

#endif  /* ! _SECURITY_LUA_LSM_REFCOUNT_H */
