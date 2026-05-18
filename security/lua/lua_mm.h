/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#ifndef _SECURITY_LUA_LSM_LUA_MM_H
#define _SECURITY_LUA_LSM_LUA_MM_H

#include <linux/lua.h>

struct vm_area_struct;

void newvma(lua_State *L, struct vm_area_struct *vma,
	    unsigned long reqprot, unsigned long prot);

#endif /* ! _SECURITY_LUA_LSM_LUA_MM_H */
