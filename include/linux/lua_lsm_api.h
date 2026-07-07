/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Public registration ABI for lua-lsm per-library API modules.
 *
 * Producers populate a struct lua_api_lib and call
 * lua_api_lib_register() (or __lua_api_lib_register() for built-ins).
 * Future fields are reserved at the tail of the struct; consumers must
 * zero the _reserved area to remain forward compatible.
 *
 * Copyright (C) 2026 lua-lsm contributors.
 */

#ifndef _LINUX_LUA_LSM_API_H
#define _LINUX_LUA_LSM_API_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/lauxlib.h>
#include <linux/lua.h>

/* Maximum library name length, including the trailing NUL. */
#define LUA_API_LIB_NAME_MAX	32

/* Bumped on any ABI-breaking descriptor or registration semantic change. */
#define LUA_API_LIB_ABI_VERSION	1u

/**
 * struct lua_api_lib - descriptor for a Lua API library
 * @name:        NUL-terminated library name visible to Lua's require().
 *               Must be non-empty and fit within %LUA_API_LIB_NAME_MAX.
 *               Must not collide with Lua standard libraries already
 *               loaded by the core.
 * @funcs:       %NULL-terminated %luaL_Reg table installed on the
 *               library table.  Required; constant-only libraries use
 *               an empty sentinel table.
 * @init_table:  Optional callback invoked after @funcs is installed
 *               with the library table on top of the stack.  Must not
 *               pop or replace the library table.  Returns 0, -ENOMEM,
 *               or -EPROTO; other non-zero values are mapped to -EPROTO.
 *               May run in atomic context (CPU-hotplug replay with BHs
 *               disabled), so it must not sleep or take blocking locks.
 *               May be %NULL.
 * @reserved_open: Reserved; must be %NULL.  Rejected with -EINVAL.
 * @owner:       Module that owns this descriptor.  Set to %THIS_MODULE
 *               for loadable producers.  Built-in producers call
 *               __lua_api_lib_register() and may use %NULL.
 * @list:        Linkage in the core's SRCU-protected registry.  Set by
 *               the core; callers must not touch it.
 * @abi_version: Must equal %LUA_API_LIB_ABI_VERSION.  Encoded as a
 *               single integer for now.
 * @_reserved:   Zero-initialised forward-compatibility padding.
 */
struct lua_api_lib {
	const char		*name;
	const luaL_Reg		*funcs;
	int			(*init_table)(lua_State *L);
	void			*reserved_open;
	struct module		*owner;
	struct list_head	list;
	u32			abi_version;
	u32			_reserved[2];
};

/**
 * lua_api_lib_register - publish a Lua API library to the lua-lsm core
 * @desc: fully populated descriptor; storage must outlive the core
 *
 * Registers @desc after validating the descriptor, checking security
 * policy, pinning @owner, replaying the library into live per-CPU VMs,
 * and publishing it to future VM construction.  Existing pooled VMs are
 * invalidated by a generation bump.
 *
 * Returns 0, -EINVAL, -EAGAIN, -EEXIST, -ENODEV, -ENOMEM, -EPROTO,
 * -EPERM, or -EKEYREJECTED.  Failed replay is rolled back before
 * return; if cleanup cannot prove that all C closures are gone, the
 * owner module pin is intentionally kept to avoid module-text UAF.
 *
 * Context: process; may sleep.
 */
int lua_api_lib_register(struct lua_api_lib *desc);

/* Built-in producers may pass desc->owner == NULL; vmlinux text cannot be unloaded. */
int __lua_api_lib_register(struct lua_api_lib *desc);

/**
 * lua_api_lib_meta_install - attach a library's method tables to a
 *                            core-owned metatable
 * @L:        Lua state passed to the library's init_table (or
 *            equivalent installer) callback.
 * @name:     metatable identifier as it appears in LUA_OBJECTS_LIST
 *            (e.g. "cap", "task", "file").  Must be non-NULL.
 * @funcs:    %NULL-terminated method table to install on the regular
 *            metatable; %NULL leaves the regular metatable's method
 *            set untouched.
 * @gc_funcs: %NULL-terminated method table for the gc-enabled
 *            metatable; the gc metatable is created lazily on first
 *            install and is only populated when both @funcs and
 *            @gc_funcs are non-NULL.
 *
 * Returns 0 on success, -EINVAL when @L or @name is %NULL, or -ENOENT
 * when @name does not match any entry in LUA_OBJECTS_LIST.
 */
int lua_api_lib_meta_install(lua_State *L, const char *name,
			     const luaL_Reg *funcs,
			     const luaL_Reg *gc_funcs);

#endif /* _LINUX_LUA_LSM_API_H */
