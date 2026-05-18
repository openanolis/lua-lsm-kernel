// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/lua.h>
#include <linux/lauxlib.h>
#include <linux/lualib.h>
#include "auxlib.h"
#include "lua_object.h"
#include "lua_mm.h"

#define VMA_META	"lua_lsm.vma"

struct lua_lsm_vma {
	struct file *file;
	unsigned long start;
	unsigned long end;
	unsigned long prot;
	unsigned long reqprot;
	unsigned long oldprot;
	bool anonymous;
	bool shared;
	bool heap;
	bool stack;
	bool file_cow;
};

static struct lua_lsm_vma *tovma(lua_State *L, int idx)
{
	return luaL_checkudata(L, idx, VMA_META);
}

static int vma_file(lua_State *L)
{
	struct lua_lsm_vma *vma = tovma(L, 1);
	struct file **filp;

	if (!vma->file) {
		lua_pushnil(L);
		return 1;
	}

	filp = newgcfile_nomain(L);
	lua_getfenv(L, 1);
	lua_setfenv(L, -2);
	*filp = get_file(vma->file);
	return 1;
}

static int vma_start(lua_State *L)
{
	struct lua_lsm_vma *vma = tovma(L, 1);

	lua_pushnumber(L, vma->start);
	return 1;
}

static int vma_finish(lua_State *L)
{
	struct lua_lsm_vma *vma = tovma(L, 1);

	lua_pushnumber(L, vma->end);
	return 1;
}

static int vma_size(lua_State *L)
{
	struct lua_lsm_vma *vma = tovma(L, 1);

	lua_pushnumber(L, vma->end - vma->start);
	return 1;
}

static const struct cflag_opt vma_prot_opts[] = {
	{ "read",	PROT_READ	},
	{ "write",	PROT_WRITE},
	{ "exec",	PROT_EXEC	},
	{ NULL, 0 }
};

static const char * const vma_prot_names[] = {
	"read", "write", "exec", NULL
};

static const char * const vma_mapping_names[] = {
	"private", "shared", NULL
};

static unsigned long vma_prot_flags(lua_State *L, int idx, int top)
{
	unsigned long flags = 0;
	int i, opt;

	for (i = idx; i <= top; i++) {
		if (lua_type(L, i) == LUA_TNUMBER) {
			flags |= lua_tointeger(L, i);
			continue;
		}
		opt = luaL_checkoption(L, i, NULL, vma_prot_names);
		flags |= vma_prot_opts[opt].flag;
	}
	return flags;
}

static int vma_test_prot(lua_State *L, unsigned long prot)
{
	int top = lua_gettop(L);

	if (top >= 2) {
		int start = (top == 2) ? 2 : 3;
		int and = lua_isboolean(L, 2) && lua_toboolean(L, 2);
		unsigned long flags = vma_prot_flags(L, start, top);
		unsigned long res = prot & flags;

		lua_pushboolean(L, and ? res == flags : (int)res);
		return 1;
	}
	if (top == 1) {
		table_fromopts(L, vma_prot_opts, 0, prot);
		return 1;
	}
	return 0;
}

static int vma_prot(lua_State *L)
{
	struct lua_lsm_vma *vma = tovma(L, 1);

	return vma_test_prot(L, vma->prot);
}

static int vma_reqprot(lua_State *L)
{
	struct lua_lsm_vma *vma = tovma(L, 1);

	return vma_test_prot(L, vma->reqprot);
}

static int vma_was(lua_State *L)
{
	struct lua_lsm_vma *vma = tovma(L, 1);

	return vma_test_prot(L, vma->oldprot);
}

static int vma_mapping(lua_State *L)
{
	struct lua_lsm_vma *vma = tovma(L, 1);
	int opt;

	if (lua_gettop(L) == 1) {
		lua_pushstring(L, vma->shared ? "shared" : "private");
		return 1;
	}

	opt = luaL_checkoption(L, 2, NULL, vma_mapping_names);
	lua_pushboolean(L, vma->shared == (opt == 1));
	return 1;
}

static bool vma_is_gaining_exec(struct lua_lsm_vma *vma)
{
	return (vma->prot & PROT_EXEC) && !(vma->oldprot & PROT_EXEC);
}

static bool vma_is_gaining_write(struct lua_lsm_vma *vma)
{
	return (vma->prot & PROT_WRITE) && !(vma->oldprot & PROT_WRITE);
}

static bool vma_is_write_to_exec(struct lua_lsm_vma *vma)
{
	return (vma->oldprot & PROT_WRITE) && vma_is_gaining_exec(vma);
}

static bool vma_has_implied_exec(struct lua_lsm_vma *vma)
{
	return (vma->prot & PROT_EXEC) && !(vma->reqprot & PROT_EXEC);
}

#define VMA_BOOL_METHOD(name, expr)					\
	static int vma_ ## name(lua_State *L)				\
	{								\
		struct lua_lsm_vma *vma = tovma(L, 1);			\
									\
		lua_pushboolean(L, !!(expr));				\
		return 1;						\
	}

VMA_BOOL_METHOD(file_backed, vma->file)
VMA_BOOL_METHOD(anonymous, vma->anonymous)
VMA_BOOL_METHOD(heap, vma->heap)
VMA_BOOL_METHOD(stack, vma->stack)
VMA_BOOL_METHOD(file_cow, vma->file_cow)
VMA_BOOL_METHOD(gaining_exec, vma_is_gaining_exec(vma))
VMA_BOOL_METHOD(gaining_write, vma_is_gaining_write(vma))
VMA_BOOL_METHOD(write_to_exec, vma_is_write_to_exec(vma))
VMA_BOOL_METHOD(implied_exec, vma_has_implied_exec(vma))
VMA_BOOL_METHOD(wx, (vma->prot & PROT_WRITE) && (vma->prot & PROT_EXEC))

#undef VMA_BOOL_METHOD

static int vma_gc(lua_State *L)
{
	struct lua_lsm_vma *vma = tovma(L, 1);

	if (vma->file) {
		fput(vma->file);
		vma->file = NULL;
	}
	return 0;
}

static int vma_tostring(lua_State *L)
{
	struct lua_lsm_vma *vma = tovma(L, 1);

	lua_pushfstring(L, "vma: <%p>", vma);
	return 1;
}

static void vma_set_meta(lua_State *L)
{
	static const luaL_reg meth[] = {
		{ "file",		vma_file		},
		{ "start",		vma_start		},
		{ "finish",		vma_finish	},
		{ "size",		vma_size		},
		{ "prot",		vma_prot		},
		{ "reqprot",		vma_reqprot	},
		{ "was",		vma_was		},
		{ "mapping",		vma_mapping	},
		{ "file_backed",	vma_file_backed	},
		{ "anonymous",	vma_anonymous	},
		{ "heap",		vma_heap		},
		{ "stack",		vma_stack		},
		{ "file_cow",	vma_file_cow	},
		{ "gaining_exec",	vma_gaining_exec	},
		{ "gaining_write",	vma_gaining_write	},
		{ "write_to_exec",	vma_write_to_exec	},
		{ "implied_exec",	vma_implied_exec	},
		{ "wx",		vma_wx		},
		{ "__gc",		vma_gc		},
		{ "__tostring",	vma_tostring	},
		{ NULL, NULL }
	};

	if (luaL_newmetatable(L, VMA_META)) {
		lua_pushstring(L, "cannot set a protected metatable");
		lua_setfield(L, -2, "__metatable");
		luaL_register(L, NULL, meth);
		lua_pushvalue(L, -1);
		lua_setfield(L, -2, "__index");
	}
	lua_setmetatable(L, -2);
}

void newvma(lua_State *L, struct vm_area_struct *vma,
	    unsigned long reqprot, unsigned long prot)
{
	struct lua_lsm_vma *ctx;
	unsigned long oldprot = 0;

	if (vma->vm_flags & VM_READ)
		oldprot |= PROT_READ;
	if (vma->vm_flags & VM_WRITE)
		oldprot |= PROT_WRITE;
	if (vma->vm_flags & VM_EXEC)
		oldprot |= PROT_EXEC;

	ctx = lua_newuserdata(L, sizeof(*ctx));
	ctx->file = NULL;
	vma_set_meta(L);
	lua_getfield(L, LUA_REGISTRYINDEX, CURR_ENV);
	lua_setfenv(L, -2);

	ctx->file = vma->vm_file ? get_file(vma->vm_file) : NULL;
	ctx->start = vma->vm_start;
	ctx->end = vma->vm_end;
	ctx->prot = prot;
	ctx->reqprot = reqprot;
	ctx->oldprot = oldprot;
	ctx->anonymous = vma_is_anonymous(vma);
	ctx->shared = vma->vm_flags & VM_SHARED;
	ctx->heap = vma->vm_mm &&
		vma->vm_start >= vma->vm_mm->start_brk &&
		vma->vm_end <= vma->vm_mm->brk;
	ctx->stack = vma->vm_mm &&
		(vma_is_initial_stack(vma) || vma_is_stack_for_current(vma));
	ctx->file_cow = vma->vm_file && vma->anon_vma;
}
