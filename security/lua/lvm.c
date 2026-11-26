/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#define pr_fmt(fmt)	"lua-lsm: " fmt

#include "debug.h"
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/kstrtox.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/compiler.h>
#include <linux/cpu.h>
#include <linux/rwlock.h>
#include <linux/cred.h>
#include <linux/percpu.h>
#include <linux/syscalls.h>	/* for __MAP */
#include <linux/timekeeping.h>	/* for ktime_get */
#include <linux/lsm_hooks.h>
#include <uapi/linux/lsm.h>
#include <linux/lua.h>
#include <linux/lualib.h>
#include <linux/lauxlib.h>
#include <linux/lockdep.h>
#include <linux/srcu.h>
#include "lsm.h"
#include "lua_object.h"
#include "lsm_defs.h"

/********************************** lvm **********************************/

static DEFINE_PER_CPU(struct lvm_state *, irq_lvms);

static lua_State *lvm_build_lua_state(struct lvm_state *lvm);
static void *lvm_alloc(void *ud, void *ptr, size_t osize, size_t nsize);

int lvm_irq_init(void)
{
	struct lvm_state *lvm;
	int cpu;
	int err;

	for_each_possible_cpu(cpu) {
		lvm = kzalloc(sizeof(struct lvm_state), GFP_KERNEL);
		if (!lvm)
			return -ENOMEM;

		err = lua_state_alloc(lvm);
		if (err)
			return err;

		per_cpu(irq_lvms, cpu) = lvm;
	}
	return 0;
}

lua_State *lvm_irq_state(int cpu)
{
	return per_cpu(irq_lvms, cpu)->L;
}

#define LUA_LVM_POOL_MAX_DEFAULT	32
#define LUA_LVM_POOL_MAX_LIMIT		256

unsigned int lua_lvm_pool_max __read_mostly = LUA_LVM_POOL_MAX_DEFAULT;

static int __init lua_lvm_pool_max_setup(char *str)
{
	unsigned int val;
	int err;

	if (!str || !*str)
		return 1;

	err = kstrtouint(str, 10, &val);
	if (err) {
		pr_warn("invalid lua.lvm_pool_max='%s', keeping %u\n",
			str, lua_lvm_pool_max);
		return 1;
	}

	if (val > LUA_LVM_POOL_MAX_LIMIT) {
		pr_warn("lua.lvm_pool_max=%u exceeds limit %u, keeping %u\n",
			val, LUA_LVM_POOL_MAX_LIMIT, lua_lvm_pool_max);
		return 1;
	}

	WRITE_ONCE(lua_lvm_pool_max, val);
	return 1;
}
__setup("lua.lvm_pool_max=", lua_lvm_pool_max_setup);

struct lvm_pool_cpu {
	struct lvm_state *head;
	unsigned int count;
	raw_spinlock_t lock;
};

static DEFINE_PER_CPU(struct lvm_pool_cpu, lvm_pools);

void lvm_pool_init_cpu(int cpu)
{
	struct lvm_pool_cpu *pool = &per_cpu(lvm_pools, cpu);

	pool->head = NULL;
	pool->count = 0;
	raw_spin_lock_init(&pool->lock);
}

static struct lvm_state *lvm_pool_get(void)
{
	struct lvm_pool_cpu *pool;
	struct lvm_state *lvm = NULL;
	unsigned long flags;
	int cpu;

	cpu = get_cpu();
	pool = &per_cpu(lvm_pools, cpu);
	raw_spin_lock_irqsave(&pool->lock, flags);
	if (pool->head) {
		lvm = pool->head;
		pool->head = lvm->next;
		pool->count--;
	}
	raw_spin_unlock_irqrestore(&pool->lock, flags);
	put_cpu();

	if (lvm)
		lvm->next = NULL;

	return lvm;
}

void lvm_pool_put(struct lvm_state *lvm)
{
	struct lvm_pool_cpu *pool;
	unsigned long flags;
	int cpu;

	if (!lvm)
		return;

	cpu = get_cpu();
	pool = &per_cpu(lvm_pools, cpu);
	raw_spin_lock_irqsave(&pool->lock, flags);
	if (pool->count < READ_ONCE(lua_lvm_pool_max)) {
		lvm->next = pool->head;
		pool->head = lvm;
		pool->count++;
		lvm = NULL;
	}
	raw_spin_unlock_irqrestore(&pool->lock, flags);
	put_cpu();

	if (lvm) {
		lua_state_free(lvm);
		kfree(lvm);
	}
}

void lvm_vm_reset(struct lvm_state *lvm)
{
	lua_State *L = lvm->L;

	if (!L)
		return;

	lua_settop(L, 0);
	lua_pushnil(L);
	lua_setfield(L, LUA_REGISTRYINDEX, CURR_ENV);

	lua_gc(L, LUA_GCCOLLECT, 0);
}

void lvm_mark_dirty(lua_State *L)
{
	void *ud;

	lua_getallocf(L, &ud);
	((struct lvm_state *)ud)->dirty = true;
}

static bool lvm_task_teardown(const struct lua_lsm_task *llt)
{
	/* Pairs with smp_store_release() in task_blob_free(). */
	return smp_load_acquire(&llt->lvm_teardown);
}

bool lvm_current_task_teardown(void)
{
	return in_task() && lvm_task_teardown(lua_lsm_task(current));
}

static struct lvm_state *
lvm_get_task_state(const struct task_struct *task, bool create)
{
	struct lua_lsm_task *llt = lua_lsm_task(task);
	struct lvm_state *lvm, *old;

	if (unlikely(lvm_task_teardown(llt)))
		return NULL;

	/* Pairs with cmpxchg() publishing a lazy task VM state. */
	lvm = smp_load_acquire(&llt->lvm);
	if (likely(lvm || !create))
		return lvm;

	lvm = kzalloc(sizeof(*lvm), lua_lsm_gfp());
	if (!lvm)
		return NULL;

	if (unlikely(lvm_task_teardown(llt))) {
		kfree(lvm);
		return NULL;
	}

	old = cmpxchg(&llt->lvm, NULL, lvm);
	if (old) {
		kfree(lvm);
		lvm = old;
	}

	if (unlikely(lvm_task_teardown(llt)))
		return NULL;

	return lvm;
}

static lua_State *
lvm_get_from_task(const struct task_struct *task)
{
	struct lua_lsm_task *llt = lua_lsm_task(task);
	struct lvm_state *lvm = lvm_get_task_state(task, true);
	lua_State *L;
	int n;

	if (!lvm)
		return NULL;

	n = refcount_acquire(&lvm->refcount);
	if (unlikely(lvm_task_teardown(llt)))
		goto err_put;
	WARN_ON(n != 1);
	KASSERT(n == 1, ("<%s> Lua VM is reused, refcount = %d\n",
			 task->comm, n));

	L = smp_load_acquire(&lvm->L);
	if (!L) {
		struct lvm_state *pooled = lvm_pool_get();
		struct lvm_state build_owner;
		struct lvm_state *owner;
		lua_State *built;

		if (pooled) {
			built = pooled->L;
			pooled->L = NULL;
			owner = pooled;
		} else {
			memset(&build_owner, 0, sizeof(build_owner));
			built = lvm_build_lua_state(&build_owner);
			if (!built)
				goto err_put;
			owner = &build_owner;
		}
		lua_setallocf(built, lvm_alloc, lvm);
#ifdef CONFIG_SECURITY_LUA_LSM_STATS
		atomic64_set(&lvm->nalloc, atomic64_read(&owner->nalloc));
		atomic64_set(&lvm->nrealloc,
			     atomic64_read(&owner->nrealloc));
		atomic64_set(&lvm->nfree, atomic64_read(&owner->nfree));
#endif
		kfree(pooled);
		/*
		 * Readers treat non-NULL lvm->L as a ready VM, so publish it
		 * only after the allocator owner has moved to the task lvm.
		 */
		smp_store_release(&lvm->L, built);
		L = built;
	}
	return L;

err_put:
	refcount_release(&lvm->refcount);
	return NULL;
}

static void lvm_put_to_task(const struct task_struct *task, lua_State *L)
{
	struct lua_lsm_task *llt = lua_lsm_task(task);
	struct lvm_state *lvm = READ_ONCE(llt->lvm);
	int n = refcount_release(&lvm->refcount);

	KASSERT(n == 0, ("<%s> Lua VM is reused, refcount = %d\n",
			 task->comm, n));
	WARN_ON(lvm->L != L);
}

lua_State *lvm_get(void)
{
	BUG_ON(in_nmi() || in_hardirq());

	if (in_task())
		return lvm_get_from_task(current);
	else
		return get_cpu_var(irq_lvms)->L;
}

void lvm_put(lua_State *L)
{
	if (in_task())
		lvm_put_to_task(current, L);
	else
		put_cpu_var(irq_lvms);
}


static const luaL_Reg builtinlibs[] = {
	{ "kernel",	luaopen_kernel		},
	{ "fs",		luaopen_fs		},
	{ "net",	luaopen_net		},
	{ "errno",	luaopen_errno		},
	{ "capability",	luaopen_capability	},
	{ "signal",	luaopen_signal		},
	{ "audit",	luaopen_audit		},
	{ NULL, NULL }
};

static void lualibs_openall(lua_State *L)
{
	const luaL_Reg *lib;

	/* TODO: loaded if needed */
	for (lib = builtinlibs; lib->func; lib++) {
		luaL_requiref(L, lib->name, lib->func, 0);
		lua_pop(L, 1);
	}
}

static int ll_require(lua_State *L)
{
	const char *modname = luaL_checkstring(L, 1);

	luaL_findtable(L, LUA_REGISTRYINDEX, "_LOADED", 1);
	lua_getfield(L, -1, modname);		/* _LOADED[modname] */
	return 1;
}

static void *lvm_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	lvm_stats_memalloc(ud, ptr, osize, nsize);

	if (nsize == 0) {
		kfree(ptr);
		return NULL;
	} else {
		return krealloc(ptr, nsize, lua_lsm_gfp());
	}
}

static int lvm_panic(lua_State *L)
{
	(void)L;	/* to avoid warnings */

	pr_err("PANIC: unprotected error in call to Lua API (%s), top = %d\n",
	       lua_tostring(L, -1), lua_gettop(L));
	return 0;
}

static int lvm_pmain(lua_State *L)
{
	luaL_openlibs(L);

	/* open builtin libraries */
	lualibs_openall(L);

	/* shared dict init */
	shdict_init(L);

	lua_gc(L, LUA_GCRESTART, 0);

	/* _G._G = nil, remove global variable _G */
	lua_pushnil(L);
	lua_setfield(L, LUA_GLOBALSINDEX, "_G");

	lua_pushcfunction(L, ll_require);
	lua_setglobal(L, "require");

	/* build _MODULES table with metatable */
	lua_newtable(L);			/* _MODULES table */
	lua_createtable(L, 0, 1);		/* metatable */
	lua_pushcfunction(L, lua_modules_index); /* TODO: pass it as args */
	lua_setfield(L, -2, "__index");		/* metatable.__index = func */
	/* setmetatable(_MODULES, metatable) */
	lua_setmetatable(L, -2);
	lua_setfield(L, LUA_REGISTRYINDEX, "_MODULES");

	/* return true */
	lua_pushboolean(L, 1);
	return 1;
}

/*
 * Build a fully-initialized lua_State without publishing it into any
 * lvm_state. The returned state has openlibs, lualibs, shdict, and the
 * _MODULES table installed; the caller is responsible for installing it.
 */
static lua_State *lvm_build_lua_state(struct lvm_state *lvm)
{
	lua_State *L;
	int status;

	L = lua_newstate(lvm_alloc, lvm);
	if (!L)
		return NULL;

	lua_atpanic(L, lvm_panic);
	lua_gc(L, LUA_GCSTOP, 0);

	lua_pushcfunction(L, lvm_pmain);
	status = lua_pcall(L, 0, 1, 0);
	if (status != 0) {
		__log_err("pcall: status = %d, top = %d, %s\n",
			  status, lua_gettop(L), lua_tostring(L, -1));
		lua_close(L);
		return NULL;
	}
	if (!lua_toboolean(L, -1) && lua_gettop(L) != 1) {
		__log_err("lvm_pmain: top = %d, stack[top] = [%s]\n",
			  lua_gettop(L), luaL_typename(L, -1));
		lua_close(L);
		return NULL;
	}
	lua_pop(L, 1);

	lvm_stats_vmalloc();
	return L;
}

int lua_state_alloc(struct lvm_state *lvm)
{
	lua_State *L = lvm_build_lua_state(lvm);

	if (!L)
		return -ENOMEM;
	lvm->L = L;
	return 0;
}

void lua_state_free(struct lvm_state *lvm)
{
	if (lvm->L) {
		lvm_stats_vmfree();
		lua_close(lvm->L);
		lvm->L = NULL;
	}
}
