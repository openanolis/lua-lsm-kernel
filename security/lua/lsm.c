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
#include "lsm.h"
#include "lua_object.h"
#include "lsm_defs.h"

#ifdef DEBUG

bool lua_lsm_debug = true;

static int __init disable_debug(char *str)
{
	lua_lsm_debug = false;
	return 1;
}
__setup("lua.nodebug", disable_debug);

#endif	/* ! DEBUG */

/* Flag indicating whether initialization completed */
int lua_lsm_initialized __initdata;

/********************************* lsm hook *********************************/

struct list_head lsm_modules = LIST_HEAD_INIT(lsm_modules);
static DEFINE_MUTEX(modules_mutex);
DEFINE_SRCU(modules_ss);

DEFINE_STATIC_KEY_FALSE(lua_lsm_modules_active);
DEFINE_STATIC_KEY_FALSE(lua_lsm_inactive_cleanup_armed);

struct lua_lsm_hook_stat lua_lsm_hook_stats[] = {
	#define LSM_HOOK(RET, DEFAULT, NAME, ...)			\
		{ .name = #NAME, .nhooks = ATOMIC_INIT(0), },

	#include <linux/lsm_hook_defs.h>
	#undef LSM_HOOK
	{ NULL }
};

/* LSM weak funcs */
#define LSM_HOOK(RET, DEFAULT, NAME, ...)				\
	int __weak __prepare_ ## NAME(__VA_ARGS__)			\
	{								\
		return 0;						\
	}								\
	void __weak __postpone_ ## NAME(__VA_ARGS__)			\
	{								\
	}

#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK

/********************************** stats **********************************/

/* Used by module unregister */
static atomic_t vm_nusage = ATOMIC_INIT(0);

#ifdef CONFIG_SECURITY_LUA_LSM_STATS

struct lua_lsm_hook_pcpu_stat {
	u64_stats_t count;
	u64_stats_t time;
	u64_stats_t maxtime;
	struct u64_stats_sync syncp;
};

struct lua_lsm_pcpu_stats {
	struct lua_lsm_hook_pcpu_stat hooks[__LL_NR_MAX];
};

static DEFINE_PER_CPU(struct lua_lsm_pcpu_stats, lua_lsm_pcpu_stats);

static atomic_t vm_nalloc = ATOMIC_INIT(0);
static atomic_t vm_nfree = ATOMIC_INIT(0);
static atomic64_t mem_nalloc = ATOMIC64_INIT(0);
static atomic64_t mem_nrealloc = ATOMIC64_INIT(0);
static atomic64_t mem_nfree = ATOMIC64_INIT(0);
static atomic_t mem_total = ATOMIC_INIT(0);
static atomic_t mem_minimum = ATOMIC_INIT(INT_MAX);
static atomic_t mem_maximum = ATOMIC_INIT(0);

static void lua_lsm_hook_stats_init_cpu(int cpu)
{
	struct lua_lsm_pcpu_stats *stats = per_cpu_ptr(&lua_lsm_pcpu_stats, cpu);
	int i;

	for (i = 0; i < __LL_NR_MAX; i++)
		u64_stats_init(&stats->hooks[i].syncp);
}

void lua_lsm_hook_stats_record(unsigned int nr, u64 delta)
{
	struct lua_lsm_hook_pcpu_stat *stat;
	unsigned long flags;
	u64 maxtime;

	local_irq_save(flags);
	stat = &this_cpu_ptr(&lua_lsm_pcpu_stats)->hooks[nr];
	u64_stats_update_begin(&stat->syncp);
	u64_stats_inc(&stat->count);
	u64_stats_add(&stat->time, delta);
	maxtime = u64_stats_read(&stat->maxtime);
	if (maxtime < delta)
		u64_stats_set(&stat->maxtime, delta);
	u64_stats_update_end(&stat->syncp);
	local_irq_restore(flags);
}

static void lvm_stats_vmalloc(void)
{
	atomic_inc(&vm_nalloc);
	atomic_inc(&vm_nusage);
}

static void lvm_stats_vmfree(void)
{
	atomic_inc(&vm_nfree);
	atomic_dec(&vm_nusage);
}

static void lvm_stats_memalloc(struct lvm_state *lvm, void *ptr,
			       size_t osize, size_t nsize)
{
	lua_State *L = lvm->L;
	int minimum, maximum, nbytes;

	if (nsize == 0) {
		atomic64_inc(&mem_nfree);
		atomic64_inc(&lvm->nfree);
		atomic_sub((int)osize, &mem_total);
	} else {
		if (ptr) {
			atomic64_inc(&mem_nrealloc);
			atomic64_inc(&lvm->nrealloc);
		} else {
			atomic64_inc(&mem_nalloc);
			atomic64_inc(&lvm->nalloc);
		}

		atomic_add(nsize - osize, &mem_total);
	}

	if (!L)
		return;

	minimum = atomic_read(&mem_minimum);
	maximum = atomic_read(&mem_maximum);
	/*
	 * XXX Notes: There may be a deadlock risk if internal lua_lock()
	 * is actually used. The current architecture does not use locking,
	 * so lua_gc() is fine here.
	 */
	nbytes = lua_gc(L, LUA_GCCOUNT, 0) * 1024 + lua_gc(L, LUA_GCCOUNTB, 0);
	atomic_cmpxchg(&mem_minimum, minimum, min(minimum, nbytes));
	atomic_cmpxchg(&mem_maximum, maximum, max(maximum, nbytes));
}

void lvm_stats_show(struct seq_file *m)
{
	int nusage = atomic_read(&vm_nusage);
	int total = atomic_read(&mem_total);
	int average = nusage ? total / nusage : 0;

	seq_printf(m, "lvm.nalloc\t= %12d\n", atomic_read(&vm_nalloc));
	seq_printf(m, "lvm.nfree\t= %12d\n", atomic_read(&vm_nfree));
	seq_printf(m, "lvm.nusage\t= %12d\n", nusage);
	seq_printf(m, "lmem.nalloc\t= %12lld\n", atomic64_read(&mem_nalloc));
	seq_printf(m, "lmem.nrealloc\t= %12lld\n", atomic64_read(&mem_nrealloc));
	seq_printf(m, "lmem.nfree\t= %12lld\n", atomic64_read(&mem_nfree));
	seq_printf(m, "lmem.total\t= %12d\n", total);
	seq_printf(m, "lmem.average\t= %12d\n", average);
	seq_printf(m, "lmem.minimum\t= %12d\n", atomic_read(&mem_minimum));
	seq_printf(m, "lmem.maximum\t= %12d\n", atomic_read(&mem_maximum));
}

int lsm_funcs_show(struct seq_file *m, void *v)
{
	int i;
	int n = 0;
	int cpu;

	seq_printf(m, "stats for lua-lsm (ns)\n");
	seq_printf(m, "%3s %-28s %4s %12s %15s %10s %12s\n",
		   "num", "name", "nlsm", "count", "total", "average", "maxtime");
	seq_printf(m, "%s\n", TABLINE);

	for (i = 0; lua_lsm_hook_stats[i].name; i++) {
		u64 count = 0;
		u64 total = 0;
		u64 maxtime = 0;

		if (!lua_lsm_hook_supported(i))
			continue;

		for_each_possible_cpu(cpu) {
			const struct lua_lsm_hook_pcpu_stat *stat;
			unsigned int start;
			u64 tcount, ttotal, tmaxtime;

			stat = &per_cpu_ptr(&lua_lsm_pcpu_stats, cpu)->hooks[i];
			do {
				start = u64_stats_fetch_begin(&stat->syncp);
				tcount = u64_stats_read(&stat->count);
				ttotal = u64_stats_read(&stat->time);
				tmaxtime = u64_stats_read(&stat->maxtime);
			} while (u64_stats_fetch_retry(&stat->syncp, start));

			count += tcount;
			total += ttotal;
			if (maxtime < tmaxtime)
				maxtime = tmaxtime;
		}

		seq_printf(m, "%3d %-28s %4d %12llu %15llu %10llu %12llu\n",
			   ++n, lua_lsm_hook_stats[i].name,
			   atomic_read(&lua_lsm_hook_stats[i].nhooks),
			   count, total, count ? total / count : 0, maxtime);
	}
	return 0;
}

#else

static inline void lvm_stats_vmalloc(void)
{
	atomic_inc(&vm_nusage);
}

static inline void lvm_stats_vmfree(void)
{
	atomic_dec(&vm_nusage);
}

static inline void lvm_stats_memalloc(struct lvm_state *lvm, void *ptr,
				      size_t osize, size_t nsize)
{
}

#endif

/********************************** lvm **********************************/

static DEFINE_PER_CPU(struct lvm_state *, irq_lvms);

static lua_State *lvm_build_lua_state(struct lvm_state *lvm);
static void *lvm_alloc(void *ud, void *ptr, size_t osize, size_t nsize);
static int lua_state_alloc(struct lvm_state *lvm);
static void lua_state_free(struct lvm_state *lvm);

#define LUA_LVM_POOL_MAX_DEFAULT	32
#define LUA_LVM_POOL_MAX_LIMIT		256

static unsigned int lua_lvm_pool_max __read_mostly = LUA_LVM_POOL_MAX_DEFAULT;

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

static void lvm_pool_init_cpu(int cpu)
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

static void lvm_pool_put(struct lvm_state *lvm)
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

static void lvm_vm_reset(struct lvm_state *lvm)
{
	lua_State *L = lvm->L;
	int modules_idx;
	int keys_idx;
	int loaded_idx;
	int nkeys;
	int i;

	if (!L)
		return;

	lua_settop(L, 0);
	lua_pushnil(L);
	lua_setfield(L, LUA_REGISTRYINDEX, CURR_ENV);

	/* Collect keys from _MODULES then clear _MODULES/_LOADED entries. */
	lua_getfield(L, LUA_REGISTRYINDEX, "_MODULES");
	if (lua_istable(L, -1)) {
		modules_idx = lua_gettop(L);
		lua_newtable(L);
		keys_idx = lua_gettop(L);
		nkeys = 0;

		lua_pushnil(L);
		while (lua_next(L, modules_idx) != 0) {
			lua_pushvalue(L, -2);
			lua_rawseti(L, keys_idx, ++nkeys);
			lua_pop(L, 1);
		}

		lua_getfield(L, LUA_REGISTRYINDEX, "_LOADED");
		loaded_idx = lua_gettop(L);
		for (i = 1; i <= nkeys; i++) {
			lua_rawgeti(L, keys_idx, i);
			if (!lua_isnil(L, -1)) {
				lua_pushvalue(L, -1);
				lua_pushnil(L);
				lua_rawset(L, modules_idx);

				if (lua_istable(L, loaded_idx)) {
					lua_pushvalue(L, -1);
					lua_pushnil(L);
					lua_rawset(L, loaded_idx);
				}
			}
			lua_pop(L, 1);
		}
		lua_pop(L, 1);
		lua_pop(L, 1);
	}
	lua_pop(L, 1);

	lua_gc(L, LUA_GCCOLLECT, 0);
}

static void lvm_mark_dirty(lua_State *L)
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
lvm_get_from_task(const struct task_struct *task, bool require_idle)
{
	struct lua_lsm_task *llt = lua_lsm_task(task);
	struct lvm_state *lvm = lvm_get_task_state(task, !require_idle);
	lua_State *L;
	int n;

	if (!lvm)
		return NULL;

	n = refcount_acquire(&lvm->refcount);
	if (unlikely(lvm_task_teardown(llt)))
		goto err_put;
	if (require_idle && n != 1) {
		refcount_release(&lvm->refcount);
		return NULL;
	}
	if (!require_idle) {
		WARN_ON(n != 1);
		KASSERT(n == 1, ("<%s> Lua VM is reused, refcount = %d\n",
				 task->comm, n));
	}

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
		return lvm_get_from_task(current, false);
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

/********************************** sandbox **********************************/

static int lua_shared_index(lua_State *L)
{
	const char *name = luaL_checkstring(L, 2);
	struct lua_lsm_module_shdict *shdict, *shtmp;
	struct lua_lsm_module *module;
	int found = 0;

	__log_info_ratelimited("READ shared table, [%s] %s\n",
			       luaL_typename(L, 2),
			       lua_tostring(L, 2) ?: "(null)");

	lua_pushlightuserdata(L, MODULE_KEY);
	lua_gettable(L, LUA_ENVIRONINDEX);	/* env.MODULE_KEY */
	if (!lua_islightuserdata(L, -1)) {
		__log_err("NO fenv module\n");
		return 0;
	}
	module = lua_touserdata(L, -1);

	rcu_read_lock();
	list_for_each_entry_rcu(shdict, &module->shdicts, list) {
		if (strcmp(shdict->name, name) == 0) {
			found = 1;
			break;
		}
	}
	rcu_read_unlock();

	if (!found) {
		unsigned long flags;
		size_t l = strlen(name);

		shdict = kmalloc(struct_size(shdict, name, l + 1),
				 lua_lsm_gfp());
		if (!shdict) {
			__log_err("No memory\n");
			return 0;
		}
		kvcache_dict_init(&shdict->dict);
		memcpy(shdict->name, name, l);
		shdict->name[l] = '\0';

		spin_lock_irqsave(&module->shdict_lock, flags);
		list_for_each_entry(shtmp, &module->shdicts, list) {
			if (strcmp(shtmp->name, name) == 0) {
				found = 1;
				break;
			}
		}
		if (!found) {
			atomic_inc(&module->shdict_count);
			list_add_tail_rcu(&shdict->list, &module->shdicts);
		}
		spin_unlock_irqrestore(&module->shdict_lock, flags);

		if (found) {
			kvcache_dict_free(&shdict->dict);
			kfree(shdict);

			shdict = shtmp;
		}
	}

	/* shared[name] = shdict */
	lua_pushvalue(L, 2);
	*newshdict(L) = &shdict->dict;
	lua_rawset(L, 1);

	lua_settop(L, 2);
	lua_rawget(L, 1);
	return 1;
}

static int lua_shared_newindex(lua_State *L)
{
	__log_err("Invalid operation: WRITE shared table, [%s] %s - [%s] %s\n",
		  luaL_typename(L, 2), lua_tostring(L, 2) ?: "(null)",
		  luaL_typename(L, 3), lua_tostring(L, 3) ?: "(null)");
	return 0;
}

static int lua_module_fenv_newindex(lua_State *L)
{
	/* args: t, k, v */
	__log_warn("Warning: set global variable, [%s] %s - [%s] %s\n",
		   luaL_typename(L, 2), lua_tostring(L, 2) ?: "(null)",
		   luaL_typename(L, 3), lua_tostring(L, 3) ?: "(null)");

	/* XXX: t[k] = v, Warning it, but still perform assignment */
	lua_rawset(L, 1);
	return 0;
}

static int module_load(lua_State *L, struct lua_lsm_module *module)
{
	int err;

	lua_newtable(L);			/* env */
	lua_pushvalue(L, -1);
	lua_replace(L, LUA_ENVIRONINDEX);

	/* Must be after lua_replace(LUA_ENVIRONINDEX) to ensure correct env */
	lua_pushlightuserdata(L, MODULE_KEY);
	lua_pushlightuserdata(L, module);
	lua_settable(L, -3);			/* env.MODULE_KEY = module */
	*newtask_nomain(L) = current;
	lua_setfield(L, -2, "current");		/* env.current = current */

	lua_newtable(L);			/* shared table */
	lua_createtable(L, 0, 2);		/* shared metatable */
	lua_pushcfunction(L, lua_shared_index);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction(L, lua_shared_newindex);
	lua_setfield(L, -2, "__newindex");
	lua_setmetatable(L, -2);		/* setmetatable(shared, mt) */
	lua_setfield(L, -2, "shared");		/* env.shared = shared */

	/* setmetatable(env, { __index = _G, __newindex = func }) */
	lua_createtable(L, 0, 2);		/* metatable */
	lua_pushvalue(L, LUA_GLOBALSINDEX);
	lua_setfield(L, -2, "__index");		/* metatable.__index = _G */
	lua_pushcfunction(L, lua_module_fenv_newindex);
	lua_setfield(L, -2, "__newindex");	/* metatable.__newindex = func */
	lua_setmetatable(L, -2);		/* setmetatable(env, metatable) */

	lua_pushcfunction(L, lua_traceback);
	err = luaL_loadbuffer_wrap(L, module->chunk,
				   module->chunk_len, module->name);
	if (err) {
		lua_pop(L, 2);
		return err;
	}

	/* stack: [env, traceback, modfunc] */
	lua_pushvalue(L, -3);
	lua_setfenv(L, -2);			/* setfenv(modfunc, env) */

	err = lua_pcall_wrap(L, 0, 1, -2);
	if (err) {
		lua_pop(L, 2);
		return err;
	}

	/* stack: [env, traceback, _M] */
	if (!lua_istable(L, -1)) {
		__log_err("module <%s> is not a table: top = %d [%s]\n",
			  module->name, lua_gettop(L), luaL_typename(L, -1));
		lua_pop(L, 3);
		return -EBADF;
	}

	lua_remove(L, -2);			/* remove traceback */
	lua_remove(L, -2);			/* remove env */
	/* NO error, only _M is returned */
	return 0;
}

static int lua_modules_index(lua_State *L)
{
	const char *key = luaL_checkstring(L, 2);
	struct lua_lsm_module *module;
	int err;

	/* module queries are always run with a read lock */
	list_for_each_entry_srcu(module, &lsm_modules, list,
				 srcu_read_lock_held(&modules_ss)) {
		if (strcmp(module->name, key) != 0)
			continue;

		lvm_mark_dirty(L);
		err = module_load(L, module);
		if (err) {
			__log_err("load: %s, err = %d, top = %d\n",
				  key, err, lua_gettop(L));
			return 0;
		}

		lua_insert(L, -2);
		lua_pushvalue(L, -2);
		/* stack: [table, thunk, key, thunk] */
		lua_rawset(L, 1);		/* table[key] = thunk */

		atomic_inc(&module->nloaded);
		return 1;			/* return the thunk */
	}

	__log_err("'%s' NOT found, top = %d\n", key, lua_gettop(L));
	return 0;
}

/*
 * When LuaVM is destroyed, iterate over the modules loaded in the VM
 * and update the load count in the module.
 */
static void lua_modules_free(struct task_struct *task, lua_State *L)
{
	struct lua_lsm_module *module;

	lua_getfield(L, LUA_REGISTRYINDEX, "_MODULES");
	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		return;
	}

	list_for_each_entry_srcu(module, &lsm_modules, list, srcu_read_lock_held(&modules_ss)) {
		lua_pushstring(L, module->name);
		lua_rawget(L, -2);
		if (lua_istable(L, -1)) {
			atomic_dec(&module->nloaded);
			__log_info("<%s>: %d-%d freed module <%s>, nloaded = %d\n",
				   task->comm, task_tgid_nr(task), task_pid_nr(task),
				   module->name, atomic_read(&module->nloaded));
		}
		lua_pop(L, 1);
	}
	lua_pop(L, 1);
}

/********************************** Lua VM **********************************/

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

static int lua_state_alloc(struct lvm_state *lvm)
{
	lua_State *L = lvm_build_lua_state(lvm);

	if (!L)
		return -ENOMEM;
	lvm->L = L;
	return 0;
}

static void lua_state_free(struct lvm_state *lvm)
{
	if (lvm->L) {
		lvm_stats_vmfree();
		lua_close(lvm->L);
		lvm->L = NULL;
	}
}

/********************************** module **********************************/

static int lvm_writer(lua_State *L, const void *b, size_t size, void *B)
{
	(void)L;
	luaL_addlstring((luaL_Buffer *)B, (const char *)b, size);
	return 0;
}

static void lua_lsm_module_free(struct lua_lsm_module *module)
{
	kfree(module->chunk);
	kfree(module->name);
	kfree(module->author);
	kfree(module->description);
	kfree(module->license);
	kfree(module);
}

int lua_lsm_module_register(const char *code, size_t len)
{
	struct lua_lsm_module *module, *m;
	struct lvm_state lvm;
	lua_State *L;
	luaL_Buffer B;
	const char *chunk;
	size_t chunk_len;
	int found = 0;
	int i;
	int status;
	int err;

	memset(&lvm, 0, sizeof(struct lvm_state));
	err = lua_state_alloc(&lvm);
	if (err)
		return err;

	L = lvm.L;
	lua_pushcfunction(L, lua_traceback);
	err = luaL_loadbuffer_wrap(L, code, len, "<lua-lsm:loader>");
	if (err)
		goto err_free_lua;

	/* TODO: run in sandbox, record the `require` lua modules */
	/* stack: [traceback, func] */
	err = lua_pcall_wrap(L, 0, 1, -2);
	if (err)
		goto err_free_lua;
	if (!lua_istable(L, -1)) {
		__log_err("pcall: top = %d [%s]\n",
			  lua_gettop(L), luaL_typename(L, -1));
		err = -EBADF;
		goto err_free_lua;
	}
	__log_info("lua module loaded, top = %d\n", lua_gettop(L));

	err = -ENOMEM;
	module = kzalloc(sizeof(*module), GFP_KERNEL);
	if (!module)
		goto err_free_lua;

	module->state = LMS_STATE_COMING;
	__BITMAP_ZERO(&module->hookfuncs);

	/* traversal the result table */
	lua_pushnil(L);
	while (lua_next(L, -2) != 0) {
		static const struct {
			const char *field;
			int type;
			int offset;
		} fields[] = {
			{ "name", LUA_TSTRING,
			  offsetof(struct lua_lsm_module, name) },
			{ "author", LUA_TSTRING,
			  offsetof(struct lua_lsm_module, author) },
			{ "description", LUA_TSTRING,
			  offsetof(struct lua_lsm_module, description) },
			{ "license", LUA_TSTRING,
			  offsetof(struct lua_lsm_module, license) },
			{ "version", LUA_TNUMBER,
			  offsetof(struct lua_lsm_module, version) },
			{ NULL }
		};
		const char *key, *s;
		char *p;

		if (!lua_isstring(L, -2)) {
			__log_err("module table index must be a string\n");
			lua_pop(L, 1);
			continue;
		}

		key = lua_tostring(L, -2);

		for (i = 0; fields[i].field; i++) {
			if (strcmp(key, fields[i].field) != 0)
				continue;

			if (lua_type(L, -1) != fields[i].type) {
				__log_err("field '%s' must be a %s\n",
					  key, lua_typename(L, fields[i].type));
				break;
			}

			p = (char *)module + fields[i].offset;
			switch (lua_type(L, -1)) {
			case LUA_TSTRING:
				s = lua_tostring(L, -1);
				*(const char **)p = kstrdup(s, GFP_KERNEL);
				break;
			case LUA_TNUMBER:
				*(int *)p = (int)lua_tointeger(L, -1);
				break;
			}
			break;
		}

		if (!fields[i].field) {
			for (i = 0; lua_lsm_hook_stats[i].name; i++) {
				if (strcmp(lua_lsm_hook_stats[i].name, key) != 0)
					continue;

				if (!lua_lsm_hook_supported(i)) {
					__log_err("hook '%s' is not supported by Lua-LSM\n",
						  key);
					err = -EOPNOTSUPP;
					goto err_free_module;
				}

				if (!lua_isfunction(L, -1)) {
					__log_err("field '%s' must be a function\n", key);
					break;
				}

				module->nhooks += 1;
				__BITMAP_SET(i, &module->hookfuncs);

				__log_info("hookfunc = %s\n", key);
				break;
			}

			if (!lua_lsm_hook_stats[i].name)
				__log_warn("field '%s' is unknown\n", key);
		}

		/* removes 'value'; keeps 'key' for next iteration */
		lua_pop(L, 1);
	}

	err = -ENOMEM;
	if (!module->name)
		goto err_free_module;

	/* Recompile with the new name */
	err = luaL_loadbuffer_wrap(L, code, len, module->name);
	if (err)
		goto err_free_module;

	/* dump function */
	luaL_checktype(L, -1, LUA_TFUNCTION);
	luaL_buffinit(L, &B);
	status = lua_dump(L, lvm_writer, &B);
	if (status != 0) {
		__log_err("dump: unable to dump the function\n");
		err = -EFAULT;
		goto err_free_module;
	}
	luaL_pushresult(&B);
	/* stack: [traceback, _M, func, chunk] */
	chunk = lua_tolstring(L, -1, &chunk_len);
	__log_info("[%s] compiled, source_len = %d, chunk_len = %d\n",
		   module->name, (int)len, (int)chunk_len);

	module->chunk = kmalloc(chunk_len, GFP_KERNEL);
	if (!module->chunk)
		goto err_free_module;
	memcpy(module->chunk, chunk, chunk_len);
	module->chunk_len = chunk_len;

	INIT_LIST_HEAD(&module->shdicts);
	spin_lock_init(&module->shdict_lock);
	atomic_set(&module->shdict_count, 0);

	INIT_LIST_HEAD(&module->kvnodes);
	spin_lock_init(&module->kvnodes_lock);
	atomic_set(&module->kvnodes_count, 0);

	mutex_lock(&modules_mutex);
	list_for_each_entry(m, &lsm_modules, list) {
		if (strcmp(module->name, m->name) == 0) {
			found = 1;
			break;
		}
	}
	if (!found) {
		for (i = 0; lua_lsm_hook_stats[i].name; i++) {
			if (__BITMAP_ISSET(i, &module->hookfuncs))
				atomic_inc(&lua_lsm_hook_stats[i].nhooks);
		}

		module->state = LMS_STATE_LIVE;
		list_add_tail_rcu(&module->list, &lsm_modules);
		/*
		 * Once any Lua policy has been loaded, inactive free-hook cleanup
		 * must stay armed for objects that outlive later module unload.
		 */
		static_branch_enable(&lua_lsm_inactive_cleanup_armed);
		static_branch_inc(&lua_lsm_modules_active);
	}
	mutex_unlock(&modules_mutex);

	err = -EEXIST;
	if (found) {
		__log_err("module <%s> registered already\n", module->name);
		goto err_free_module;
	}

	pr_info("module <%s> registered with %d filters\n",
		module->name, module->nhooks);

	lua_state_free(&lvm);
	return 0;

err_free_module:
	lua_lsm_module_free(module);
err_free_lua:
	lua_state_free(&lvm);

	return err;
}

static int lvm_remove_module(lua_State *L, struct lua_lsm_module *module)
{
	int err = -ENOENT;
	/* registry._MODULES[modname] = nil */
	lua_getfield(L, LUA_REGISTRYINDEX, "_MODULES");
	if (lua_istable(L, -1)) {
		lua_pushstring(L, module->name);
		lua_rawget(L, -2);
		if (lua_istable(L, -1)) {
			lua_pop(L, 1);

			lua_pushstring(L, module->name);
			lua_pushnil(L);
			lua_rawset(L, -3);

			/* performs a full garbage-collection cycle. */
			lua_gc(L, LUA_GCCOLLECT, 0);
			err = 0;
		} else {
			lua_pop(L, 1);
		}
	}
	lua_pop(L, 1);
	return err;
}

static int task_remove_module(struct task_struct *task, void *arg)
{
	struct lua_lsm_task *llt = lua_lsm_task(task);
	struct lua_lsm_module *module = arg;
	struct lvm_state *lvm;
	lua_State *L;
	int err;

	if (task_curr(task) && task != current)
		return -EBUSY;

	/* Unregister must not lazily create a VM for untouched tasks. */
	/* Pairs with cmpxchg() in lvm_get_task_state(). */
	lvm = smp_load_acquire(&llt->lvm);
	if (!lvm || !smp_load_acquire(&lvm->L))
		return -ENOENT;

	L = lvm_get_from_task(task, true);
	if (!L)
		return -EAGAIN;

	err = lvm_remove_module(L, module);
	lvm_put_to_task(task, L);
	return err;
}

static int tasks_lvm_remove_module(struct lua_lsm_module *module, int *nbusy)
{
	struct task_struct *g, *task;
	int count = 0;
	int err;

	*nbusy = 0;
	/* remove loaded module from every Lua VM */
	read_lock(&tasklist_lock);
	for_each_process_thread(g, task) {
		if (task == current)
			err = task_remove_module(task, module);
		else
			err = task_call_func(task, task_remove_module, module);

		if (!err) {
			count++;
			__log_info("<%s>: err = [ OK ] \t<%s>: %d-%d\n", module->name,
				   task->comm, task_tgid_nr(task), task_pid_nr(task));
		} else if (err == -EBUSY || err == -EAGAIN) {
			*nbusy += 1;
			__log_info("<%s>: err = %s \t<%s>: %d-%d\n",
				   module->name, err == -EBUSY ? "EBUSY" : "EAGAIN",
				   task->comm, task_tgid_nr(task), task_pid_nr(task));
		} else if (err != -ENOENT) {
			__log_info_ratelimited("<%s>: err = %d \t<%s>: %d-%d\n",
					       module->name, err,
					       task->comm, task_tgid_nr(task), task_pid_nr(task));
		}
	}
	read_unlock(&tasklist_lock);
	return count;
}

/*
 * Due to the limitations of schedule_on_each_cpu(), global variables
 * are used to pass parameters to the callback function.
 */
static struct lua_lsm_module *work_ctx_remove_module;
static atomic_t work_ctx_remove_count;

static void softirq_lvm_remove_module(struct work_struct *work)
{
	struct lua_lsm_module *module = work_ctx_remove_module;
	int cpu = smp_processor_id();
	int err;

	WARN_ON(!work_ctx_remove_module);
	/*
	 * Disable softirq to prevent triggered softirq or RCU from
	 * changing the Lua VM environment.
	 */
	local_bh_disable();
	err = lvm_remove_module(per_cpu(irq_lvms, cpu)->L, module);
	if (!err) {
		atomic_inc(&work_ctx_remove_count);
		__log_info("<%s>: err = [ OK ] \t<softirq-%d>, count = %d\n",
			   module->name, cpu, atomic_read(&work_ctx_remove_count));
	}
	local_bh_enable();
}

int lua_lsm_module_unregister(const char *name)
{
	struct lua_lsm_module *module;
	struct lua_lsm_module_shdict *shdict, *tmp;
	int count = 0, nloaded, nbusy;
	unsigned int cpu;
	int found = 0;
	int err;
	int i;

	mutex_lock(&modules_mutex);
	list_for_each_entry(module, &lsm_modules, list) {
		if (strcmp(module->name, name) == 0) {
			found = 1;
			break;
		}
	}
	if (found && module->state == LMS_STATE_LIVE) {
		module->state = LMS_STATE_GOING;
		static_branch_dec(&lua_lsm_modules_active);

		for (i = 0; lua_lsm_hook_stats[i].name; i++) {
			if (__BITMAP_ISSET(i, &module->hookfuncs))
				atomic_dec(&lua_lsm_hook_stats[i].nhooks);
		}
	}

	if (!found) {
		mutex_unlock(&modules_mutex);
		return -ENOENT;
	}

	pr_info("Prepare to unregister module <%s> ...\n", name);

	synchronize_srcu(&modules_ss);

	list_for_each_entry_safe(shdict, tmp, &module->shdicts, list) {
		list_del(&shdict->list);
		kvcache_dict_free(&shdict->dict);
		kfree(shdict);
		atomic_dec(&module->shdict_count);
	}

	kvcache_module_nodes_gc(module);

	nloaded = atomic_read(&module->nloaded);
	/* remove loaded module from every Lua VM */
	if (nloaded > 0) {
		count += tasks_lvm_remove_module(module, &nbusy);

		__log_info("Unregister module <%s> from task, freed = %d/%d, nbusy = %d\n",
			   name, count, nloaded, nbusy);
	}

	/*
	 * At this time, LuaVM may still be released asynchronously,
	 * so the nloaded will be updated in the air.
	 */
	nloaded = atomic_read(&module->nloaded);
	if (count < nloaded) {
		/*
		 * Since global variables are used, locking ensures that only
		 * one instance of the softirq LuaVM offload is executed.
		 */
		work_ctx_remove_module = module;
		atomic_set(&work_ctx_remove_count, 0);

		err = schedule_on_each_cpu(softirq_lvm_remove_module);
		WARN_ON(err);
		count += atomic_read(&work_ctx_remove_count);

		__log_info("Unregister module <%s> from pcpu, freed = %d/%d\n",
			   name, count, nloaded);
	}

	nloaded = atomic_read(&module->nloaded);
	if (count < nloaded) {
		/* ditto for the idle 'swapper' tasks */
		cpus_read_lock();
		for_each_possible_cpu(cpu) {
			/* TODO: remove 'swapper' tasks Lua VM */
			err = task_call_func(idle_task(cpu), task_remove_module, module);
			if (!err)
				count++;
		}
		cpus_read_unlock();

		__log_info("Unregister module <%s> from swapper, freed = %d/%d\n",
			   name, count, atomic_read(&module->nloaded));
	}

	nloaded = atomic_read(&module->nloaded);
	if (count < nloaded && nbusy > 0) {
		for (i = 1; i <= 5; i++) {
			count += tasks_lvm_remove_module(module, &nbusy);
			WARN_ON(count > nloaded);

			__log_info("Unregister module <%s> from task, freed = %d/%d, nbusy = %d, loop = %d\n",
				name, count, nloaded, nbusy, i);

			nloaded = atomic_read(&module->nloaded);
			if (count == nloaded || nbusy == 0)
				break;

			msleep(500 * i);

			nloaded = atomic_read(&module->nloaded);
			if (count == nloaded)
				break;
		}
	}

	if (atomic_sub_return(count, &module->nloaded) == 0) {
		list_del_rcu(&module->list);
		synchronize_srcu(&modules_ss);
		lua_lsm_module_free(module);
		err = 0;
	} else {
		module->state = LMS_STATE_ZOMBIE;
		err = -EBUSY;
	}
	mutex_unlock(&modules_mutex);

	pr_info("Unregistered module <%s> from %d/%d Lua VMs, vm_nusage = %d\n",
		name, count, nloaded, atomic_read(&vm_nusage));

	return err;
}

int modules_show(struct seq_file *m, void *v)
{
	struct lua_lsm_module *module;
	int idx;

	seq_printf(m, "modules for lua-lsm\n");
	seq_printf(m, "%-20s %-10s %6s %4s %5s %6s %6s %-34s\n",
		   "name", "license", "size", "nlsm",
		   "nload", "shdict", "kvnode", "author");
	seq_printf(m, "%s\n", TABLINE);

	idx = srcu_read_lock(&modules_ss);
	list_for_each_entry_srcu(module, &lsm_modules, list, srcu_read_lock_held(&modules_ss)) {
		seq_printf(m, "%-20s %-10s %6zu %4d %5d %6d %6d %-34s\n",
			   module->name, module->license, module->chunk_len,
			   module->nhooks, atomic_read(&module->nloaded),
			   atomic_read(&module->shdict_count),
			   atomic_read(&module->kvnodes_count), module->author);
	}
	srcu_read_unlock(&modules_ss, idx);
	return 0;
}

/*********************************** main ***********************************/

int task_blob_init(struct task_struct *task)
{
	struct lua_lsm_task *llt = lua_lsm_task(task);

	WRITE_ONCE(llt->lvm_teardown, false);
	return 0;
}

void task_blob_free(struct task_struct *task)
{
	struct lua_lsm_task *llt = lua_lsm_task(task);
	struct lvm_state *lvm;

	/*
	 * Lua GC can run finalizers which re-enter LSM hooks. Keep the task VM
	 * published until reset completes, but make lvm_get() skip this task so
	 * re-entrant hooks cannot allocate or reuse a VM during teardown.
	 */
	smp_store_release(&llt->lvm_teardown, true);
	/* Pairs with cmpxchg() in lvm_get_task_state(). */
	lvm = smp_load_acquire(&llt->lvm);
	if (lvm && READ_ONCE(lvm->L) && lvm->dirty) {
		lua_modules_free(task, lvm->L);
		lvm_vm_reset(lvm);
		lvm->dirty = false;
	}

	lvm = xchg(&llt->lvm, NULL);
	if (lvm) {
		if (!READ_ONCE(lvm->L)) {
			kfree(lvm);
		} else {
			refcount_init(&lvm->refcount, 0);
			lvm_pool_put(lvm);
		}
	}
	kvcache_dict_free(&llt->dict);
}

/*
 * TODO: Currently, the key, perf_event, tun_dev, and ib objects do not
 * have corresponding free LSM callback functions, which prevents object
 * properties from being released. Therefore, setting properties for these
 * four objects is not supported at this time, as this requires support at
 * the security subsystem architecture.
 */
struct lsm_blob_sizes lua_lsm_blob_sizes __ro_after_init = {
	.lbs_task = sizeof(struct lua_lsm_task),
	.lbs_cred = sizeof(struct lua_lsm_object),
	.lbs_file = sizeof(struct lua_lsm_object),
	.lbs_backing_file = sizeof(struct lua_lsm_object),
	.lbs_ib = 0,
	.lbs_inode = sizeof(struct lua_lsm_object),
	.lbs_sock = sizeof(struct lua_lsm_object),
	.lbs_superblock = sizeof(struct lua_lsm_object),
	.lbs_ipc = sizeof(struct lua_lsm_object),
	.lbs_key = 0,
	.lbs_msg_msg = sizeof(struct lua_lsm_object),
	.lbs_perf_event = 0,
	/* TODO: number of xattr slots in new_xattrs array */
	.lbs_xattr_count = 10,
	.lbs_tun_dev = 0,
	.lbs_bdev = sizeof(struct lua_lsm_object),
};

static struct security_hook_list lua_lsm_hooks[] __ro_after_init = {
	#define LSM_HOOK(RET, DEFAULT, NAME, ...)			\
		LSM_HOOK_INIT(NAME, lua_lsm_ ## NAME),

	#include <linux/lsm_hook_defs.h>
	#undef LSM_HOOK
};

int lua_lsm_enabled __ro_after_init = 1;

static const struct lsm_id lua_lsmid = {
	.name = "lua",
	.id = LSM_ID_LUA,
};

static int __init lua_lsm_init(void)
{
	struct lvm_state *lvm;
	int cpu;
	int err;
	int i;

	for_each_possible_cpu(cpu)
		lvm_pool_init_cpu(cpu);

#ifdef CONFIG_SECURITY_LUA_LSM_STATS
	for_each_possible_cpu(cpu)
		lua_lsm_hook_stats_init_cpu(cpu);
#endif

	err = task_blob_init(current);
	if (err)
		return err;

	for_each_possible_cpu(cpu) {
		lvm = kzalloc(sizeof(struct lvm_state), GFP_KERNEL);
		if (!lvm)
			return -ENOMEM;

		err = lua_state_alloc(lvm);
		if (err)
			return err;

		per_cpu(irq_lvms, cpu) = lvm;
	}

	/* Register only the hooks that Lua-LSM exposes to modules. */
	for (i = 0; i < ARRAY_SIZE(lua_lsm_hooks); i++) {
		if (!lua_lsm_hook_supported(i))
			continue;
		security_add_hooks(&lua_lsm_hooks[i], 1, &lua_lsmid);
	}

	/* Report that Lua-LSM successfully initialized */
	lua_lsm_initialized = 1;

	pr_info("Lua based LSM initialized (lvm_pool_max=%u)\n",
		READ_ONCE(lua_lvm_pool_max));
	return 0;
}

DEFINE_LSM(lua) = {
	.id = &lua_lsmid,
	.enabled = &lua_lsm_enabled,
	.blobs = &lua_lsm_blob_sizes,
	.init = lua_lsm_init,
	.initcall_fs = lua_lsm_securityfs_init,
};
