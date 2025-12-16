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
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/compiler.h>
#include <linux/rwlock.h>
#include <linux/cred.h>
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

bool debug = true;

static int __init disable_debug(char *str)
{
	debug = false;
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

static atomic_t vm_nalloc = ATOMIC_INIT(0);
static atomic_t vm_nfree = ATOMIC_INIT(0);
static atomic_t mem_nalloc = ATOMIC_INIT(0);
static atomic_t mem_nrealloc = ATOMIC_INIT(0);
static atomic_t mem_nfree = ATOMIC_INIT(0);
static atomic_t mem_total = ATOMIC_INIT(0);
static atomic_t mem_minimum = ATOMIC_INIT(INT_MAX);
static atomic_t mem_maximum = ATOMIC_INIT(0);

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
		atomic_inc(&mem_nfree);
		atomic_inc(&lvm->nfree);
		atomic_sub((int)osize, &mem_total);
	} else {
		if (ptr) {
			atomic_inc(&mem_nrealloc);
			atomic_inc(&lvm->nrealloc);
		} else {
			atomic_inc(&mem_nalloc);
			atomic_inc(&lvm->nalloc);
		}

		atomic_add(nsize - osize, &mem_total);
	}

	if (L == NULL)
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

	seq_printf(m, "lvm.nalloc\t= %9d\n", atomic_read(&vm_nalloc));
	seq_printf(m, "lvm.nfree\t= %9d\n", atomic_read(&vm_nfree));
	seq_printf(m, "lvm.nusage\t= %9d\n", nusage);
	seq_printf(m, "lmem.nalloc\t= %9d\n", atomic_read(&mem_nalloc));
	seq_printf(m, "lmem.nrealloc\t= %9d\n", atomic_read(&mem_nrealloc));
	seq_printf(m, "lmem.nfree\t= %9d\n", atomic_read(&mem_nfree));
	seq_printf(m, "lmem.total\t= %9d\n", total);
	seq_printf(m, "lmem.average\t= %9d\n", average);
	seq_printf(m, "lmem.minimum\t= %9d\n", atomic_read(&mem_minimum));
	seq_printf(m, "lmem.maximum\t= %9d\n", atomic_read(&mem_maximum));
}

int lsm_funcs_show(struct seq_file *m, void *v)
{
	struct lua_lsm_hook_stat *stat;
	int i = 1;

	seq_printf(m, "stats for lua-lsm (ns)\n");
	seq_printf(m, "%3s %-28s %4s %12s %15s %10s %12s\n",
		"num", "name", "nlsm", "count", "total", "average", "maxtime");
	seq_printf(m, "%s\n", TABLINE);

	for (stat = lua_lsm_hook_stats; stat->name; stat++) {
		int n = atomic_read(&stat->count);
		s64 total = atomic64_read(&stat->time);
		s64 maxtime = atomic64_read(&stat->maxtime);
		seq_printf(m, "%3d %-28s %4d %12d %15llu %10llu %12llu\n",
			i++, stat->name, atomic_read(&stat->nhooks),
			n, total, n ? total / n : 0, maxtime);
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

static lua_State *
lvm_get_from_task(const struct task_struct *task, bool exclusive)
{
	struct lua_lsm_task *llt = lua_lsm_task(task);
	struct lvm_state *lvm = &llt->lvm;
	int n = refcount_acquire(&lvm->refcount);
	if (exclusive && n != 1) {
		refcount_release(&lvm->refcount);
		return NULL;
	}
	WARN_ON(n != 1);
	KASSERT(n == 1, ("<%s> Lua VM is reused, refcount = %d\n",
		task->comm, n));
	return lvm->L;
}

static void lvm_put_to_task(const struct task_struct *task, lua_State *L)
{
	struct lua_lsm_task *llt = lua_lsm_task(task);
	struct lvm_state *lvm = &llt->lvm;
	int n = refcount_release(&lvm->refcount);
	KASSERT(n == 0, ("<%s> Lua VM is reused, refcount = %d\n",
		task->comm, n));
	WARN_ON(L != lvm->L);
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
		luaL_typename(L, 2), lua_tostring(L, 2) ?: "(null)");

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
		if (shdict == NULL) {
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
	*newtask(L) = current;
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

	list_for_each_entry_srcu(module, &lsm_modules, list,
				srcu_read_lock_held(&modules_ss)) {
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

static int lua_state_alloc(struct lvm_state *lvm)
{
	lua_State *L;
	int status;

	L = lua_newstate(lvm_alloc, lvm);
	if (L == NULL)
		return -ENOMEM;

	lvm->L = L;
	lua_atpanic(L, lvm_panic);
	lua_gc(L, LUA_GCSTOP, 0);

	lua_pushcfunction(L, lvm_pmain);
	status = lua_pcall(L, 0, 1, 0);
	if (status != 0) {
		__log_err("pcall: status = %d, top = %d, %s\n",
			status, lua_gettop(L), lua_tostring(L, -1));
		status = -ENOEXEC;
	} else if (!lua_toboolean(L, -1) && lua_gettop(L) != 1) {
		__log_err("lvm_pmain: top = %d, stack[top] = [%s]\n",
			lua_gettop(L), luaL_typename(L, -1));
		status = -EFAULT;
	} else {
		lua_pop(L, 1);		/* pop boolean result */
		status = 0;
	}

	if (status != 0) {
		lua_close(L);
		lvm->L = NULL;
		return status;
	}

	lvm_stats_vmalloc();
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
	if (module == NULL)
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
			{ "name",		LUA_TSTRING,	offsetof(struct lua_lsm_module,	name)		},
			{ "author",		LUA_TSTRING,	offsetof(struct lua_lsm_module,	author)		},
			{ "description",	LUA_TSTRING,	offsetof(struct lua_lsm_module,	description)	},
			{ "license",		LUA_TSTRING,	offsetof(struct lua_lsm_module,	license)	},
			{ "version",		LUA_TNUMBER,	offsetof(struct lua_lsm_module,	version)	},
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

		if (fields[i].field == NULL) {
			for (i = 0; lua_lsm_hook_stats[i].name; i++) {
				if (strcmp(lua_lsm_hook_stats[i].name, key) != 0)
					continue;

				if (!lua_isfunction(L, -1)) {
					__log_err("field '%s' must be a function\n", key);
					break;
				}

				module->nhooks += 1;
				__BITMAP_SET(i, &module->hookfuncs);

				__log_info("hookfunc = %s\n", key);
				break;
			}

			if (lua_lsm_hook_stats[i].name == NULL)
				__log_warn("field '%s' is unknown\n", key);
		}

		/* removes 'value'; keeps 'key' for next iteration */
		lua_pop(L, 1);
	}

	err = -ENOMEM;
	if (module->name == NULL)
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
	if (module->chunk == NULL)
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
	struct lua_lsm_module *module = arg;
	lua_State *L;
	int err;

	if (task_curr(task) && task != current)
		return -EBUSY;

	L = lvm_get_from_task(task, true);
	if (L == NULL)
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
		} else {
			__log_info_ratelimited("<%s>: err = %s \t<%s>: %d-%d\n",
				module->name, err == -ENOENT ? "[ENOENT]" : "unknown",
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

	WARN_ON(work_ctx_remove_module == NULL);
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
	list_for_each_entry_srcu(module, &lsm_modules, list,
				srcu_read_lock_held(&modules_ss)) {
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
	struct lvm_state *lvm = &llt->lvm;
	int err;

	kvcache_dict_init(&llt->dict);

	refcount_init(&lvm->refcount, 0);
	err = lua_state_alloc(lvm);
	if (err)
		return err;

	return 0;
}

void task_blob_free(struct task_struct *task)
{
	struct lua_lsm_task *llt = lua_lsm_task(task);
	struct lvm_state *lvm = &llt->lvm;
	lua_modules_free(task, lvm->L);
	lua_state_free(lvm);
	kvcache_dict_free(&llt->dict);
}

struct lsm_blob_sizes lua_lsm_blob_sizes __ro_after_init = {
	.lbs_task = sizeof(struct lua_lsm_task),
	.lbs_cred = sizeof(struct lua_lsm_object),
	.lbs_file = sizeof(struct lua_lsm_object),
	.lbs_ib = sizeof(struct lua_lsm_object),
	.lbs_inode = sizeof(struct lua_lsm_object),
	.lbs_sock = sizeof(struct lua_lsm_object),
	.lbs_superblock = sizeof(struct lua_lsm_object),
	.lbs_ipc = sizeof(struct lua_lsm_object),
	.lbs_key = sizeof(struct lua_lsm_object),
	.lbs_msg_msg = sizeof(struct lua_lsm_object),
	.lbs_perf_event = sizeof(struct lua_lsm_object),
	/* TODO: number of xattr slots in new_xattrs array */
	.lbs_xattr_count = 10,
	.lbs_tun_dev = sizeof(struct lua_lsm_object),
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

	err = task_blob_init(current);
	if (err)
		return err;

	for_each_possible_cpu(cpu) {
		lvm = kzalloc(sizeof(struct lvm_state), GFP_KERNEL);
		if (lvm == NULL)
			return -ENOMEM;

		err = lua_state_alloc(lvm);
		if (err)
			return err;

		per_cpu(irq_lvms, cpu) = lvm;
	}

	security_add_hooks(lua_lsm_hooks, ARRAY_SIZE(lua_lsm_hooks), &lua_lsmid);

	/* Report that Lua-LSM successfully initialized */
	lua_lsm_initialized = 1;

	pr_info("Lua based LSM initialized\n");
	return 0;
}

DEFINE_LSM(lua) = {
	.name = "lua",
	.enabled = &lua_lsm_enabled,
	.blobs = &lua_lsm_blob_sizes,
	.init = lua_lsm_init,
};
