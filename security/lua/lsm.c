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

/********************************** Lua VM **********************************/

struct lvm_userdata {
	bool softirq;
};

static struct lvm_userdata irq_lvms_ud = {
	.softirq = true,
};

static DEFINE_PER_CPU(lua_State *, irq_lvms);

static lua_State *
lvm_get_from_task(const struct task_struct *task, bool exclusive)
{
	struct lua_lsm_task *llt = lua_lsm_task(task);
	int n = refcount_acquire(&llt->refcount);
	if (exclusive && n != 1) {
		refcount_release(&llt->refcount);
		return NULL;
	}
	WARN_ON(n != 1);
	KASSERT(n == 1, ("<%s> Lua VM is reused, refcount = %d\n",
		task->comm, n));
	return llt->L;
}

static void lvm_put_to_task(const struct task_struct *task, lua_State *L)
{
	struct lua_lsm_task *llt = lua_lsm_task(task);
	int n = refcount_release(&llt->refcount);
	KASSERT(n == 0, ("<%s> Lua VM is reused, refcount = %d\n",
		task->comm, n));
	WARN_ON(L != llt->L);
}

lua_State *lvm_get(void)
{
	BUG_ON(in_nmi() || in_hardirq());

	if (in_task())
		return lvm_get_from_task(current, false);
	else
		return get_cpu_var(irq_lvms);
}

void lvm_put(lua_State *L)
{
	if (in_task())
		lvm_put_to_task(current, L);
	else
		put_cpu_var(irq_lvms);
}


static int lua_shared_index(lua_State *L)
{
	const char *name = luaL_checkstring(L, 2);
	struct lua_module_shdict *shdict, *shtmp;
	struct lua_module *module;
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
	__log_warn("warning: set global variable, [%s] %s - [%s] %s\n",
		luaL_typename(L, 2), lua_tostring(L, 2) ?: "(null)",
		luaL_typename(L, 3), lua_tostring(L, 3) ?: "(null)");

	/* XXX: t[k] = v, Warning it, but still perform assignment */
	lua_rawset(L, 1);
	return 0;
}

static int lua_module_load(lua_State *L, struct lua_module *module)
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

static int lua_module_index(lua_State *L)
{
	const char *key = luaL_checkstring(L, 2);
	struct lua_module *module;
	int err;

	/* module queries are always run with a read lock */
	list_for_each_entry_srcu(module, &lsm_modules, list,
				srcu_read_lock_held(&modules_ss)) {
		if (strcmp(module->name, key) != 0)
			continue;

		err = lua_module_load(L, module);
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
	struct lua_module *module;

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


static atomic_t vm_nalloc = ATOMIC_INIT(0);
static atomic_t vm_nfree = ATOMIC_INIT(0);
static atomic_t vm_inuse = ATOMIC_INIT(0);
static atomic_t mem_nalloc = ATOMIC_INIT(0);
static atomic_t mem_nrealloc = ATOMIC_INIT(0);
static atomic_t mem_nfree = ATOMIC_INIT(0);

static void *lvm_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	struct lvm_userdata *args = ud;

	(void)osize;
	(void)args;

	if (nsize == 0) {
		atomic_inc(&mem_nfree);
		kfree(ptr);
		return NULL;
	} else {
		if (ptr)
			atomic_inc(&mem_nrealloc);
		else
			atomic_inc(&mem_nalloc);

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
	lua_pushcfunction(L, lua_module_index);	/* TODO: pass it as args */
	lua_setfield(L, -2, "__index");		/* metatable.__index = func */
	/* setmetatable(_MODULES, metatable) */
	lua_setmetatable(L, -2);
	lua_setfield(L, LUA_REGISTRYINDEX, "_MODULES");

	/* return true */
	lua_pushboolean(L, 1);
	return 1;
}

static lua_State *lua_state_alloc(struct lvm_userdata *args)
{
	lua_State *L;
	int status;

	L = lua_newstate(lvm_alloc, args);
	if (L == NULL)
		return ERR_PTR(-ENOMEM);

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
		return ERR_PTR(status);
	}

	atomic_inc(&vm_nalloc);
	atomic_inc(&vm_inuse);
	return L;
}

static void lua_state_free(lua_State *L)
{
	if (L) {
		atomic_inc(&vm_nfree);
		atomic_dec(&vm_inuse);
		lua_close(L);
	}
}

/********************************** module **********************************/

static int lvm_writer(lua_State *L, const void *b, size_t size, void *B)
{
	(void)L;
	luaL_addlstring((luaL_Buffer *)B, (const char *)b, size);
	return 0;
}

static void lua_module_free(struct lua_module *module)
{
	kfree(module->chunk);
	kfree(module->name);
	kfree(module->author);
	kfree(module->description);
	kfree(module->license);
	kfree(module);
}

int lua_module_register(const char *code, size_t len)
{
	struct lua_module *module, *m;
	lua_State *L;
	luaL_Buffer B;
	const char *chunk;
	size_t chunk_len;
	int found = 0;
	int i;
	int status;
	int err;

	L = lua_state_alloc(NULL);
	if (IS_ERR(L))
		return PTR_ERR(L);

	err = luaL_loadbuffer_wrap(L, code, len, "<lua-lsm>");
	if (err)
		goto err_free_lua;

	/* dump function */
	luaL_checktype(L, -1, LUA_TFUNCTION);
	luaL_buffinit(L, &B);
	status = lua_dump(L, lvm_writer, &B);
	if (status != 0) {
		__log_err("dump: unable to dump the function\n");
		err = -EFAULT;
		goto err_free_lua;
	}
	luaL_pushresult(&B);
	chunk = lua_tolstring(L, -1, &chunk_len);
	__log_info("compiled, source_len = %d, chunk_len = %d\n",
		(int)len, (int)chunk_len);

	/* TODO: run in sandbox, record the `require` lua modules */
	lua_pushcfunction(L, lua_traceback);
	lua_pushvalue(L, -3);
	/* stack: [func, chunk, traceback, func] */
	err = lua_pcall_wrap(L, 0, LUA_MULTRET, -2);
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
		const char *key, *s;

		if (!lua_isstring(L, -2)) {
			__log_err("module table index must be a string\n");
			lua_pop(L, 1);
			continue;
		}

		key = lua_tostring(L, -2);
		if (strcmp(key, "name") == 0) {
			if (lua_isstring(L, -1)) {
				s = lua_tostring(L, -1);
				module->name = kstrdup(s, GFP_KERNEL);
			} else {
				__log_err("'%s' value must be a string\n", key);
			}
		} else if (strcmp(key, "author") == 0) {
			if (lua_isstring(L, -1)) {
				s = lua_tostring(L, -1);
				module->author = kstrdup(s, GFP_KERNEL);
			} else {
				__log_err("'%s' value must be a string\n", key);
			}
		} else if (strcmp(key, "description") == 0) {
			if (lua_isstring(L, -1)) {
				s = lua_tostring(L, -1);
				module->description = kstrdup(s, GFP_KERNEL);
			} else {
				__log_err("'%s' value must be a string\n", key);
			}
		} else if (strcmp(key, "license") == 0) {
			if (lua_isstring(L, -1)) {
				s = lua_tostring(L, -1);
				module->license = kstrdup(s, GFP_KERNEL);
			} else {
				__log_err("'%s' value must be a string\n", key);
			}
		} else if (strcmp(key, "version") == 0) {
			if (lua_isnumber(L, -1)) {
				module->version = (int)lua_tointeger(L, -1);
			} else {
				__log_err("'%s' value must be a integer\n", key);
			}
		} else {
			for (i = 0; lua_lsm_hook_stats[i].name; i++) {
				if (strcmp(lua_lsm_hook_stats[i].name, key) != 0)
					continue;

				if (!lua_isfunction(L, -1)) {
					__log_err("'%s' field must be a function\n", key);
					continue;
				}

				module->nhooks += 1;
				__BITMAP_SET(i, &module->hookfuncs);

				__log_info("hookfunc = %s\n", key);
				break;
			}

			if (lua_lsm_hook_stats[i].name == NULL)
				__log_warn("'%s' is unknown function\n", key);
		}

		/* removes 'value'; keeps 'key' for next iteration */
		lua_pop(L, 1);
	}

	err = -ENOMEM;
	if (module->name == NULL)
		goto err_free_module;

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

	lua_state_free(L);
	return 0;

err_free_module:
	lua_module_free(module);
err_free_lua:
	lua_state_free(L);

	return err;
}

static int lvm_remove_module(lua_State *L, struct lua_module *module)
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
	struct lua_module *module = arg;
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

static int tasks_lvm_remove_module(struct lua_module *module, int *nbusy)
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
static struct lua_module *work_ctx_remove_module;
static atomic_t work_ctx_remove_count;

static void softirq_lvm_remove_module(struct work_struct *work)
{
	struct lua_module *module = work_ctx_remove_module;
	int cpu = smp_processor_id();
	int err;

	WARN_ON(work_ctx_remove_module == NULL);
	/*
	 * Disable softirq to prevent triggered softirq or RCU from
	 * changing the Lua VM environment.
	 */
	local_bh_disable();
	err = lvm_remove_module(per_cpu(irq_lvms, cpu), module);
	if (!err) {
		atomic_inc(&work_ctx_remove_count);
		__log_info("<%s>: err = [ OK ] \t<softirq-%d>, count = %d\n",
			module->name, cpu, atomic_read(&work_ctx_remove_count));
	}
	local_bh_enable();
}

int lua_module_unregister(const char *name)
{
	struct lua_module *module;
	struct lua_module_shdict *shdict, *tmp;
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
		lua_module_free(module);
		err = 0;
	} else {
		module->state = LMS_STATE_ZOMBIE;
		err = -EBUSY;
	}
	mutex_unlock(&modules_mutex);

	pr_info("Unregistered module <%s> from %d/%d Lua VMs, vm_inuse = %d\n",
		name, count, nloaded, atomic_read(&vm_inuse));

	return err;
}

/*****************************************************************************/

int modules_show(struct seq_file *m, void *v)
{
	struct lua_module *module;
	int idx;

	seq_printf(m, "modules for lua-lsm\n");
	seq_printf(m, "%-12s %-10s %6s %6s  %-48s\n",
		"name", "license", "size", "nhooks", "author");
	seq_printf(m, "%s\n", TABLINE);

	idx = srcu_read_lock(&modules_ss);
	list_for_each_entry_srcu(module, &lsm_modules, list,
				srcu_read_lock_held(&modules_ss)) {
		seq_printf(m, "%-12s %-10s %6zu %6d  %-48s\n",
			module->name, module->license, module->chunk_len,
			module->nhooks, module->author);
	}
	srcu_read_unlock(&modules_ss, idx);
	return 0;
}


#ifdef CONFIG_SECURITY_LUA_LSM_STATISTICS

int lua_lsm_status_show(struct seq_file *m, void *v)
{
	struct task_struct *g, *p;
	unsigned int cpu;
	int nalloc, nfree;
	int inuse, total, minimum, maximum, avg;
	int nbytes;
	lua_State *L;

	nalloc = atomic_read(&vm_nalloc);
	nfree = atomic_read(&vm_nfree);
	seq_printf(m, "Lua VM:\n");
	seq_printf(m, "  Alloc:      alloc %d, free %d, inuse %d\n",
		nalloc, nfree, nalloc - nfree);
	seq_printf(m, "  Mem alloc:  alloc %d, realloc %d, free %d\n",
		atomic_read(&mem_nalloc), atomic_read(&mem_nrealloc),
		atomic_read(&mem_nfree));

	inuse = 0;
	total = 0;
	minimum = INT_MAX;
	maximum = 0;
	mutex_lock(&modules_mutex);
	read_lock(&tasklist_lock);
	for_each_process_thread(g, p) {
		L = lua_lsm_task(p)->L;
		nbytes = lua_gc(L, LUA_GCCOUNT, 0) * 1024 + lua_gc(L, LUA_GCCOUNTB, 0);
		inuse++;
		total += nbytes;
		minimum = min(minimum, nbytes);
		maximum = max(maximum, nbytes);
	}
	read_unlock(&tasklist_lock);

	cpus_read_lock();
	for_each_possible_cpu(cpu) {
		L = lua_lsm_task(idle_task(cpu))->L;
		nbytes = lua_gc(L, LUA_GCCOUNT, 0) * 1024 + lua_gc(L, LUA_GCCOUNTB, 0);
		inuse++;
		total += nbytes;
		minimum = min(minimum, nbytes);
		maximum = max(maximum, nbytes);
	}
	cpus_read_unlock();
	mutex_unlock(&modules_mutex);

	avg = inuse ? total / inuse : 0;
	seq_printf(m, "  Mem usage:  total %d, min %d, max %d, inuse %d, average %d\n",
		total, minimum, maximum, inuse, avg);

	kvcache_status(&nalloc, &nfree);
	seq_printf(m, "kvcache:\n");
	seq_printf(m, "  Alloc:      alloc %d, free %d, inuse %d\n",
		nalloc, nfree, nalloc - nfree);

	return 0;
}

int lsmhook_stat_show(struct seq_file *m, void *v)
{
	struct lua_lsm_hook_stat *stat;
	int i = 1;

	seq_printf(m, "stats for lua-lsm (ns)\n");
	seq_printf(m, "%3s %-28s %6s %8s %15s %10s %12s\n",
		"num", "name", "nhooks", "count", "total", "average", "maxtime");
	seq_printf(m, "%s\n", TABLINE);

	for (stat = lua_lsm_hook_stats; stat->name; stat++) {
		int n = atomic_read(&stat->count);
		s64 total = atomic64_read(&stat->time);
		s64 maxtime = atomic64_read(&stat->maxtime);
		seq_printf(m, "%3d %-28s %6d %8d %15llu %10llu %12llu\n",
			i++, stat->name, atomic_read(&stat->nhooks),
			n, total, n ? total / n : 0, maxtime);
	}
	return 0;
}

#endif

/*********************************** main ***********************************/

int lua_task_blob_init(struct task_struct *task)
{
	struct lua_lsm_task *llt = lua_lsm_task(task);
	lua_State *L;

	kvcache_dict_init(&llt->dict);

	L = lua_state_alloc(NULL);
	if (IS_ERR(L))
		return PTR_ERR(L);

	llt->L = L;
	refcount_init(&llt->refcount, 0);
	return 0;
}

void lua_task_blob_free(struct task_struct *task)
{
	struct lua_lsm_task *llt = lua_lsm_task(task);
	lua_modules_free(task, llt->L);
	lua_state_free(llt->L);
	llt->L = NULL;
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

int lua_enabled __ro_after_init = 1;

static const struct lsm_id lua_lsmid = {
	.name = "lua",
	.id = LSM_ID_LUA,
};

static int __init lua_lsm_init(void)
{
	lua_State *L;
	int cpu;
	int err;

	err = lua_task_blob_init(current);
	if (err)
		return err;

	for_each_possible_cpu(cpu) {
		L = lua_state_alloc(&irq_lvms_ud);
		if (IS_ERR(L))
			return PTR_ERR(L);
		per_cpu(irq_lvms, cpu) = L;
	}

	security_add_hooks(lua_lsm_hooks, ARRAY_SIZE(lua_lsm_hooks), &lua_lsmid);

	/* Report that Lua-LSM successfully initialized */
	lua_lsm_initialized = 1;

	pr_info("Lua based LSM initialized\n");
	return 0;
}

DEFINE_LSM(lua) = {
	.name = "lua",
	.enabled = &lua_enabled,
	.blobs = &lua_lsm_blob_sizes,
	.init = lua_lsm_init,
};
