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

struct list_head lsm_modules = LIST_HEAD_INIT(lsm_modules);
static DEFINE_MUTEX(modules_mutex);
DEFINE_SRCU(modules_ss);

static void lua_lsm_module_finalize_workfn(struct work_struct *work);
static DECLARE_WORK(lua_lsm_module_finalize_work,
		    lua_lsm_module_finalize_workfn);

static LIST_HEAD(orphan_modules);

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

/* Allocate a module object with its embedded state initialized. */
static struct lua_lsm_module *module_create(void)
{
	struct lua_lsm_module *module;

	module = kzalloc(sizeof(*module), GFP_KERNEL);
	if (!module)
		return NULL;

	__BITMAP_ZERO(&module->hookfuncs);
	atomic_set(&module->loaded_vm_count, 0);
	INIT_LIST_HEAD(&module->orphan);

	INIT_LIST_HEAD(&module->shdicts);
	spin_lock_init(&module->shdict_lock);
	atomic_set(&module->shdict_count, 0);

	INIT_LIST_HEAD(&module->kvnodes);
	spin_lock_init(&module->kvnodes_lock);
	atomic_set(&module->kvnodes_count, 0);
	return module;
}

/* Result-table metadata fields copied straight into struct lua_lsm_module. */
static const struct {
	const char *field;
	int type;
	int offset;
} module_fields[] = {
	{ "name", LUA_TSTRING, offsetof(struct lua_lsm_module, name) },
	{ "author", LUA_TSTRING, offsetof(struct lua_lsm_module, author) },
	{ "description", LUA_TSTRING,
	  offsetof(struct lua_lsm_module, description) },
	{ "license", LUA_TSTRING, offsetof(struct lua_lsm_module, license) },
	{ "version", LUA_TNUMBER, offsetof(struct lua_lsm_module, version) },
	{ NULL }
};

/*
 * Walk the module's result table: fill the metadata fields, count the
 * hook functions, and set their bits in the hookfuncs bitmap.
 *
 * in:  [..., _M] (the result table on top)
 * out: stack unchanged; module fields and hookfuncs filled
 * returns 0, or -EOPNOTSUPP for a hook this build does not expose
 * (on error the caller discards the loader VM, so no stack cleanup)
 */
static int module_table_extract(lua_State *L, struct lua_lsm_module *module)
{
	const char *key, *s;
	int i;

	lua_pushnil(L);
	/* removes 'value' on every path; keeps 'key' for the next iteration */
	while (lua_next(L, -2) != 0) {
		if (!lua_isstring(L, -2)) {
			__log_err("module table index must be a string\n");
			goto pop_value;
		}
		key = lua_tostring(L, -2);

		for (i = 0; module_fields[i].field; i++) {
			if (strcmp(key, module_fields[i].field) == 0)
				break;
		}
		if (module_fields[i].field) {
			void *p = (char *)module + module_fields[i].offset;

			if (lua_type(L, -1) == module_fields[i].type) {
				switch (lua_type(L, -1)) {
				case LUA_TSTRING:
					s = lua_tostring(L, -1);
					*(const char **)p = kstrdup(s, GFP_KERNEL);
					break;
				case LUA_TNUMBER:
					*(int *)p = (int)lua_tointeger(L, -1);
					break;
				}
			} else {
				__log_err("field '%s' must be a %s\n", key,
					  lua_typename(L, module_fields[i].type));
			}
			goto pop_value;
		}

		/* Not a metadata field: must be a hook function. */
		for (i = 0; lua_lsm_hook_stats[i].name; i++) {
			if (strcmp(lua_lsm_hook_stats[i].name, key) != 0)
				continue;

			if (!lua_lsm_hook_supported(i)) {
				__log_err("hook '%s' is not supported by Lua-LSM\n",
					  key);
				return -EOPNOTSUPP;
			}
			if (!lua_isfunction(L, -1)) {
				__log_err("field '%s' must be a function\n", key);
				goto pop_value;
			}

			module->nhooks += 1;
			__BITMAP_SET(i, &module->hookfuncs);
			__log_info("hookfunc = %s\n", key);
			goto pop_value;
		}
		__log_warn("field '%s' is unknown\n", key);
pop_value:
		lua_pop(L, 1);
	}
	return 0;
}

/*
 * Recompile the source under the module's own name (so runtime errors
 * carry it) and store the bytecode dump in module->chunk.
 *
 * in:  [..., _M]; source, len, and module->name
 * out: chunk and chunk_len set; leftover compile stack is left in
 * place, the caller discards the loader VM either way
 * returns 0 or negative errno
 */
static int module_compile_chunk(lua_State *L, const char *code, size_t len,
				struct lua_lsm_module *module)
{
	luaL_Buffer B;
	const char *chunk;
	size_t chunk_len;
	int func;
	int err;

	err = luaL_loadbuffer_wrap(L, code, len, module->name);
	if (err)
		return err;

	/* stack: [..., _M, func] */
	func = lua_gettop(L);
	luaL_checktype(L, func, LUA_TFUNCTION);

	luaL_buffinit(L, &B);
	if (lua_dump(L, lvm_writer, &B) != 0) {
		__log_err("dump: unable to dump the function\n");
		return -EFAULT;
	}
	luaL_pushresult(&B);
	/* stack: [..., _M, func, chunk] */
	chunk = lua_tolstring(L, func + 1, &chunk_len);
	__log_info("[%s] compiled, source_len = %d, chunk_len = %d\n",
		   module->name, (int)len, (int)chunk_len);

	module->chunk = kmalloc(chunk_len, GFP_KERNEL);
	if (!module->chunk)
		return -ENOMEM;
	memcpy(module->chunk, chunk, chunk_len);
	module->chunk_len = chunk_len;
	return 0;
}

/*
 * Make the module globally visible.  Caller holds modules_mutex and
 * has verified the name is unused.
 */
static void module_publish(struct lua_lsm_module *module)
{
	int i;

	for (i = 0; lua_lsm_hook_stats[i].name; i++) {
		if (__BITMAP_ISSET(i, &module->hookfuncs))
			atomic_inc(&lua_lsm_hook_stats[i].nhooks);
	}

	WRITE_ONCE(module->state, LMS_STATE_LIVE);
	list_add_tail_rcu(&module->list, &lsm_modules);
	/*
	 * Objects can outlive the module that last touched them, so
	 * free-hook cleanup must stay enabled forever after the first
	 * registration -- even while no module is live.
	 */
	static_branch_enable(&lua_lsm_modules_ever_registered);
	static_branch_inc(&lua_lsm_modules_live);
}

int lua_lsm_module_register(const char *code, size_t len)
{
	struct lua_lsm_module *module, *m;
	struct lvm_state loader;
	lua_State *L;
	bool exists;
	int err;

	memset(&loader, 0, sizeof(loader));
	err = lua_state_alloc(&loader);
	if (err)
		return err;
	L = loader.L;

	/* Run the chunk in a private VM; it must return the module table. */
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

	module = module_create();
	if (!module) {
		err = -ENOMEM;
		goto err_free_lua;
	}

	err = module_table_extract(L, module);
	if (err)
		goto err_free_module;

	err = -ENOMEM;
	if (!module->name)
		goto err_free_module;

	err = module_compile_chunk(L, code, len, module);
	if (err)
		goto err_free_module;

	exists = false;
	mutex_lock(&modules_mutex);
	list_for_each_entry(m, &lsm_modules, list) {
		if (strcmp(m->name, module->name) == 0) {
			exists = true;
			break;
		}
	}
	if (exists)
		err = -EEXIST;
	else
		module_publish(module);
	mutex_unlock(&modules_mutex);
	if (exists) {
		__log_err("module <%s> registered already\n", module->name);
		goto err_free_module;
	}

	pr_info("module <%s> registered with %d filters\n",
		module->name, module->nhooks);

	lua_state_free(&loader);
	return 0;

err_free_module:
	lua_lsm_module_free(module);
err_free_lua:
	lua_state_free(&loader);

	return err;
}

/* The per-CPU work item carries its own argument: the module to drop. */
struct irq_lvm_drop_ctx {
	struct work_struct work;
	struct lua_lsm_module *module;
};

static DEFINE_PER_CPU(struct irq_lvm_drop_ctx, irq_lvm_drop_ctx);

/*
 * Drop the module from cpu's irq-context VM.  Softirqs are disabled so
 * that a softirq or RCU callback cannot re-enter the same VM while it
 * is being changed.
 */
static void irq_vm_drop_module(int cpu, struct lua_lsm_module *module)
{
	local_bh_disable();
	lvm_drop_module(lvm_irq_state(cpu), module);
	local_bh_enable();
}

static void irq_lvm_drop_workfn(struct work_struct *work)
{
	struct irq_lvm_drop_ctx *ctx =
		container_of(work, struct irq_lvm_drop_ctx, work);

	irq_vm_drop_module(smp_processor_id(), ctx->module);
}

/*
 * Drop the module from every irq-context VM.  Must be called with
 * modules_mutex held: the work items read ctx->module, and this
 * function flushes them all before returning, so the pointer stays
 * valid for the whole round.
 */
static void irq_vms_drop_module(struct lua_lsm_module *module)
{
	struct irq_lvm_drop_ctx *ctx;
	int cpu;

	lockdep_assert_held(&modules_mutex);

	cpus_read_lock();
	for_each_possible_cpu(cpu) {
		ctx = per_cpu_ptr(&irq_lvm_drop_ctx, cpu);
		ctx->module = module;
		INIT_WORK(&ctx->work, irq_lvm_drop_workfn);
		if (!cpu_online(cpu)) {
			irq_vm_drop_module(cpu, module);
			continue;
		}
		WARN_ON_ONCE(!schedule_work_on(cpu, &ctx->work));
	}
	for_each_possible_cpu(cpu) {
		if (cpu_online(cpu))
			flush_work(&per_cpu_ptr(&irq_lvm_drop_ctx, cpu)->work);
	}
	cpus_read_unlock();
}

static bool lua_lsm_module_ready_to_finalize(struct lua_lsm_module *module)
{
	return READ_ONCE(module->state) == LMS_STATE_GOING &&
	       atomic_read(&module->loaded_vm_count) == 0;
}

void lua_lsm_module_put_loaded_vm(struct lua_lsm_module *module)
{
	int loaded_vms = atomic_dec_return(&module->loaded_vm_count);

	WARN_ON_ONCE(loaded_vms < 0);
	if (loaded_vms == 0)
		schedule_work(&lua_lsm_module_finalize_work);
}

static void lua_lsm_module_mark_shdicts_dead(struct lua_lsm_module *module)
{
	struct lua_lsm_module_shdict *shdict;
	unsigned long flags;

	spin_lock_irqsave(&module->shdict_lock, flags);
	list_for_each_entry(shdict, &module->shdicts, list)
		WRITE_ONCE(shdict->dead, true);
	spin_unlock_irqrestore(&module->shdict_lock, flags);
}

static void lua_lsm_module_release_shdicts(struct lua_lsm_module *module)
{
	LIST_HEAD(released);
	struct lua_lsm_module_shdict *shdict, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&module->shdict_lock, flags);
	list_for_each_entry_safe(shdict, tmp, &module->shdicts, list) {
		list_move_tail(&shdict->list, &released);
		atomic_dec(&module->shdict_count);
	}
	spin_unlock_irqrestore(&module->shdict_lock, flags);

	list_for_each_entry_safe(shdict, tmp, &released, list) {
		list_del_init(&shdict->list);
		lua_lsm_shdict_put(shdict);
	}
}

static void lua_lsm_module_unregister_hooks(struct lua_lsm_module *module)
{
	int i;

	for (i = 0; lua_lsm_hook_stats[i].name; i++) {
		if (__BITMAP_ISSET(i, &module->hookfuncs))
			atomic_dec(&lua_lsm_hook_stats[i].nhooks);
	}
}

static void lua_lsm_module_release_srcu(struct rcu_head *rcu)
{
	struct lua_lsm_module *module;

	module = container_of(rcu, struct lua_lsm_module, rcu);

	mutex_lock(&modules_mutex);
	if (atomic_read(&module->loaded_vm_count) != 0) {
		INIT_LIST_HEAD(&module->orphan);
		list_add_tail(&module->orphan, &orphan_modules);
		mutex_unlock(&modules_mutex);
		return;
	}

	kvcache_module_nodes_gc(module);
	mutex_unlock(&modules_mutex);

	lua_lsm_module_free(module);
}

/*
 * Remove the module from all global lookup paths.  The object itself stays
 * alive until pre-existing modules_ss readers have left their critical section.
 */
static void lua_lsm_module_detach_locked(struct lua_lsm_module *module)
{
	lockdep_assert_held(&modules_mutex);

	WARN_ON_ONCE(READ_ONCE(module->state) != LMS_STATE_LIVE);

	WRITE_ONCE(module->state, LMS_STATE_GOING);
	static_branch_dec(&lua_lsm_modules_live);
	/* Order the state store before the loaded-VM count read below. */
	smp_mb__after_atomic();
	lua_lsm_module_unregister_hooks(module);
	list_del_rcu(&module->list);
}

static void lua_lsm_module_finalize_locked(struct lua_lsm_module *module)
{
	lockdep_assert_held(&modules_mutex);

	WARN_ON_ONCE(READ_ONCE(module->state) != LMS_STATE_GOING);

	list_del(&module->orphan);
	call_srcu(&modules_ss, &module->rcu,
		  lua_lsm_module_release_srcu);
}

static void lua_lsm_module_finalize_workfn(struct work_struct *work)
{
	struct lua_lsm_module *module, *tmp;

	mutex_lock(&modules_mutex);
	list_for_each_entry_safe(module, tmp, &orphan_modules, orphan) {
		if (lua_lsm_module_ready_to_finalize(module))
			lua_lsm_module_finalize_locked(module);
	}
	mutex_unlock(&modules_mutex);
}

int lua_lsm_module_unregister(const char *name)
{
	struct lua_lsm_module *module;
	int found = 0;
	int remaining;

	mutex_lock(&modules_mutex);
	list_for_each_entry(module, &lsm_modules, list) {
		if (strcmp(module->name, name) == 0) {
			found = 1;
			break;
		}
	}

	if (!found) {
		mutex_unlock(&modules_mutex);
		return -ENOENT;
	}

	if (READ_ONCE(module->state) != LMS_STATE_LIVE) {
		mutex_unlock(&modules_mutex);
		return -EINVAL;
	}

	pr_info("Prepare to unregister module <%s> ...\n", name);

	lua_lsm_module_detach_locked(module);

	/*
	 * The module is no longer globally visible.  Drop resources owned by
	 * its active registration; Lua userdata keep their own references.
	 */
	lua_lsm_module_mark_shdicts_dead(module);
	lua_lsm_module_release_shdicts(module);
	list_add_tail(&module->orphan, &orphan_modules);

	/*
	 * At this time, LuaVM may still be released asynchronously,
	 * so loaded_vm_count may change concurrently.
	 */
	remaining = atomic_read(&module->loaded_vm_count);
	if (remaining > 0) {
		irq_vms_drop_module(module);

		__log_info("Unregister module <%s> from pcpu VMs, remaining = %d\n",
			   name, atomic_read(&module->loaded_vm_count));
	}

	remaining = atomic_read(&module->loaded_vm_count);
	if (remaining == 0)
		lua_lsm_module_finalize_locked(module);

	mutex_unlock(&modules_mutex);

	pr_info("Unregistered module <%s>: pending_vms = %d, vm_nusage = %d\n",
		name, remaining, lvm_stats_vm_nusage());

	return 0;
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
			   module->nhooks, atomic_read(&module->loaded_vm_count),
			   atomic_read(&module->shdict_count),
			   atomic_read(&module->kvnodes_count), module->author);
	}
	srcu_read_unlock(&modules_ss, idx);
	return 0;
}
