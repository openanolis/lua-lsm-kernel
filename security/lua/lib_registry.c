// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * lua-lsm per-library API registry.
 *
 * Copyright (C) 2026 The Alibaba Cloud Linux Authors.
 */

#define pr_fmt(fmt)	"lua-lsm: " fmt

#include <linux/audit.h>
#include <linux/cpu.h>
#include <linux/cpuhotplug.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/lua.h>
#include <linux/lauxlib.h>
#include <linux/lualib.h>
#include <linux/lua_lsm_api.h>
#include <uapi/linux/audit.h>

#include "auxlib.h"
#include "lsm.h"
#include "refcount.h"

enum lua_api_lib_audit_reason {
	LUA_API_LIB_AUDIT_NONE,
	LUA_API_LIB_AUDIT_NOT_READY,
	LUA_API_LIB_AUDIT_UNSIGNED,
	LUA_API_LIB_AUDIT_DUPLICATE,
	LUA_API_LIB_AUDIT_RESERVED_NAME,
	LUA_API_LIB_AUDIT_PIN_FAILED,
	LUA_API_LIB_AUDIT_TEXT_OWNER,
	LUA_API_LIB_AUDIT_SCRATCH,
	LUA_API_LIB_AUDIT_REPLAY,
	LUA_API_LIB_AUDIT_RESOURCE,
};

static const char *lua_api_lib_audit_reason_str(enum lua_api_lib_audit_reason r)
{
	switch (r) {
	case LUA_API_LIB_AUDIT_NOT_READY:	return "not-ready";
	case LUA_API_LIB_AUDIT_UNSIGNED:	return "unsigned";
	case LUA_API_LIB_AUDIT_DUPLICATE:	return "duplicate";
	case LUA_API_LIB_AUDIT_RESERVED_NAME:	return "reserved-name";
	case LUA_API_LIB_AUDIT_PIN_FAILED:	return "pin-failed";
	case LUA_API_LIB_AUDIT_TEXT_OWNER:	return "text-owner";
	case LUA_API_LIB_AUDIT_SCRATCH:		return "scratch";
	case LUA_API_LIB_AUDIT_REPLAY:		return "replay";
	case LUA_API_LIB_AUDIT_RESOURCE:	return "resource";
	default:				return "unknown";
	}
}

/*
 * Writers serialise on modules_mutex (shared with the policy-module
 * registry in lsm.c); readers walk under srcu_read_lock(&modules_ss).
 */
static LIST_HEAD(lua_api_libs);

/* Cleared until lua_lsm_init() finishes publishing the built-in seeds. */
bool lua_api_lib_registry_ready;

/* Bumped under modules_mutex on publish; stale pools are discarded. */
atomic_t lua_api_lib_generation = ATOMIC_INIT(0);

static int lua_api_lib_validate_common(const struct lua_api_lib *desc)
{
	size_t namelen;

	if (!desc)
		return -EINVAL;
	if (!desc->name)
		return -EINVAL;

	namelen = strnlen(desc->name, LUA_API_LIB_NAME_MAX);
	if (namelen == 0 || namelen >= LUA_API_LIB_NAME_MAX)
		return -EINVAL;

	if (desc->abi_version != LUA_API_LIB_ABI_VERSION)
		return -EINVAL;

	return 0;
}

static int lua_api_lib_validate_shared(const struct lua_api_lib *desc)
{
	int err = lua_api_lib_validate_common(desc);

	if (err)
		return err;

	if (!desc->funcs)
		return -EINVAL;
	if (desc->reserved_open)
		return -EINVAL;

	return 0;
}

/* Built-in descriptors are part of vmlinux; only modules need this gate. */
static int lua_api_lib_gate_signed(const struct lua_api_lib *desc)
{
	if (!IS_ENABLED(CONFIG_LUA_LSM_REQUIRE_SIGNED_API))
		return 0;
	if (!desc->owner)
		return 0;
	if (!module_sig_ok(desc->owner))
		return -EKEYREJECTED;
	return 0;
}

static bool lua_api_lib_ptr_in_owner_text(const struct lua_api_lib *desc,
					  const void *ptr)
{
	void *entry;
	unsigned long addr;

	if (!ptr)
		return true;
	if (!desc->owner)
		return true;

	entry = dereference_module_function_descriptor(desc->owner, (void *)ptr);
	addr = (unsigned long)entry;

	/* Lua closures can outlive module init text. */
	return within_module_mem_type(addr, desc->owner, MOD_TEXT);
}

static int lua_api_lib_validate_text_owner(const struct lua_api_lib *desc)
{
	unsigned int i;

	for (i = 0; desc->funcs[i].name; i++) {
		if (!desc->funcs[i].func)
			return -EINVAL;
		if (!lua_api_lib_ptr_in_owner_text(desc, desc->funcs[i].func))
			return -EINVAL;
	}

	if (!lua_api_lib_ptr_in_owner_text(desc, desc->init_table))
		return -EINVAL;

	return 0;
}

/* Shape validation runs before audit to avoid logging malformed descriptors. */
static void lua_api_lib_audit(const struct lua_api_lib *desc, int result,
			      enum lua_api_lib_audit_reason reason)
{
	struct audit_buffer *ab;
	const char *sig_ok;
	unsigned int nfuncs = 0;

	if (!audit_enabled)
		return;

	ab = audit_log_start(audit_context(), GFP_KERNEL, AUDIT_LUA_LSM_API);
	if (!ab)
		return;

	if (desc->owner)
		sig_ok = module_sig_ok(desc->owner) ? "1" : "0";
	else
		sig_ok = "builtin";

	if (desc->funcs) {
		while (desc->funcs[nfuncs].name)
			nfuncs++;
	}

	audit_log_format(ab, "op=lua_api_lib_register result=%s",
			 result ? "denied" : "success");
	if (result)
		audit_log_format(ab, " reason=%s",
				 lua_api_lib_audit_reason_str(reason));
	audit_log_format(ab, " name=");
	audit_log_untrustedstring(ab, desc->name);
	audit_log_format(ab, " owner=%s sig_ok=%s funcs=%u res=%d",
			 desc->owner ? desc->owner->name : "(builtin)",
			 sig_ok, nfuncs, result);
	audit_log_end(ab);
}

static bool lua_api_lib_name_exists_locked(const char *name)
{
	struct lua_api_lib *cur;

	lockdep_assert_held(&modules_mutex);

	list_for_each_entry(cur, &lua_api_libs, list) {
		if (!strcmp(cur->name, name))
			return true;
	}
	return false;
}

static bool lua_api_lib_name_reserved(const char *name)
{
	static const char * const reserved[] = {
		"_G",
		LUA_COLIBNAME,
		LUA_TABLIBNAME,
		LUA_STRLIBNAME,
		LUA_DBLIBNAME,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(reserved); i++) {
		if (!strcmp(name, reserved[i]))
			return true;
	}

	return false;
}

/* Stack depth is restored on every exit, including init_table failures. */
static int lib_install_funcs(lua_State *L, struct lua_api_lib *desc)
{
	int original_top = lua_gettop(L);
	int loaded_idx, libtab_idx;
	int nfuncs = 0;
	int err = 0;

	luaL_findtable(L, LUA_REGISTRYINDEX, "_LOADED", 1);
	loaded_idx = lua_gettop(L);

	lua_getfield(L, loaded_idx, desc->name);
	if (lua_toboolean(L, -1))
		goto out;
	lua_pop(L, 1);

	while (desc->funcs[nfuncs].name)
		nfuncs++;

	lua_createtable(L, 0, nfuncs);
	libtab_idx = lua_gettop(L);

	luaL_register(L, NULL, desc->funcs);
	lua_settop(L, libtab_idx);

	if (desc->init_table) {
		err = desc->init_table(L);
		/* Normalize init_table errors to the public contract. */
		if (err > 0 || (err < 0 && err != -ENOMEM))
			err = -EPROTO;
		if (err < 0)
			goto out;
		lua_settop(L, libtab_idx);
	}

	lua_pushvalue(L, libtab_idx);
	lua_setfield(L, loaded_idx, desc->name);

out:
	lua_settop(L, original_top);
	return err;
}

struct lib_protected_ctx {
	struct lua_api_lib *desc;
	int err;
};

static int lib_install_trampoline(lua_State *L)
{
	struct lib_protected_ctx *ctx = lua_touserdata(L, -1);

	lua_pop(L, 1);
	ctx->err = lib_install_funcs(L, ctx->desc);
	return 0;
}

static int lib_install_protected(lua_State *L, struct lua_api_lib *desc)
{
	struct lib_protected_ctx ctx = {
		.desc = desc,
		.err = 0,
	};
	int original_top = lua_gettop(L);
	int rc;

	lua_pushcfunction(L, lib_install_trampoline);
	lua_pushlightuserdata(L, &ctx);
	rc = lua_pcall_wrap(L, 1, 0, 0);
	lua_settop(L, original_top);

	if (rc == -ENOMEM)
		return -ENOMEM;
	if (rc < 0)
		return -EPROTO;
	return ctx.err;
}

/*
 * Called from lvm_pmain() while building a fresh VM.  Snapshot the
 * generation BEFORE the walk so a concurrent publish only makes this
 * VM look stale to lvm_pool_get(); it never appears newer than the
 * descriptors actually installed.
 */
int lualibs_openall_dynamic(lua_State *L)
{
	struct lua_api_lib *desc;
	struct lvm_state *lvm;
	unsigned int gen_pre;
	int err = 0;
	int idx;

	gen_pre = (unsigned int)atomic_read(&lua_api_lib_generation);

	idx = srcu_read_lock(&modules_ss);
	list_for_each_entry_srcu(desc, &lua_api_libs, list,
				 srcu_read_lock_held(&modules_ss)) {
		err = lib_install_protected(L, desc);
		if (err)
			break;
	}
	srcu_read_unlock(&modules_ss, idx);

	if (err)
		return err;

	lvm = lvm_state_from_lua_state(L);
	if (lvm)
		WRITE_ONCE(lvm->generation, gen_pre);

	return 0;
}

/*
 * Replay log entries are sized nr_cpu_ids and indexed by cpu id.  The
 * outer cpus_read_lock() pins the online set across forward swap and
 * rollback, so irq_installed[] doubles as the swap-back set.
 */
struct lib_replay_log {
	struct lvm_state **irq_old;
	struct lvm_state **irq_new;
	bool *irq_installed;
	struct work_struct __percpu *swap_works;
	struct lvm_state *current_old;
	struct lvm_state *current_new;
	bool current_swapped;
};

static int lib_replay_log_init(struct lib_replay_log *log)
{
	log->irq_old = kvcalloc(nr_cpu_ids, sizeof(*log->irq_old),
				GFP_KERNEL);
	if (!log->irq_old)
		return -ENOMEM;
	log->irq_new = kvcalloc(nr_cpu_ids, sizeof(*log->irq_new),
				GFP_KERNEL);
	if (!log->irq_new) {
		kvfree(log->irq_old);
		log->irq_old = NULL;
		return -ENOMEM;
	}
	log->irq_installed = kvcalloc(nr_cpu_ids, sizeof(*log->irq_installed),
				      GFP_KERNEL);
	if (!log->irq_installed) {
		kvfree(log->irq_new);
		kvfree(log->irq_old);
		log->irq_new = NULL;
		log->irq_old = NULL;
		return -ENOMEM;
	}
	log->swap_works = alloc_percpu(struct work_struct);
	if (!log->swap_works) {
		kvfree(log->irq_installed);
		kvfree(log->irq_new);
		kvfree(log->irq_old);
		log->irq_installed = NULL;
		log->irq_new = NULL;
		log->irq_old = NULL;
		return -ENOMEM;
	}
	log->current_old = NULL;
	log->current_new = NULL;
	log->current_swapped = false;
	return 0;
}

static void lib_replay_log_free(struct lib_replay_log *log)
{
	free_percpu(log->swap_works);
	kvfree(log->irq_installed);
	kvfree(log->irq_old);
	kvfree(log->irq_new);
	log->swap_works = NULL;
	log->irq_installed = NULL;
	log->irq_old = NULL;
	log->irq_new = NULL;
}

static void lua_api_lib_drain_pools(void)
{
	struct lvm_pool_cpu *pool;
	struct lvm_state *lvm, *next;
	unsigned long flags;
	int cpu;

	for_each_possible_cpu(cpu) {
		pool = &per_cpu(lvm_pools, cpu);
		raw_spin_lock_irqsave(&pool->lock, flags);
		lvm = pool->head;
		pool->head = NULL;
		pool->count = 0;
		raw_spin_unlock_irqrestore(&pool->lock, flags);

		while (lvm) {
			next = lvm->next;
			lvm_state_free_heap(lvm);
			lvm = next;
		}
	}
}

/*
 * Per-CPU swap workers take no arguments, so the active log is handed
 * over through this pointer.  modules_mutex serialises registrations,
 * so only one replay is in flight at a time.
 */
static struct lib_replay_log *work_ctx_log;

/*
 * Caller must hold cpus_read_lock().  Unlike schedule_on_each_cpu(),
 * schedule_work_on() + flush_work() do not retake it, so this nests
 * safely inside the registration hotplug-read section.
 */
static void lib_dispatch_per_cpu(struct lib_replay_log *log,
				 work_func_t func)
{
	int cpu;

	lockdep_assert_cpus_held();

	for_each_online_cpu(cpu) {
		struct work_struct *w = per_cpu_ptr(log->swap_works, cpu);

		INIT_WORK(w, func);
		schedule_work_on(cpu, w);
	}
	for_each_online_cpu(cpu)
		flush_work(per_cpu_ptr(log->swap_works, cpu));
}

static void swap_irq_lvm_work(struct work_struct *work)
{
	struct lib_replay_log *log = READ_ONCE(work_ctx_log);
	int cpu = smp_processor_id();
	struct lvm_state *old;

	if (WARN_ON(!log))
		return;
	if (!log->irq_new[cpu])
		return;

	/*
	 * Pair with softirq users of irq_lvms: after local_bh_disable()
	 * any in-flight softirq has finished, so the single-pointer swap
	 * is observed atomically.
	 */
	local_bh_disable();
	old = per_cpu(irq_lvms, cpu);
	per_cpu(irq_lvms, cpu) = log->irq_new[cpu];
	log->irq_old[cpu] = old;
	log->irq_installed[cpu] = true;
	local_bh_enable();
}

static void swap_back_irq_lvm_work(struct work_struct *work)
{
	struct lib_replay_log *log = READ_ONCE(work_ctx_log);
	int cpu = smp_processor_id();

	if (WARN_ON(!log))
		return;
	if (!log->irq_installed[cpu])
		return;
	if (WARN_ON(!log->irq_old[cpu]))
		return;

	local_bh_disable();
	per_cpu(irq_lvms, cpu) = log->irq_old[cpu];
	local_bh_enable();
}

static int lua_api_lib_replay(struct lua_api_lib *desc,
			      struct lib_replay_log *log)
{
	struct lua_lsm_task *llt;
	unsigned int target_gen;
	int cpu;
	int err;

	lockdep_assert_held(&modules_mutex);
	lockdep_assert_cpus_held();

	target_gen = (unsigned int)atomic_read(&lua_api_lib_generation) + 1;

	for_each_online_cpu(cpu) {
		struct lvm_state *new_vm = lvm_state_build_new();

		if (IS_ERR(new_vm))
			return PTR_ERR(new_vm);

		err = lib_install_protected(new_vm->L, desc);
		if (err) {
			lvm_state_free_heap(new_vm);
			return err;
		}
		WRITE_ONCE(new_vm->generation, target_gen);
		log->irq_new[cpu] = new_vm;
	}

	WRITE_ONCE(work_ctx_log, log);
	lib_dispatch_per_cpu(log, swap_irq_lvm_work);
	WRITE_ONCE(work_ctx_log, NULL);

	/*
	 * Build a replacement for current's task VM and swap atomically.
	 * If we cannot acquire it exclusively, fall back to generation-
	 * based invalidation rather than mutating a live VM in place.
	 */
	{
		struct lvm_state *new_lvm;
		struct lvm_state *old_lvm;
		int n;

		new_lvm = lvm_state_build_new();
		if (IS_ERR(new_lvm))
			return PTR_ERR(new_lvm);

		err = lib_install_protected(new_lvm->L, desc);
		if (err) {
			lvm_state_free_heap(new_lvm);
			return err;
		}
		WRITE_ONCE(new_lvm->generation, target_gen);
		log->current_new = new_lvm;

		llt = lua_lsm_task(current);
		if (!llt || !llt->lvm) {
			lvm_state_free_heap(new_lvm);
			log->current_new = NULL;
		} else {
			old_lvm = llt->lvm;
			n = refcount_acquire(&old_lvm->refcount);
			if (n != 1) {
				refcount_release(&old_lvm->refcount);
				lvm_state_free_heap(new_lvm);
				log->current_new = NULL;
			} else {
				log->current_old = old_lvm;
				WRITE_ONCE(llt->lvm, new_lvm);
				/*
				 * llt no longer references old_lvm; release
				 * the bump directly so we don't touch the
				 * post-swap llt->lvm refcount.
				 */
				refcount_release(&old_lvm->refcount);
				log->current_swapped = true;
			}
		}
	}

	for_each_possible_cpu(cpu) {
		if (log->irq_installed[cpu] && log->irq_old[cpu]) {
			lvm_state_free_heap(log->irq_old[cpu]);
			log->irq_old[cpu] = NULL;
		}
	}

	if (log->current_swapped && log->current_old) {
		lvm_state_free_heap(log->current_old);
		log->current_old = NULL;
	}

	return 0;
}

static bool lua_api_lib_rollback(struct lua_api_lib *desc,
				 struct lib_replay_log *log)
{
	struct lua_lsm_task *llt;
	bool cleanup_ok = true;
	int cpu;

	lockdep_assert_held(&modules_mutex);
	lockdep_assert_cpus_held();

	if (log->current_swapped) {
		llt = lua_lsm_task(current);
		if (llt && llt->lvm == log->current_new) {
			int n = refcount_acquire(&log->current_new->refcount);

			if (n != 1) {
				refcount_release(&log->current_new->refcount);
				pr_err("rollback: cannot acquire exclusive on current's swapped-in VM for '%s' (refcount=%d); leaking module pin to prevent UAF\n",
				       desc->name, n);
				cleanup_ok = false;
			} else {
				WRITE_ONCE(llt->lvm, log->current_old);
				refcount_release(&log->current_new->refcount);
				log->current_swapped = false;
			}
		} else {
			pr_err("rollback: current's task VM no longer references its replay-time replacement for '%s'; leaking module pin to prevent UAF\n",
			       desc->name);
			cleanup_ok = false;
		}
	}

	WRITE_ONCE(work_ctx_log, log);
	lib_dispatch_per_cpu(log, swap_back_irq_lvm_work);
	WRITE_ONCE(work_ctx_log, NULL);

	for_each_possible_cpu(cpu) {
		if (log->irq_new[cpu]) {
			lvm_state_free_heap(log->irq_new[cpu]);
			log->irq_new[cpu] = NULL;
		}
	}

	if (cleanup_ok && log->current_new) {
		lvm_state_free_heap(log->current_new);
		log->current_new = NULL;
	}

	return cleanup_ok;
}

/*
 * The per-CPU lua_State outlives hotplug; this callback only replays
 * descriptors published while the CPU was offline.
 */
static int lua_api_lib_cpu_online(unsigned int cpu)
{
	struct lvm_state *lvm = per_cpu(irq_lvms, cpu);
	struct lua_api_lib *desc;
	int err = 0;
	int idx;

	if (!lvm)
		return 0;

	idx = srcu_read_lock(&modules_ss);
	list_for_each_entry_srcu(desc, &lua_api_libs, list,
				 srcu_read_lock_held(&modules_ss)) {
		local_bh_disable();
		err = lib_install_protected(lvm->L, desc);
		local_bh_enable();
		if (err) {
			pr_err("cpu %u online: install of '%s' failed: %d\n",
			       cpu, desc->name, err);
			break;
		}
	}
	srcu_read_unlock(&modules_ss, idx);
	if (!err)
		WRITE_ONCE(lvm->generation,
			   (unsigned int)atomic_read(&lua_api_lib_generation));
	return err;
}

int __init lua_api_lib_cpu_hotplug_init(void)
{
	int ret;

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
				"lua-lsm:api-lib-online",
				lua_api_lib_cpu_online, NULL);
	if (ret < 0)
		return ret;

	return 0;
}

int __lua_api_lib_register(struct lua_api_lib *desc)
{
	struct lib_replay_log log = { };
	enum lua_api_lib_audit_reason reason = LUA_API_LIB_AUDIT_NONE;
	struct lvm_state *scratch;
	bool cleanup_ok;
	int err;

	err = lua_api_lib_validate_shared(desc);
	if (err)
		return err;

	if (!READ_ONCE(lua_api_lib_registry_ready)) {
		err = -EAGAIN;
		reason = LUA_API_LIB_AUDIT_NOT_READY;
		goto audit;
	}

	err = lua_api_lib_gate_signed(desc);
	if (err) {
		reason = LUA_API_LIB_AUDIT_UNSIGNED;
		goto audit;
	}

	if (lua_api_lib_name_reserved(desc->name)) {
		err = -EEXIST;
		reason = LUA_API_LIB_AUDIT_RESERVED_NAME;
		goto audit;
	}

	err = lib_replay_log_init(&log);
	if (err) {
		reason = LUA_API_LIB_AUDIT_RESOURCE;
		goto audit;
	}

	mutex_lock(&modules_mutex);

	if (lua_api_lib_name_exists_locked(desc->name)) {
		err = -EEXIST;
		reason = LUA_API_LIB_AUDIT_DUPLICATE;
		goto unlock;
	}

	if (!try_module_get(desc->owner)) {
		err = -ENODEV;
		reason = LUA_API_LIB_AUDIT_PIN_FAILED;
		goto unlock;
	}

	err = lua_api_lib_validate_text_owner(desc);
	if (err) {
		reason = LUA_API_LIB_AUDIT_TEXT_OWNER;
		module_put(desc->owner);
		goto unlock;
	}

	scratch = lvm_state_build_new();
	if (IS_ERR(scratch)) {
		err = PTR_ERR(scratch);
		reason = LUA_API_LIB_AUDIT_SCRATCH;
		module_put(desc->owner);
		goto unlock;
	}
	err = lib_install_protected(scratch->L, desc);
	lvm_state_free_heap(scratch);
	if (err) {
		reason = LUA_API_LIB_AUDIT_SCRATCH;
		module_put(desc->owner);
		goto unlock;
	}

	/* Lock ordering matches lua_lsm_module_unregister(). */
	cpus_read_lock();

	err = lua_api_lib_replay(desc, &log);
	if (err) {
		cleanup_ok = lua_api_lib_rollback(desc, &log);
		cpus_read_unlock();
		if (cleanup_ok) {
			module_put(desc->owner);
		} else {
			pr_err("registration of '%s' failed and rollback could not prove all VMs released the library's C closures; leaking module pin to prevent module-text UAF\n",
			       desc->name);
		}
		reason = LUA_API_LIB_AUDIT_REPLAY;
		goto unlock;
	}

	/* Commit point: no failure path after publication. */
	INIT_LIST_HEAD(&desc->list);
	list_add_tail_rcu(&desc->list, &lua_api_libs);
	atomic_inc_return(&lua_api_lib_generation);

	cpus_read_unlock();

	lua_api_lib_drain_pools();

	mutex_unlock(&modules_mutex);

	lib_replay_log_free(&log);
	pr_info("registered Lua API library '%s'\n", desc->name);
	err = 0;
	goto audit;

unlock:
	mutex_unlock(&modules_mutex);
	lib_replay_log_free(&log);

audit:
	lua_api_lib_audit(desc, err, reason);
	return err;
}

int lua_api_lib_register(struct lua_api_lib *desc)
{
	if (!desc || !desc->owner)
		return -EINVAL;
	return __lua_api_lib_register(desc);
}
EXPORT_SYMBOL_GPL(lua_api_lib_register);

int lua_api_libraries_show(struct seq_file *m, void *v)
{
	struct lua_api_lib *desc;
	unsigned int nfuncs;
	unsigned int version;
	int idx;
	bool found = false;

	version = (unsigned int)atomic_read(&lua_api_lib_generation);
	seq_puts(m, "API libraries for lua-lsm\n");
	seq_printf(m, "API set version: %u\n", version);
	seq_printf(m, "%-20s %-20s %5s %10s %4s\n",
		   "name", "provider", "funcs", "init-table", "abi");
	seq_printf(m, "%s\n", TABLINE);

	idx = srcu_read_lock(&modules_ss);
	list_for_each_entry_srcu(desc, &lua_api_libs, list,
				 srcu_read_lock_held(&modules_ss)) {
		found = true;
		nfuncs = 0;
		while (desc->funcs[nfuncs].name)
			nfuncs++;

		seq_printf(m, "%-20s %-20s %5u %10s %4u\n",
			   desc->name,
			   desc->owner ? desc->owner->name : "builtin",
			   nfuncs,
			   desc->init_table ? "yes" : "no",
			   desc->abi_version);
	}
	srcu_read_unlock(&modules_ss, idx);
	if (!found)
		seq_puts(m, "(none)\n");

	return 0;
}
