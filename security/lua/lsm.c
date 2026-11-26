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

#ifdef DEBUG

bool lua_lsm_debug = true;

static int __init disable_debug(char *str)
{
	lua_lsm_debug = false;
	return 1;
}
__setup("lua.nodebug", disable_debug);

#endif	/* ! DEBUG */

int lua_lsm_initialized __initdata;

DEFINE_STATIC_KEY_FALSE(lua_lsm_modules_live);
DEFINE_STATIC_KEY_FALSE(lua_lsm_modules_ever_registered);

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
		lvm_put_loaded_modules(lvm->L);
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

	err = lvm_irq_init();
	if (err)
		return err;

	/* Register only the hooks that Lua-LSM exposes to modules. */
	for (i = 0; i < ARRAY_SIZE(lua_lsm_hooks); i++) {
		if (!lua_lsm_hook_supported(i))
			continue;
		security_add_hooks(&lua_lsm_hooks[i], 1, &lua_lsmid);
	}

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
