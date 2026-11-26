// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#define pr_fmt(fmt)	"lua-lsm: " fmt

#include "debug.h"
#include <linux/printk.h>
#include <linux/percpu.h>
#include <linux/seq_file.h>
#include <linux/lua.h>
#include "lsm.h"

/* Used by module unregister */
static atomic_t vm_nusage = ATOMIC_INIT(0);

int lvm_stats_vm_nusage(void)
{
	return atomic_read(&vm_nusage);
}

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

void lua_lsm_hook_stats_init_cpu(int cpu)
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

void lvm_stats_vmalloc(void)
{
	atomic_inc(&vm_nalloc);
	atomic_inc(&vm_nusage);
}

void lvm_stats_vmfree(void)
{
	atomic_inc(&vm_nfree);
	atomic_dec(&vm_nusage);
}

void lvm_stats_memalloc(struct lvm_state *lvm, void *ptr,
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

#else	/* !CONFIG_SECURITY_LUA_LSM_STATS */

void lvm_stats_vmalloc(void)
{
	atomic_inc(&vm_nusage);
}

void lvm_stats_vmfree(void)
{
	atomic_dec(&vm_nusage);
}

void lvm_stats_memalloc(struct lvm_state *lvm, void *ptr,
			size_t osize, size_t nsize)
{
}

#endif
