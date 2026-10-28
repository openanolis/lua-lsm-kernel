/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#ifndef _SECURITY_LUA_LSM_KVCACHE_H
#define _SECURITY_LUA_LSM_KVCACHE_H

#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/rwlock.h>
#include <linux/seq_file.h>
#include <linux/lua.h>
#include "refcount.h"
#undef RB_ROOT
#include "tree.h"

#define CACHE_CAPACITY	1024

/* UNINIT must stay 0: kzalloc'd LSM blobs skip an explicit initializer. */
enum kvcache_dict_state {
	KVCACHE_DICT_UNINIT,
	KVCACHE_DICT_INITING,
	KVCACHE_DICT_READY,
};

struct lua_lsm_module;

/*
 * Immutable, reference-counted string value.  The payload is copied out of
 * the Lua state at allocation time, so a node never retains a pointer into
 * a VM stack. Nodes only exchange string references; the old value is
 * recycled once the last concurrent reader drops it.
 */
struct kvcache_string {
	atomic_t refcount;
	size_t len;
	char data[];
};

struct kvcache_node {
	const char *key;
	struct lua_lsm_module *module;
	struct kvcache_dict *dict;
	atomic_t refcount;
	rwlock_t lock;
	int tt;
	union {
		int b;
		lua_Number n;
		void *p;
		struct kvcache_string *s;
	};
	RB_ENTRY(kvcache_node) node;
	struct list_head modlist;
};

struct kvcache_dict {
	atomic_t state;
	/* Set before publishing a named shared dictionary, never for blobs. */
	bool snapshot_tracked;
	int capacity;
	atomic_t count;
	rwlock_t lock;

	RB_HEAD(kvcache, kvcache_node) root;
};

#ifdef CONFIG_SECURITY_LUA_LSM_STATS
void kvcache_stats_show(struct seq_file *m);
#endif

int kvcache_module_nodes_gc(struct lua_lsm_module *module);
void kvcache_dict_free(struct kvcache_dict *dict);
void kvcache_dict_init(struct kvcache_dict *dict);
int kvcache_dump_capture(struct kvcache_dict *dict, const char *module_name,
			 const char *dict_name, struct list_head *snapshots,
			 size_t *remaining);
int kvcache_dump_format(struct list_head *snapshots, char *buf, size_t size,
			size_t *pos);
void kvcache_dump_free(struct list_head *snapshots);

/* Short, non-sleeping mutation windows; never encompass a Lua API call. */
void shdict_snapshot_write_begin(void);
void shdict_snapshot_write_end(void);
bool shdict_snapshot_begin(u64 *generation);
bool shdict_snapshot_retry(u64 generation);

/******************************** object cache *******************************/

extern const int _module_sentinel;
#define MODULE_KEY	((void *)&_module_sentinel)

int lua_object_get(lua_State *L, struct kvcache_dict *dict);
int lua_object_incr(lua_State *L, struct kvcache_dict *dict);
int lua_object_index(lua_State *L, struct kvcache_dict *dict);
int lua_object_newindex(lua_State *L, struct kvcache_dict *dict);

/******************************** shared dict ********************************/

#define METH_SHARED_DICT	"meth_shared_dict"

#define newshdict(L)							\
	((struct kvcache_dict **)newcptr((L), METH_SHARED_DICT))
#define toshdictp(L, idx)						\
	((struct kvcache_dict **)luaL_checkudata((L), (idx), METH_SHARED_DICT))
#define toshdict(L, idx)	(*toshdictp(L, idx))

int shdict_init(lua_State *L);

#endif  /* ! _SECURITY_LUA_LSM_KVCACHE_H */
