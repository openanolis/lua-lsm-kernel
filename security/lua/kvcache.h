/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#ifndef _SECURITY_LUA_LSM_KVCACHE_H
#define _SECURITY_LUA_LSM_KVCACHE_H

#include <linux/list.h>
#include <linux/rwlock.h>
#include <linux/seq_file.h>
#include <linux/lua.h>
#include "refcount.h"
#undef RB_ROOT
#include "tree.h"

#define CACHE_CAPACITY	1024

struct lua_lsm_module;

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
	};
	RB_ENTRY(kvcache_node) node;
	struct list_head modlist;
};

struct kvcache_dict {
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
