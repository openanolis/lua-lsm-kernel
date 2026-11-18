/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#include "debug.h"
#include <linux/bottom_half.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/errname.h>
#include <linux/rwlock.h>
#include <linux/processor.h>
#include <linux/lua.h>
#include <linux/lualib.h>
#include <linux/lauxlib.h>
#include "auxlib.h"
#include "lsm.h"
#include "kvcache.h"

/*
 * A generation alone misses a writer which has started but not committed.
 * Count overlapping writers as well. The lock orders both observations and
 * publication, but is NEVER held across a mutation, allocation or Lua call.
 * Dictionary/node locks still protect the actual data. Readers may sleep while
 * capturing values, validate the window, then format only retained copies.
 */
static DEFINE_SPINLOCK(shdict_snapshot_lock);
static u64 shdict_snapshot_generation;
static unsigned int shdict_snapshot_writers;

void shdict_snapshot_write_begin(void)
{
	unsigned long flags;

	spin_lock_irqsave(&shdict_snapshot_lock, flags);
	shdict_snapshot_writers++;
	spin_unlock_irqrestore(&shdict_snapshot_lock, flags);
}

void shdict_snapshot_write_end(void)
{
	unsigned long flags;

	spin_lock_irqsave(&shdict_snapshot_lock, flags);
	shdict_snapshot_generation++;
	shdict_snapshot_writers--;
	spin_unlock_irqrestore(&shdict_snapshot_lock, flags);
}

bool shdict_snapshot_begin(u64 *generation)
{
	unsigned long flags;
	bool ready;

	spin_lock_irqsave(&shdict_snapshot_lock, flags);
	*generation = shdict_snapshot_generation;
	ready = !shdict_snapshot_writers;
	spin_unlock_irqrestore(&shdict_snapshot_lock, flags);
	return ready;
}

bool shdict_snapshot_retry(u64 generation)
{
	unsigned long flags;
	bool retry;

	spin_lock_irqsave(&shdict_snapshot_lock, flags);
	retry = shdict_snapshot_writers ||
		generation != shdict_snapshot_generation;
	spin_unlock_irqrestore(&shdict_snapshot_lock, flags);
	return retry;
}

#ifdef CONFIG_SECURITY_LUA_LSM_STATS

static atomic64_t node_nalloc = ATOMIC_INIT(0);
static atomic64_t node_nfree = ATOMIC_INIT(0);
static atomic64_t node_nusage = ATOMIC_INIT(0);

static void kvcache_stats_alloc(void)
{
	atomic64_inc(&node_nalloc);
	atomic64_inc(&node_nusage);
}

static void kvcache_stats_free(void)
{
	atomic64_inc(&node_nfree);
	atomic64_dec(&node_nusage);
}

void kvcache_stats_show(struct seq_file *m)
{
	seq_printf(m, "kvcache.nalloc\t= %12lld\n", atomic64_read(&node_nalloc));
	seq_printf(m, "kvcache.nfree\t= %12lld\n", atomic64_read(&node_nfree));
	seq_printf(m, "kvcache.nusage\t= %12lld\n", atomic64_read(&node_nusage));
}

#else

static inline void kvcache_stats_alloc(void) {}
static inline void kvcache_stats_free(void) {}

#endif

static struct kvcache_string *
kvcache_string_alloc(const char *value, size_t len)
{
	struct kvcache_string *string;

	if (len == SIZE_MAX)
		return NULL;

	string = kmalloc(struct_size(string, data, len + 1), lua_lsm_gfp());
	if (!string)
		return NULL;

	refcount_init(&string->refcount, 1);
	string->len = len;
	memcpy(string->data, value, len);
	string->data[len] = '\0';
	return string;
}

static void kvcache_string_hold(struct kvcache_string *string)
{
	if (string)
		refcount_acquire(&string->refcount);
}

static void kvcache_string_drop(struct kvcache_string *string)
{
	if (string && refcount_release(&string->refcount) == 0)
		kfree(string);
}

static int kvcache_node_cmp(struct kvcache_node *n1, struct kvcache_node *n2)
{
	int n = strcmp(n1->key, n2->key);

	if (n != 0)
		return n;
	return (char *)n1->module - (char *)n2->module;
}

RB_GENERATE_STATIC(kvcache, kvcache_node, node, kvcache_node_cmp);

static void __kvcache_dict_init(struct kvcache_dict *dict)
{
	rwlock_init(&dict->lock);
	RB_INIT(&dict->root);
	atomic_set(&dict->count, 0);
	dict->capacity = CACHE_CAPACITY;
}

static bool kvcache_dict_ready(struct kvcache_dict *dict)
{
	int state;

	for (;;) {
		state = atomic_read_acquire(&dict->state);
		if (likely(state == KVCACHE_DICT_READY))
			return true;
		if (state != KVCACHE_DICT_INITING)
			return false;
		cpu_relax();
	}
}

static int kvcache_dict_init_once(struct kvcache_dict *dict)
{
	int state;

	for (;;) {
		local_bh_disable();
		state = atomic_read_acquire(&dict->state);
		if (likely(state == KVCACHE_DICT_READY))
			goto out_bh;
		if (state == KVCACHE_DICT_INITING) {
			local_bh_enable();
			cpu_relax();
			continue;
		}
		if (WARN_ON_ONCE(state != KVCACHE_DICT_UNINIT)) {
			local_bh_enable();
			return -EINVAL;
		}

		/*
		 * Readers busy-wait while the dictionary is INITING. Keep the
		 * UNINIT->READY transition within a softirq-disabled window so a
		 * same-CPU softirq cannot observe INITING and spin before the
		 * initializer publishes READY.
		 */
		if (atomic_try_cmpxchg(&dict->state, &state,
				       KVCACHE_DICT_INITING)) {
			__kvcache_dict_init(dict);
			atomic_set_release(&dict->state, KVCACHE_DICT_READY);
			goto out_bh;
		}
		local_bh_enable();
	}

out_bh:
	local_bh_enable();
	return 0;
}

static int kvcache_result(lua_State *L, int err)
{
	lua_pushnil(L);
	lua_pushstring(L, errname(err) ?: "unknown");
	return 2;
}

static struct kvcache_node *
kvcache_node_alloc(struct kvcache_dict *dict, struct lua_lsm_module *module,
		   const char *key, size_t len)
{
	size_t l = sizeof(struct kvcache_node);
	struct kvcache_node *node;

	l += key ? (len + 1) : 0;
	node = kmalloc(l, lua_lsm_gfp());
	if (!node)
		return NULL;

	if (key) {
		memcpy((char *)(node + 1), key, len);
		((char *)(node + 1))[len] = '\0';	/* ending 0 */
		node->key = (const char *)(node + 1);
	} else {
		node->key = NULL;
	}
	node->tt = LUA_TNIL;
	node->module = module;
	node->dict = dict;
	refcount_init(&node->refcount, 1);
	rwlock_init(&node->lock);
	kvcache_stats_alloc();
	return node;
}

static void kvcache_node_clear(struct kvcache_node *node)
{
	switch (node->tt) {
	case LUA_TBOOLEAN:
	case LUA_TNUMBER:
	case LUA_TLIGHTUSERDATA:
		break;
	case LUA_TSTRING:
		kvcache_string_drop(node->s);
		break;
	}
	node->tt = LUA_TNIL;
}

static void kvcache_node_free(struct kvcache_node *node)
{
	kvcache_node_clear(node);
	kvcache_stats_free();
	kfree(node);
}

static void kvcache_node_hold(struct kvcache_node *node)
{
	if (node)
		refcount_acquire(&node->refcount);
}

static void kvcache_node_drop(struct kvcache_node *node)
{
	if (!node)
		return;
	if (refcount_release(&node->refcount) == 0)
		kvcache_node_free(node);
}

static struct kvcache_node *
kvcache_lookup(struct kvcache_dict *dict,
	       struct lua_lsm_module *module, const char *key)
{
	struct kvcache_node tmp, *node;
	unsigned long flags;

	if (!kvcache_dict_ready(dict))
		return NULL;

	tmp.key = key;
	tmp.module = module;
	read_lock_irqsave(&dict->lock, flags);
	node = RB_FIND(kvcache, &dict->root, &tmp);
	kvcache_node_hold(node);
	read_unlock_irqrestore(&dict->lock, flags);
	return node;
}

static struct kvcache_node *
kvcache_module_link(struct kvcache_dict *dict,
		    struct lua_lsm_module *module, struct kvcache_node *node)
{
	struct kvcache_node *prev;
	unsigned long flags;

	write_lock_irqsave(&dict->lock, flags);

	if (atomic_read(&dict->count) >= dict->capacity) {
		prev = ERR_PTR(-ERANGE);
		goto unlock;
	}

	if (dict->snapshot_tracked)
		shdict_snapshot_write_begin();
	prev = RB_INSERT(kvcache, &dict->root, node);
	if (prev) {
		kvcache_node_hold(prev);
	} else {
		atomic_inc(&dict->count);
		if (module) {
			/* An admitted SRCU reader may finish after LIVE -> GOING. */
			spin_lock(&module->kvnodes_lock);
			list_add_tail_rcu(&node->modlist, &module->kvnodes);
			atomic_inc(&module->kvnodes_count);
			spin_unlock(&module->kvnodes_lock);
		}
	}
	if (dict->snapshot_tracked)
		shdict_snapshot_write_end();

unlock:
	write_unlock_irqrestore(&dict->lock, flags);
	return prev;
}

static bool
kvcache_module_unlink_unlocked(struct kvcache_dict *dict,
			       struct lua_lsm_module *module,
			       struct kvcache_node *node)
{
	/* Two deleters may have acquired lookup references to the same node. */
	if (RB_FIND(kvcache, &dict->root, node) != node)
		return false;
	if (dict->snapshot_tracked)
		shdict_snapshot_write_begin();
	RB_REMOVE(kvcache, &dict->root, node);
	atomic_dec(&dict->count);
	if (module) {
		spin_lock(&module->kvnodes_lock);
		list_del_rcu(&node->modlist);
		atomic_dec(&module->kvnodes_count);
		spin_unlock(&module->kvnodes_lock);
	}
	if (dict->snapshot_tracked)
		shdict_snapshot_write_end();
	return true;
}

static bool
kvcache_module_unlink(struct kvcache_dict *dict,
		      struct lua_lsm_module *module,
		      struct kvcache_node *node)
{
	unsigned long flags;
	bool removed;

	write_lock_irqsave(&dict->lock, flags);
	removed = kvcache_module_unlink_unlocked(dict, module, node);
	write_unlock_irqrestore(&dict->lock, flags);
	return removed;
}

static int kvcache_node_fill(lua_State *L, int idx, struct kvcache_node *node)
{
	size_t len;
	const char *value;

	node->tt = lua_type(L, idx);
	switch (node->tt) {
	case LUA_TBOOLEAN:
		node->b = lua_toboolean(L, idx);
		break;

	case LUA_TNUMBER:
		node->n = lua_tonumber(L, idx);
		break;

	case LUA_TLIGHTUSERDATA:
		node->p = lua_touserdata(L, idx);
		break;

	case LUA_TSTRING:
		value = lua_tolstring(L, idx, &len);
		node->s = kvcache_string_alloc(value, len);
		if (!node->s)
			return -ENOMEM;
		break;

	default:
		return -EINVAL;
	}
	return 0;
}

static void
kvcache_node_copy(struct kvcache_node *node, struct kvcache_node *src)
{
	node->tt = src->tt;
	switch (src->tt) {
	case LUA_TBOOLEAN:
		node->b = src->b;
		break;
	case LUA_TNUMBER:
		node->n = src->n;
		break;
	case LUA_TLIGHTUSERDATA:
		node->p = src->p;
		break;
	case LUA_TSTRING:
		node->s = src->s;
		kvcache_string_hold(node->s);
		break;
	}
}

static int kvcache_node_refill(lua_State *L, int idx,
			       struct kvcache_node *node)
{
	struct kvcache_node ntmp = { .tt = LUA_TNIL };
	unsigned long flags;
	int err;

	err = kvcache_node_fill(L, idx, &ntmp);
	if (err)
		return err;

	write_lock_irqsave(&node->lock, flags);
	if (node->dict->snapshot_tracked)
		shdict_snapshot_write_begin();
	kvcache_node_clear(node);
	kvcache_node_copy(node, &ntmp);
	if (node->dict->snapshot_tracked)
		shdict_snapshot_write_end();
	write_unlock_irqrestore(&node->lock, flags);
	kvcache_node_clear(&ntmp);
	return 0;
}

static int kvcache_set(lua_State *L, struct kvcache_dict *dict,
		       struct lua_lsm_module *module)
{
	size_t len;
	const char *key = luaL_checklstring(L, 2, &len);
	int tt = lua_type(L, 3);
	struct kvcache_node *node, *prev;
	int err;

	err = kvcache_dict_init_once(dict);
	if (err)
		return kvcache_result(L, err);

	node = kvcache_lookup(dict, module, key);
	if (!node) {
		if (tt == LUA_TNIL)
			goto ret;

		node = kvcache_node_alloc(dict, module, key, len);
		if (!node)
			return kvcache_result(L, -ENOMEM);

		err = kvcache_node_fill(L, 3, node);
		if (err) {
			kvcache_node_free(node);
			return kvcache_result(L, err);
		}

		prev = kvcache_module_link(dict, module, node);
		if (prev) {
			kvcache_node_free(node);

			if (IS_ERR(prev))
				return kvcache_result(L, PTR_ERR(prev));

			err = kvcache_node_refill(L, 3, prev);
			kvcache_node_drop(prev);
			if (err)
				return kvcache_result(L, err);
		}
	} else {
		if (tt == LUA_TNIL) {
			if (kvcache_module_unlink(dict, module, node))
				kvcache_node_drop(node); /* tree reference */
			kvcache_node_drop(node);	/* lookup reference */
		} else {
			err = kvcache_node_refill(L, 3, node);
			kvcache_node_drop(node);
			if (err)
				return kvcache_result(L, err);
		}
	}

ret:
	lua_pushboolean(L, 1);
	return 1;
}

static int kvcache_value_push(lua_State *L)
{
	const struct kvcache_node *value = lua_touserdata(L, 1);

	switch (value->tt) {
	case LUA_TBOOLEAN:
		lua_pushboolean(L, value->b);
		break;
	case LUA_TNUMBER:
		lua_pushnumber(L, value->n);
		break;
	case LUA_TLIGHTUSERDATA:
		lua_pushlightuserdata(L, value->p);
		break;
	case LUA_TSTRING:
		lua_pushlstring(L, value->s->data, value->s->len);
		break;
	default:
		return luaL_error(L, "invalid dictionary value type");
	}
	return 1;
}

static int kvcache_get(lua_State *L, struct kvcache_dict *dict,
		       struct lua_lsm_module *module)
{
	const char *key = luaL_checkstring(L, 2);
	struct kvcache_node *node;
	struct kvcache_node value = { .tt = LUA_TNIL };
	unsigned long flags;
	int status;

	/* Closure allocation must precede acquiring any C-owned references. */
	lua_pushcfunction(L, kvcache_value_push);
	lua_pushlightuserdata(L, &value);
	node = kvcache_lookup(dict, module, key);
	if (!node) {
		lua_pop(L, 2);
		lua_pushnil(L);
		return 1;
	}
	read_lock_irqsave(&node->lock, flags);
	kvcache_node_copy(&value, node);
	read_unlock_irqrestore(&node->lock, flags);
	kvcache_node_drop(node);

	/* lua_pushlstring() may longjmp on OOM. Always drop the snapshot first. */
	status = lua_pcall(L, 1, 1, 0);
	kvcache_node_clear(&value);
	if (status) {
		lua_pop(L, 1);
		/* lua_error() would turn LUA_ERRMEM into LUA_ERRRUN on rethrow. */
		return kvcache_result(L, status == LUA_ERRMEM ? -ENOMEM : -EIO);
	}
	return 1;
}

static int kvcache_incr(lua_State *L, struct kvcache_dict *dict,
			struct lua_lsm_module *module)
{
	size_t len;
	const char *key = luaL_checklstring(L, 2, &len);
	lua_Number n = luaL_optnumber(L, 3, 1);
	struct kvcache_node *node, *prev;
	unsigned long flags;
	int err;

	err = kvcache_dict_init_once(dict);
	if (err)
		return kvcache_result(L, err);

	node = kvcache_lookup(dict, module, key);
	if (!node) {
		node = kvcache_node_alloc(dict, module, key, len);
		if (!node)
			return kvcache_result(L, -ENOMEM);

		node->n = n;
		node->tt = LUA_TNUMBER;

		prev = kvcache_module_link(dict, module, node);
		if (prev) {
			kvcache_node_free(node);

			if (IS_ERR(prev))
				return kvcache_result(L, PTR_ERR(prev));

			node = prev;
			goto update;
		}
	} else {
update:
		err = -EINVAL;
		write_lock_irqsave(&node->lock, flags);
		if (node->tt == LUA_TNUMBER) {
			if (dict->snapshot_tracked)
				shdict_snapshot_write_begin();
			node->n += n;
			n = node->n;
			err = 0;
			if (dict->snapshot_tracked)
				shdict_snapshot_write_end();
		}
		write_unlock_irqrestore(&node->lock, flags);
		kvcache_node_drop(node);

		if (err)
			return kvcache_result(L, err);
	}

	lua_pushnumber(L, n);
	return 1;
}

/*
 * Currently, there's no efficient RCU read-side traversal solution for
 * rbtree. Therefore, a spinlock is used to synchronize the release of
 * kvcache_nodes along the following two paths:
 *   - Release the entire kvnodes list when the module is released
 *   - Release the entire kvcache_dict when the kernel object is released
 */
static DEFINE_SPINLOCK(nodes_gc_lock);

int kvcache_module_nodes_gc(struct lua_lsm_module *module)
{
	struct kvcache_node *node, *tmp;
	int count, n = 0;

	spin_lock_bh(&nodes_gc_lock);
	list_for_each_entry(node, &module->kvnodes, modlist) {
		struct kvcache_dict *dict = node->dict;

		BUG_ON(!dict);
		/*
		 * module is set to NULL, so there is no need to remove
		 * node from the module kvnodes queue.
		 */
		kvcache_module_unlink(dict, NULL, node);
	}
	spin_unlock_bh(&nodes_gc_lock);

	count = atomic_read(&module->kvnodes_count);
	list_for_each_entry_safe(node, tmp, &module->kvnodes, modlist) {
		list_del(&node->modlist);
		atomic_dec(&module->kvnodes_count);
		kvcache_node_drop(node);
		n += 1;
	}

	__log_info("module <%s>, kvnodes_count = %d, freed = %d\n",
		   module->name, count, n);
	WARN_ON(count != n);
	return n;
}

void kvcache_dict_free(struct kvcache_dict *dict)
{
	struct kvcache_node *node, *n;
	struct lua_lsm_module *module;

	if (!kvcache_dict_ready(dict))
		return;

	if (atomic_read(&dict->count) == 0)
		return;

	spin_lock_bh(&nodes_gc_lock);
	RB_FOREACH(node, kvcache, &dict->root) {
		module = node->module;
		if (module) {
			spin_lock(&module->kvnodes_lock);
			list_del_rcu(&node->modlist);
			atomic_dec(&module->kvnodes_count);
			spin_unlock(&module->kvnodes_lock);
		}
	}
	spin_unlock_bh(&nodes_gc_lock);

	RB_FOREACH_SAFE(node, kvcache, &dict->root, n) {
		kvcache_module_unlink_unlocked(dict, NULL, node);
		kvcache_node_drop(node);
	}
	WARN_ON(atomic_read(&dict->count) != 0);
}

void kvcache_dict_init(struct kvcache_dict *dict)
{
	dict->snapshot_tracked = false;
	atomic_set(&dict->state, KVCACHE_DICT_INITING);
	__kvcache_dict_init(dict);
	atomic_set_release(&dict->state, KVCACHE_DICT_READY);
}

static int kvcache_dump_append(char *buf, size_t size, size_t *pos,
			       const char *value, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		unsigned char c = value[i];

		if (c >= 0x20 && c < 0x7f && c != '\\') {
			if (*pos + 1 >= size)
				return -E2BIG;
			buf[(*pos)++] = c;
			continue;
		}

		if (*pos + 4 >= size)
			return -E2BIG;
		*pos += scnprintf(buf + *pos, size - *pos, "\\x%02x", c);
	}
	return 0;
}

struct kvcache_dump_entry {
	struct kvcache_node *node;
	int tt;
	union {
		int b;
		lua_Number n;
		struct kvcache_string *s;
	};
};

struct kvcache_dump_snapshot {
	struct list_head list;
	const char *module_name;
	const char *dict_name;
	size_t count;
	struct kvcache_dump_entry entries[];
};

/* Capture references and immutable values, without text formatting. */
int kvcache_dump_capture(struct kvcache_dict *dict, const char *module_name,
			 const char *dict_name, struct list_head *snapshots,
			 size_t *remaining)
{
	struct kvcache_dump_snapshot *snapshot;
	struct kvcache_node *node;
	unsigned long flags;
	size_t capacity, i;
	int err = 0;

	if (!kvcache_dict_ready(dict))
		return 0;
	capacity = atomic_read(&dict->count);
	if (!capacity)
		return 0;
	if (!*remaining)
		return -E2BIG;
	capacity = min(capacity, *remaining);
	snapshot = kvzalloc(struct_size(snapshot, entries, capacity), GFP_KERNEL);
	if (!snapshot)
		return -ENOMEM;
	snapshot->module_name = module_name;
	snapshot->dict_name = dict_name;
	list_add_tail(&snapshot->list, snapshots);

	read_lock_irqsave(&dict->lock, flags);
	RB_FOREACH(node, kvcache, &dict->root) {
		if (snapshot->count == capacity) {
			err = -E2BIG;
			break;
		}
		kvcache_node_hold(node);
		snapshot->entries[snapshot->count++].node = node;
	}
	read_unlock_irqrestore(&dict->lock, flags);
	if (err)
		return err;
	*remaining -= snapshot->count;

	for (i = 0; i < snapshot->count; i++) {
		struct kvcache_dump_entry *entry = &snapshot->entries[i];

		node = snapshot->entries[i].node;
		read_lock_irqsave(&node->lock, flags);
		entry->tt = node->tt;
		switch (node->tt) {
		case LUA_TBOOLEAN:
			entry->b = node->b;
			break;
		case LUA_TNUMBER:
			entry->n = node->n;
			break;
		case LUA_TSTRING:
			entry->s = node->s;
			kvcache_string_hold(entry->s);
			break;
		}
		read_unlock_irqrestore(&node->lock, flags);
	}
	return 0;
}

void kvcache_dump_free(struct list_head *snapshots)
{
	struct kvcache_dump_snapshot *snapshot, *next;
	size_t i;

	list_for_each_entry_safe(snapshot, next, snapshots, list) {
		for (i = 0; i < snapshot->count; i++) {
			if (snapshot->entries[i].tt == LUA_TSTRING)
				kvcache_string_drop(snapshot->entries[i].s);
			kvcache_node_drop(snapshot->entries[i].node);
		}
		list_del(&snapshot->list);
		kvfree(snapshot);
	}
}

/* Only called after global generation validation; data is already copied. */
static int kvcache_dump_one(struct kvcache_dump_snapshot *snapshot,
			    char *buf, size_t size, size_t *pos)
{
	const char *module_name = snapshot->module_name;
	const char *dict_name = snapshot->dict_name;
	struct kvcache_node *node;
	struct kvcache_dump_entry *value;
	size_t count = snapshot->count, i;
	int err = 0, n;

	for (i = 0; i < count; i++) {
		node = snapshot->entries[i].node;
		err = kvcache_dump_append(buf, size, pos, module_name,
					  strlen(module_name));
		if (err)
			goto out;
		if (*pos + 1 >= size) {
			err = -E2BIG;
			goto out;
		}
		buf[(*pos)++] = ' ';
		err = kvcache_dump_append(buf, size, pos, dict_name,
					  strlen(dict_name));
		if (err)
			goto out;
		if (*pos + 1 >= size) {
			err = -E2BIG;
			goto out;
		}
		buf[(*pos)++] = ' ';
		err = kvcache_dump_append(buf, size, pos, node->key,
					  strlen(node->key));
		if (err)
			goto out;

		value = &snapshot->entries[i];

		switch (value->tt) {
		case LUA_TBOOLEAN:
			n = snprintf(buf + *pos, size - *pos, " boolean %s\n",
				     value->b ? "true" : "false");
			break;
		case LUA_TNUMBER:
			n = snprintf(buf + *pos, size - *pos, " number %lld\n",
				     (long long)value->n);
			break;
		case LUA_TSTRING:
			n = snprintf(buf + *pos, size - *pos, " string ");
			if (n < 0 || n >= size - *pos) {
				err = -E2BIG;
				break;
			}
			*pos += n;
			err = kvcache_dump_append(buf, size, pos, value->s->data,
						  value->s->len);
			if (!err) {
				if (*pos + 1 >= size)
					err = -E2BIG;
				else
					buf[(*pos)++] = '\n';
			}
			n = 0;
			break;
		case LUA_TLIGHTUSERDATA:
			n = snprintf(buf + *pos, size - *pos,
				     " lightuserdata <hidden>\n");
			break;
		default:
			n = -EINVAL;
			break;
		}

		if (err)
			goto out;
		if (n < 0) {
			err = n;
			goto out;
		}
		if (n >= size - *pos) {
			err = -E2BIG;
			goto out;
		}
		*pos += n;
	}

out:
	return err;
}

int kvcache_dump_format(struct list_head *snapshots, char *buf, size_t size,
			size_t *pos)
{
	struct kvcache_dump_snapshot *snapshot;
	int err;

	*pos = 0;
	list_for_each_entry(snapshot, snapshots, list) {
		err = kvcache_dump_one(snapshot, buf, size, pos);
		if (err)
			return err;
	}
	return 0;
}

/******************************** object cache *******************************/

const int _module_sentinel;

static struct lua_lsm_module *module_from_object_fenv(lua_State *L, int idx)
{
	struct lua_lsm_module *module;

	lua_getfenv(L, 1);
	lua_pushlightuserdata(L, MODULE_KEY);
	lua_gettable(L, -2);
	if (!lua_islightuserdata(L, -1)) {
		const char * __maybe_unused key = luaL_checkstring(L, 2);

		if (luaL_callmeta(L, 1, "__tostring")) {
			__log_err("NO object.fenv: <%s> key = %s, top = %d [%s]\n",
				  lua_tostring(L, -1), key, lua_gettop(L),
				  luaL_typename(L, -1));
			lua_pop(L, 3);
		} else {
			__log_err("NO object.fenv: key = %s, top = %d\n",
				  key, lua_gettop(L));
			lua_pop(L, 2);
		}
		return NULL;
	}

	module = lua_touserdata(L, -1);
	lua_pop(L, 2);
	return module;
}

int lua_object_get(lua_State *L, struct kvcache_dict *dict)
{
	struct lua_lsm_module *module;

	if (!dict)
		return 0;

	module = module_from_object_fenv(L, 1);
	if (!module)
		return 0;
	return kvcache_get(L, dict, module);
}

int lua_object_incr(lua_State *L, struct kvcache_dict *dict)
{
	struct lua_lsm_module *module;

	if (!dict)
		return kvcache_result(L, -ESRCH);

	module = module_from_object_fenv(L, 1);
	if (!module)
		return kvcache_result(L, -ESRCH);

	return kvcache_incr(L, dict, module);
}

/*
 *	__index = function(object, key)
 *		local mt = getmetatable(object)
 *		if not mt then
 *			return nil
 *		end
 *		repeat
 *		    local v = rawget(mt, key)
 *		    if v then
 *		        return v
 *		    end
 *		    mt = getmetatable(mt)
 *		until mt == nil
 *		local module = fenv.MODULE_KEY
 *		return C.kvcache_get(L, object.kvcache, module, key)
 *	end
 */
int lua_object_index(lua_State *L, struct kvcache_dict *dict)
{
	if (lua_getmetatable(L, 1) == 0) {
		__log_err("NO metatable for userdata\n");
		return 0;
	}

	do {
		lua_pushvalue(L, 2);
		lua_rawget(L, -2);		/* metatable[key] */
		if (!lua_isnil(L, -1))
			return 1;
		lua_pop(L, 1);
	} while (lua_getmetatable(L, -1));

	return lua_object_get(L, dict);
}

/*
 *	__newindex = function(object, key, v)
 *		local module = fenv.MODULE_KEY
 *		return C.kvcache_set(L, object.kvcache, module, key, v)
 *	end
 */
int lua_object_newindex(lua_State *L, struct kvcache_dict *dict)
{
	struct lua_lsm_module *module;

	if (!dict)
		return kvcache_result(L, -ESRCH);

	module = module_from_object_fenv(L, 1);
	if (!module)
		return kvcache_result(L, -ESRCH);

	return kvcache_set(L, dict, module);
}

/******************************** shared dict ********************************/

static int shdict_set(lua_State *L)
{
	struct kvcache_dict *shdict = toshdict(L, 1);

	return kvcache_set(L, shdict, NULL);
}

static int shdict_get(lua_State *L)
{
	struct kvcache_dict *shdict = toshdict(L, 1);

	return kvcache_get(L, shdict, NULL);
}

static int shdict_incr(lua_State *L)
{
	struct kvcache_dict *shdict = toshdict(L, 1);

	return kvcache_incr(L, shdict, NULL);
}

static int shdict_index(lua_State *L)
{
	struct kvcache_dict *shdict = toshdict(L, 1);

	/* metatable[key] */
	if (lua_getmetatable(L, 1) == 0) {
		__log_err("NO metatable for userdata\n");
		return 0;
	}
	lua_pushvalue(L, 2);
	lua_rawget(L, -2);
	if (!lua_isnoneornil(L, -1))
		return 1;

	return kvcache_get(L, shdict, NULL);
}

static int shdict_tostring(lua_State *L)
{
	struct kvcache_dict *shdict = toshdict(L, 1);
	unsigned long flags;

	read_lock_irqsave(&shdict->lock, flags);
	lua_pushfstring(L, "shdict (%d / %d)",
			atomic_read(&shdict->count), shdict->capacity);
	read_unlock_irqrestore(&shdict->lock, flags);
	return 1;
}

static int shdict_gc(lua_State *L)
{
	__log_info_ratelimited("shdict already freed by unregister\n");
	return 0;
}

static const luaL_Reg shdict_meth[] = {
	{ "set",	shdict_set	},
	{ "get",	shdict_get	},
	{ "incr",	shdict_incr	},
	{ "__index",	shdict_index	},
	{ "__newindex",	shdict_set	},
	{ "__tostring",	shdict_tostring	},
	{ "__gc",	shdict_gc	},
	{ NULL, NULL }
};

int shdict_init(lua_State *L)
{
	createmeta(L, METH_SHARED_DICT, "shdict", shdict_meth, NULL, 1);
	return 0;
}
