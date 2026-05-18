/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#include "debug.h"
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errname.h>
#include <linux/rwlock.h>
#include <linux/lua.h>
#include <linux/lualib.h>
#include <linux/lauxlib.h>
#include "auxlib.h"
#include "lsm.h"
#include "kvcache.h"

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

static int kvcache_node_cmp(struct kvcache_node *n1, struct kvcache_node *n2)
{
	int n = strcmp(n1->key, n2->key);

	if (n != 0)
		return n;
	return (char *)n1->module - (char *)n2->module;
}

RB_GENERATE_STATIC(kvcache, kvcache_node, node, kvcache_node_cmp);

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

	prev = RB_INSERT(kvcache, &dict->root, node);
	if (prev) {
		kvcache_node_hold(prev);
	} else {
		atomic_inc(&dict->count);
		if (module) {
			WARN_ON(module->state != LMS_STATE_LIVE);
			spin_lock(&module->kvnodes_lock);
			list_add_tail_rcu(&node->modlist, &module->kvnodes);
			atomic_inc(&module->kvnodes_count);
			spin_unlock(&module->kvnodes_lock);
		}
	}

unlock:
	write_unlock_irqrestore(&dict->lock, flags);
	return prev;
}

static void
kvcache_module_unlink_unlocked(struct kvcache_dict *dict,
			       struct lua_lsm_module *module,
			       struct kvcache_node *node)
{
	RB_REMOVE(kvcache, &dict->root, node);
	atomic_dec(&dict->count);
	if (module) {
		spin_lock(&module->kvnodes_lock);
		list_del_rcu(&node->modlist);
		atomic_dec(&module->kvnodes_count);
		spin_unlock(&module->kvnodes_lock);
	}
}

static void
kvcache_module_unlink(struct kvcache_dict *dict,
		      struct lua_lsm_module *module,
		      struct kvcache_node *node)
{
	unsigned long flags;

	write_lock_irqsave(&dict->lock, flags);
	kvcache_module_unlink_unlocked(dict, module, node);
	write_unlock_irqrestore(&dict->lock, flags);
}

static int kvcache_node_fill(lua_State *L, int idx, struct kvcache_node *node)
{
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
	}
}

static int kvcache_node_refill(lua_State *L, int idx, struct kvcache_node *node)
{
	struct kvcache_node ntmp;
	unsigned long flags;
	int err;

	err = kvcache_node_fill(L, idx, &ntmp);
	if (err)
		return err;

	write_lock_irqsave(&node->lock, flags);
	kvcache_node_clear(node);
	kvcache_node_copy(node, &ntmp);
	write_unlock_irqrestore(&node->lock, flags);

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
		}
	} else {
		if (tt == LUA_TNIL) {
			kvcache_module_unlink(dict, module, node);
			kvcache_node_drop(node);
			err = 0;
		} else {
			err = kvcache_node_refill(L, 3, node);
		}
		kvcache_node_drop(node);
	}

	if (err)
		return kvcache_result(L, err);

ret:
	lua_pushboolean(L, 1);
	return 1;
}

static int kvcache_node_get(lua_State *L, struct kvcache_node *node)
{
	struct kvcache_node ntmp;
	unsigned long flags;

	read_lock_irqsave(&node->lock, flags);
	kvcache_node_copy(&ntmp, node);
	read_unlock_irqrestore(&node->lock, flags);

	switch (ntmp.tt) {
	case LUA_TBOOLEAN:
		lua_pushboolean(L, ntmp.b);
		break;
	case LUA_TNUMBER:
		lua_pushnumber(L, ntmp.n);
		break;
	case LUA_TLIGHTUSERDATA:
		lua_pushlightuserdata(L, ntmp.p);
		break;
	default:
		WARN_ON(1);
		return -EINVAL;
	}
	return 0;
}

static int kvcache_get(lua_State *L, struct kvcache_dict *dict,
		       struct lua_lsm_module *module)
{
	const char *key = luaL_checkstring(L, 2);
	struct kvcache_node *node;

	node = kvcache_lookup(dict, module, key);
	if (node) {
		kvcache_node_get(L, node);
		kvcache_node_drop(node);
	} else {
		lua_pushnil(L);
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
			node->n += n;
			n = node->n;
			err = 0;
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
	rwlock_init(&dict->lock);
	RB_INIT(&dict->root);
	atomic_set(&dict->count, 0);
	dict->capacity = CACHE_CAPACITY;
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
