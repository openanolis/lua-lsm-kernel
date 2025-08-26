/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#include "debug.h"
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/rwlock.h>
#include <linux/lua.h>
#include <linux/lualib.h>
#include <linux/lauxlib.h>
#include "auxlib.h"
#include "lsm.h"
#include "kvcache.h"

static atomic_t node_nalloc = ATOMIC_INIT(0);
static atomic_t node_nfree = ATOMIC_INIT(0);

static int kvcache_node_cmp(struct kvcache_node *n1, struct kvcache_node *n2)
{
	int n = strcmp(n1->key, n2->key);
	if (n != 0)
		return n;
	return (char *)n1->module - (char *)n2->module;
}
RB_GENERATE_STATIC(kvcache, kvcache_node, node, kvcache_node_cmp);


static int kvcache_result(lua_State *L, int err, int nresults)
{
	const char *error = "unknown error";

	if (err >= 0)
		return nresults;

	switch (err) {
	case -ENOMEM:	error = "no memory";		break;
	case -EINVAL:	error = "invalid value";	break;
	case -ERANGE:	error = "no space";		break;
	case -ENOENT:	error = "no module";		break;
	}
	lua_pushnil(L);
	lua_pushstring(L, error);
	return 2;
}

static struct kvcache_node *
kvcache_lookup(struct kvcache_dict *dict,
	struct lua_module *module, const char *key)
{
	struct kvcache_node tmp;
	tmp.key = key;
	tmp.module = module;
	return RB_FIND(kvcache, &dict->root, &tmp);
}

static struct kvcache_node *
kvcache_node_alloc(struct kvcache_dict *dict, struct lua_module *module,
		const char *key, size_t len)
{
	size_t l = sizeof(struct kvcache_node);
	struct kvcache_node *node;

	l += key ? (len + 1) : 0;
	node = kmalloc(l, GFP_KERNEL);
	if (node == NULL)
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
	atomic_inc(&node_nalloc);
	return node;
}

#define kvcache_value_alloc()	kvcache_node_alloc(NULL, NULL, NULL, 0)

static void kvcache_node_free(struct kvcache_node *node);
static int kvcache_node_fill(lua_State *L, int idx, struct kvcache_node *node);

static void kvcache_node_clear(struct kvcache_node *node)
{
	struct kvcache_node *n, *tmp;
	switch (node->tt) {
	case LUA_TBOOLEAN:
	case LUA_TNUMBER:
	case LUA_TLIGHTUSERDATA:
		break;
	case LUA_TSTRING:
		kfree(node->s.s);
		break;
	case LUA_TTABLE:
		TAILQ_FOREACH_SAFE(n, &node->q.h, qlist, tmp) {
			TAILQ_REMOVE(&node->q.h, n, qlist);
			node->q.l -= 1;
			kvcache_node_free(n);
		}
		WARN_ON(node->q.l != 0);
		break;
	}
	node->tt = LUA_TNIL;
}

static void kvcache_node_free(struct kvcache_node *node)
{
	if (node->module) {
		unsigned long flags;
		spin_lock_irqsave(&node->module->kvnodes_lock, flags);
		TAILQ_REMOVE(&node->module->kvnodes, node, modlist);
		spin_unlock_irqrestore(&node->module->kvnodes_lock, flags);
	}
	kvcache_node_clear(node);
	atomic_inc(&node_nfree);
	kfree(node);
}

static void
kvcache_module_link(struct kvcache_dict *dict, struct lua_module *module,
		struct kvcache_node *node)
{
	RB_INSERT(kvcache, &dict->root, node);
	atomic_inc(&dict->count);
	if (module) {
		unsigned long flags;
		spin_lock_irqsave(&module->kvnodes_lock, flags);
		TAILQ_INSERT_TAIL(&module->kvnodes, node, modlist);
		spin_unlock_irqrestore(&module->kvnodes_lock, flags);
	}
}

static void
kvcache_module_unlink(struct kvcache_dict *dict, struct lua_module *module,
		struct kvcache_node *node)
{
	RB_REMOVE(kvcache, &dict->root, node);
	atomic_dec(&dict->count);
	if (module) {
		unsigned long flags;
		spin_lock_irqsave(&module->kvnodes_lock, flags);
		TAILQ_REMOVE(&module->kvnodes, node, modlist);
		spin_unlock_irqrestore(&module->kvnodes_lock, flags);
	}
}

static int
kvcache_qnode_new(lua_State *L, int idx, struct kvcache_node *head, int left)
{
	struct kvcache_node *node;
	int err;

	node = kvcache_value_alloc();
	if (node == NULL)
		return -ENOMEM;

	err = kvcache_node_fill(L, idx, node);
	if (err) {
		kvcache_node_free(node);
		return err;
	}

	if (left)
		TAILQ_INSERT_HEAD(&head->q.h, node, qlist);
	else
		TAILQ_INSERT_TAIL(&head->q.h, node, qlist);

	head->q.l += 1;
	return 0;
}

static int kvcache_node_fill(lua_State *L, int idx, struct kvcache_node *node)
{
	const char *s;
	int tidx;
	int err = 0;

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
		s = lua_tolstring(L, idx, &node->s.l);
		node->s.s = kmalloc(node->s.l + 1, GFP_KERNEL);
		if (node->s.s == NULL)
			return -ENOMEM;
		memcpy((void *)node->s.s, s, node->s.l + 1/* ending 0 */);
		break;

	case LUA_TTABLE:
		TAILQ_INIT(&node->q.h);
		node->q.l = 0;
		tidx = idx > 0 ? idx : idx - 1;
		lua_pushnil(L);
		while (lua_next(L, tidx) != 0) {
			/* uses 'key' (at index -2) and 'value' (at index -1) */
			err = kvcache_qnode_new(L, -1, node, 0);
			if (err)
				break;

			/* removes 'value'; keeps 'key' for next iteration */
			lua_pop(L, 1);
		}
		if (err) {
			kvcache_node_clear(node);
			/* removes 'key' and 'value' */
			lua_pop(L, 2);
			return err;
		}
		break;

	default:
		return -EINVAL;
	}
	return 0;
}

static int kvcache_node_refill(lua_State *L, int idx, struct kvcache_node *node)
{
	struct kvcache_node ntmp;
	int err;

	err = kvcache_node_fill(L, idx, &ntmp);
	if (err)
		return err;

	kvcache_node_clear(node);

	node->tt = ntmp.tt;
	switch (node->tt) {
	case LUA_TBOOLEAN:
		node->b = ntmp.b;
		break;
	case LUA_TNUMBER:
		node->n = ntmp.n;
		break;
	case LUA_TLIGHTUSERDATA:
		node->p = ntmp.p;
		break;
	case LUA_TSTRING:
		node->s.s = ntmp.s.s;
		node->s.l = ntmp.s.l;
		break;
	case LUA_TTABLE:
		TAILQ_INIT(&node->q.h);
		TAILQ_SWAP(&node->q.h, &ntmp.q.h, kvcache_node, qlist);
		node->q.l = ntmp.q.l;
		break;
	}
	return 0;
}

static int
kvcache_set(lua_State *L, struct kvcache_dict *dict, struct lua_module *module)
{
	size_t len;
	const char *key = luaL_checklstring(L, 2, &len);
	int tt = lua_type(L, 3);
	struct kvcache_node *node;
	int err = 0;

	write_lock(&dict->lock);
	node = kvcache_lookup(dict, module, key);
	if (node) {
		if (tt == LUA_TNIL) {
			kvcache_module_unlink(dict, module, node);
			kvcache_node_free(node);
		} else {
			err = kvcache_node_refill(L, 3, node);
		}
		goto unlock;
	}

	if (tt == LUA_TNIL)
		goto unlock;

	err = -ERANGE;
	if (atomic_read(&dict->count) >= dict->capacity)
		goto unlock;

	err = -ENOMEM;
	node = kvcache_node_alloc(dict, module, key, len);
	if (node == NULL)
		goto unlock;

	err = kvcache_node_fill(L, 3, node);
	if (err) {
		kvcache_node_free(node);
		goto unlock;
	}

	kvcache_module_link(dict, module, node);

unlock:
	write_unlock(&dict->lock);

	if (!err)
		lua_pushboolean(L, 1);

	return kvcache_result(L, err, 1);
}

static int kvcache_node_get(lua_State *L, struct kvcache_node *node)
{
	struct kvcache_node *n;
	int idx = 1;

	switch (node->tt) {
	case LUA_TBOOLEAN:
		lua_pushboolean(L, node->b);
		break;
	case LUA_TNUMBER:
		lua_pushnumber(L, node->n);
		break;
	case LUA_TLIGHTUSERDATA:
		lua_pushlightuserdata(L, node->p);
		break;
	case LUA_TSTRING:
		lua_pushlstring(L, node->s.s, node->s.l);
		break;
	case LUA_TTABLE:
		lua_createtable(L, node->q.l, 0);
		TAILQ_FOREACH(n, &node->q.h, qlist) {
			kvcache_node_get(L, n);
			lua_rawseti(L, -2, idx++);
		}
		break;
	default:
		WARN_ON(1);
		return -EINVAL;
	}
	return 0;
}

static int
kvcache_get(lua_State *L, struct kvcache_dict *dict, struct lua_module *module)
{
	const char *key = luaL_checkstring(L, 2);
	struct kvcache_node *node;

	read_lock(&dict->lock);
	node = kvcache_lookup(dict, module, key);
	if (node)
		kvcache_node_get(L, node);
	else
		lua_pushnil(L);
	read_unlock(&dict->lock);
	return 1;
}

static int
kvcache_incr(lua_State *L, struct kvcache_dict *dict, struct lua_module *module)
{
	size_t len;
	const char *key = luaL_checklstring(L, 2, &len);
	lua_Number n = luaL_optnumber(L, 3, 1);
	struct kvcache_node *node;
	int err = 0;

	write_lock(&dict->lock);
	node = kvcache_lookup(dict, module, key);
	if (node) {
		if (node->tt == LUA_TNUMBER) {
			node->n += n;
			lua_pushnumber(L, node->n);
		} else {
			err = -EINVAL;
		}
		goto unlock;
	}

	err = -ERANGE;
	if (atomic_read(&dict->count) >= dict->capacity)
		goto unlock;

	err = -ENOMEM;
	node = kvcache_node_alloc(dict, module, key, len);
	if (node == NULL)
		goto unlock;

	node->n = n;
	node->tt = LUA_TNUMBER;
	kvcache_module_link(dict, module, node);
	lua_pushnumber(L, node->n);
	err = 0;

unlock:
	write_unlock(&dict->lock);

	return kvcache_result(L, err, 1);
}

static int
kvcache_qnode_append(lua_State *L, int from, struct kvcache_node *head, int left)
{
	int top = lua_gettop(L);
	int nres = 0;
	int err;

	for ( ; from <= top; from++) {
		err = kvcache_qnode_new(L, from, head, left);
		if (err) {
			__log_err("qnode_new: from = %d, err = %d\n", from, err);
			break;
		}
		nres += 1;
	}
	return nres;
}

static int kvcache_push(lua_State *L, struct kvcache_dict *dict,
			struct lua_module *module, int left)
{
	size_t len;
	const char *key = luaL_checklstring(L, 2, &len);
	struct kvcache_node *node;
	int nres;
	int err = 0;

	write_lock(&dict->lock);
	node = kvcache_lookup(dict, module, key);
	if (node) {
		if (node->tt == LUA_TTABLE) {
			nres = kvcache_qnode_append(L, 3, node, left);
			lua_pushinteger(L, nres);
		} else {
			err = -EINVAL;
		}
		goto unlock;
	}

	err = -ERANGE;
	if (atomic_read(&dict->count) >= dict->capacity)
		goto unlock;

	err = -ENOMEM;
	node = kvcache_node_alloc(dict, module, key, len);
	if (node == NULL)
		goto unlock;

	node->tt = LUA_TTABLE;
	node->q.l = 0;
	TAILQ_INIT(&node->q.h);
	nres = kvcache_qnode_append(L, 3, node, left);

	kvcache_module_link(dict, module, node);

	lua_pushinteger(L, nres);
	err = 0;

unlock:
	write_unlock(&dict->lock);

	return kvcache_result(L, err, 1);
}

static int
kvcache_qnode_pop(lua_State *L, int npop, struct kvcache_node *head, int left)
{
	struct kvcache_node *node;
	int nres = 0;

	while (head->q.l > 0 && npop-- > 0) {
		WARN_ON(TAILQ_EMPTY(&head->q.h));

		if (left)
			node = TAILQ_FIRST(&head->q.h);
		else
			node = TAILQ_LAST_FAST(&head->q.h, kvcache_node, qlist);

		TAILQ_REMOVE(&head->q.h, node, qlist);
		head->q.l -= 1;
		kvcache_node_get(L, node);
		kvcache_node_free(node);
		nres += 1;
	}
	return nres;
}

static int kvcache_pop(lua_State *L, struct kvcache_dict *dict,
			struct lua_module *module, int left)
{
	const char *key = luaL_checkstring(L, 2);
	int npop = luaL_optint(L, 3, 1);
	struct kvcache_node *node;
	int nres = 0;
	int err = 0;

	write_lock(&dict->lock);
	node = kvcache_lookup(dict, module, key);
	if (node) {
		if (node->tt == LUA_TTABLE)
			nres = kvcache_qnode_pop(L, npop, node, left);
		else
			err = -EINVAL;
	}
	write_unlock(&dict->lock);
	return kvcache_result(L, err, nres);
}

static int kvcache_llen(lua_State *L, struct kvcache_dict *dict,
			struct lua_module *module)
{
	const char *key = luaL_checkstring(L, 2);
	struct kvcache_node *node;
	int err = 0;

	read_lock(&dict->lock);
	node = kvcache_lookup(dict, module, key);
	if (node) {
		if (node->tt == LUA_TTABLE)
			lua_pushinteger(L, node->q.l);
		else
			err = -EINVAL;
	}
	read_unlock(&dict->lock);
	return kvcache_result(L, err, 1);
}

void kvcache_module_nodes_gc(struct lua_module *module)
{
	TAILQ_HEAD(, kvcache_node) cleanup_list;
	struct kvcache_node *node, *tmp;
	unsigned long flags;

	TAILQ_INIT(&cleanup_list);
	spin_lock_irqsave(&module->kvnodes_lock, flags);
	TAILQ_SWAP(&module->kvnodes, &cleanup_list, kvcache_node, modlist);
	spin_unlock_irqrestore(&module->kvnodes_lock, flags);

	TAILQ_FOREACH_SAFE(node, &cleanup_list, modlist, tmp) {
		struct kvcache_dict *dict = node->dict;

		WARN_ON(!dict);
		write_lock(&dict->lock);
		RB_REMOVE(kvcache, &dict->root, node);
		write_unlock(&dict->lock);
		atomic_dec(&dict->count);

		TAILQ_REMOVE(&cleanup_list, node, modlist);
		kvcache_node_free(node);
	}
}

void kvcache_dict_free(struct kvcache_dict *dict)
{
	struct kvcache_node *node, *n;

	write_lock(&dict->lock);
	RB_FOREACH_SAFE(node, kvcache, &dict->root, n) {
		RB_REMOVE(kvcache, &dict->root, node);
		kvcache_node_free(node);
		atomic_dec(&dict->count);
	}
	WARN_ON(atomic_read(&dict->count) != 0);
	write_unlock(&dict->lock);
}

void kvcache_dict_init(struct kvcache_dict *dict)
{
	rwlock_init(&dict->lock);
	RB_INIT(&dict->root);
	atomic_set(&dict->count, 0);
	dict->capacity = CACHE_CAPACITY;
}

void kvcache_status(int *nalloc, int *nfree)
{
	if (nalloc)
		*nalloc = atomic_read(&node_nalloc);
	if (nfree)
		*nfree = atomic_read(&node_nfree);
}

/******************************** object cache *******************************/

const int _module_sentinel;

static inline struct lua_module *module_from_object_fenv(lua_State *L, int idx)
{
	struct lua_module *module;

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
	struct lua_module *module;

	module = module_from_object_fenv(L, 1);
	if (module == NULL)
		return 0;
	return kvcache_get(L, dict, module);
}

int lua_object_incr(lua_State *L, struct kvcache_dict *dict)
{
	struct lua_module *module;

	module = module_from_object_fenv(L, 1);
	if (module == NULL)
		return kvcache_result(L, -ENOENT, 0);

	return kvcache_incr(L, dict, module);
}

int lua_object_lpush(lua_State *L, struct kvcache_dict *dict)
{
	struct lua_module *module;

	module = module_from_object_fenv(L, 1);
	if (module == NULL)
		return kvcache_result(L, -ENOENT, 0);

	return kvcache_push(L, dict, module, 1);
}

int lua_object_rpush(lua_State *L, struct kvcache_dict *dict)
{
	struct lua_module *module;

	module = module_from_object_fenv(L, 1);
	if (module == NULL)
		return kvcache_result(L, -ENOENT, 0);

	return kvcache_push(L, dict, module, 0);
}

int lua_object_lpop(lua_State *L, struct kvcache_dict *dict)
{
	struct lua_module *module;

	module = module_from_object_fenv(L, 1);
	if (module == NULL)
		return kvcache_result(L, -ENOENT, 0);

	return kvcache_pop(L, dict, module, 1);
}

int lua_object_rpop(lua_State *L, struct kvcache_dict *dict)
{
	struct lua_module *module;

	module = module_from_object_fenv(L, 1);
	if (module == NULL)
		return kvcache_result(L, -ENOENT, 0);

	return kvcache_pop(L, dict, module, 0);
}

int lua_object_llen(lua_State *L, struct kvcache_dict *dict)
{
	struct lua_module *module;

	module = module_from_object_fenv(L, 1);
	if (module == NULL)
		return kvcache_result(L, -ENOENT, 0);

	return kvcache_llen(L, dict, module);
}

/*
 *	__index = function(object, key)
 *		local mt = getmetatable(object)
 *		if not mt then
 *			return nil
 *		end
 *		local v = mt[key]
 *		if v then
 *			return v
 *		end
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
	lua_pushvalue(L, 2);
	lua_rawget(L, -2);		/* metatable[key] */
	if (!lua_isnoneornil(L, -1))
		return 1;

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
	struct lua_module *module;

	module = module_from_object_fenv(L, 1);
	if (module == NULL)
		return kvcache_result(L, -ENOENT, 0);
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

static int shdict_lpush(lua_State *L)
{
	struct kvcache_dict *shdict = toshdict(L, 1);
	return kvcache_push(L, shdict, NULL, 1);
}

static int shdict_rpush(lua_State *L)
{
	struct kvcache_dict *shdict = toshdict(L, 1);
	return kvcache_push(L, shdict, NULL, 0);
}

static int shdict_lpop(lua_State *L)
{
	struct kvcache_dict *shdict = toshdict(L, 1);
	return kvcache_pop(L, shdict, NULL, 1);
}

static int shdict_rpop(lua_State *L)
{
	struct kvcache_dict *shdict = toshdict(L, 1);
	return kvcache_pop(L, shdict, NULL, 0);
}

static int shdict_llen(lua_State *L)
{
	struct kvcache_dict *shdict = toshdict(L, 1);
	return kvcache_llen(L, shdict, NULL);
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
	read_lock(&shdict->lock);
	lua_pushfstring(L, "shdict (%d / %d)",
			atomic_read(&shdict->count), shdict->capacity);
	read_unlock(&shdict->lock);
	return 1;
}

static int shdict_gc(lua_State *L)
{
	__log_info("shdict already freed by unregister\n");
	return 0;
}

static const luaL_Reg shdict_meth[] = {
	{ "set",	shdict_set	},
	{ "get",	shdict_get	},
	{ "incr",	shdict_incr	},
	{ "lpush",	shdict_lpush	},
	{ "rpush",	shdict_rpush	},
	{ "lpop",	shdict_lpop	},
	{ "rpop",	shdict_rpop	},
	{ "llen",	shdict_llen	},
	{ "__index",	shdict_index	},
	{ "__newindex",	shdict_set	},
	{ "__tostring",	shdict_tostring	},
	{ "__gc",	shdict_gc	},
	{ NULL, NULL }
};

int shdict_init(lua_State *L)
{
	createmeta(L, METH_SHARED_DICT, shdict_meth, 1, 1);
	return 0;
}
