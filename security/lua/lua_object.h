/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#ifndef _SECURITY_LUA_LSM_LUA_OBJECT_H
#define _SECURITY_LUA_LSM_LUA_OBJECT_H

#include <linux/stddef.h>
#include "auxlib.h"
#include "lsm.h"
#include "kvcache.h"

#define CURR_ENV	"_CURR_ENV"

#define METHOD_NAME(name)	("method." #name)
#define METHOD_NAME_RAW(name)	("method." #name ".raw")
#define METHOD_NAME_GC(name)	("method." #name ".gc")

#define LUA_OBJECT_META_DEFINE(name, ctype, d, metaname)					\
	static inline ctype *new ## name ## _nomain(lua_State *L)				\
	{											\
		ctype *p = (ctype *)lua_newuserdata(L, sizeof(ctype));				\
		*p = d;										\
		luaL_getmetatable(L, metaname);							\
		lua_setmetatable(L, -2);							\
		return p;									\
	}											\
	/* Calling from the Main chunk requires setting the correct fenv. */			\
	static inline ctype *new ## name(lua_State *L)						\
	{											\
		ctype *p = new ## name ## _nomain(L);						\
		lua_getfield(L, LUA_REGISTRYINDEX, CURR_ENV);					\
		lua_setfenv(L, -2);								\
		return p;									\
	}											\
	static inline ctype *to ## name ## p(lua_State *L, int idx)				\
	{											\
		return (ctype *)checkudata3(L, idx, metaname);					\
	}											\
	static inline ctype to ## name(lua_State *L, int idx)					\
	{											\
		return *to ## name ## p(L, idx);						\
	}											\
	static inline ctype *checkudata_ ## name(lua_State *L, int idx)				\
	{											\
		return (ctype *)checkudata(L, idx, metaname);					\
	}

#define LUA_OBJECT_KVCACHE_FUNC(name, ctype, blob, method, fname)				\
	static int rawmeth_ ## name ## _ ## method(lua_State *L)				\
	{											\
		ctype p = toraw ## name(L, 1);							\
		struct lua_lsm_ ## blob *ll = lua_lsm_ ## name(p);				\
		return lua_object_ ## fname(L, ll ? &ll->dict : NULL);				\
	}

#define LUA_OBJECT_FUNCS_DEFINE(name, ctype, has_kvcache)					\
	static int rawmeth_ ## name ## _type(lua_State *L)					\
	{											\
		lua_pushstring(L, #name);							\
		lua_pushboolean(L, has_kvcache);						\
		return 2;									\
	}											\
	static int rawmeth_ ## name ## _tostring(lua_State *L)					\
	{											\
		ctype o = toraw ## name(L, 1);							\
		lua_pushfstring(L, #name ": <%p>", o);						\
		return 1;									\
	}

#define LUA_OBJECT_BLOB_FUNCS_DEFINE(name, ctype, d, blob)					\
	LUA_OBJECT_META_DEFINE(name, ctype, d, METHOD_NAME(name))				\
	LUA_OBJECT_META_DEFINE(raw ## name, ctype, d, METHOD_NAME_RAW(name))			\
	LUA_OBJECT_META_DEFINE(gc ## name, ctype, d, METHOD_NAME_GC(name))			\
	LUA_OBJECT_KVCACHE_FUNC(name, ctype, blob, kvcache_get, get)				\
	LUA_OBJECT_KVCACHE_FUNC(name, ctype, blob, kvcache_incr, incr)				\
	LUA_OBJECT_KVCACHE_FUNC(name, ctype, blob, index, index)				\
	LUA_OBJECT_KVCACHE_FUNC(name, ctype, blob, newindex, newindex)				\
	LUA_OBJECT_FUNCS_DEFINE(name, ctype, 1)							\
	static inline void create_ ## name ## _meta(lua_State *L,				\
				const luaL_Reg *funcs, const luaL_Reg *gc)			\
	{											\
		static const luaL_Reg basemeths[] = {						\
			{ "__index",		rawmeth_ ## name ## _index		},	\
			{ "__newindex",		rawmeth_ ## name ## _newindex		},	\
			{ "__tostring",		rawmeth_ ## name ## _tostring		},	\
			{ NULL, NULL }								\
		};										\
		static const luaL_Reg rawmeths[] = {						\
			{ "kvcache_set",	rawmeth_ ## name ## _newindex		},	\
			{ "kvcache_get",	rawmeth_ ## name ## _kvcache_get	},	\
			{ "kvcache_incr",	rawmeth_ ## name ## _kvcache_incr	},	\
			{ "type",		rawmeth_ ## name ## _type		},	\
			{ NULL, NULL }								\
		};										\
		createmeta3(L, #name, basemeths, METHOD_NAME_GC(name), gc,			\
			METHOD_NAME(name), funcs, METHOD_NAME_RAW(name), rawmeths);		\
	}

#define LUA_OBJECT_func_DEFINE(name, ctype, d)							\
	LUA_OBJECT_META_DEFINE(name, ctype, d, METHOD_NAME(name))				\
	LUA_OBJECT_META_DEFINE(raw ## name, ctype, d, METHOD_NAME_RAW(name))			\
	LUA_OBJECT_META_DEFINE(gc ## name, ctype, d, METHOD_NAME_GC(name))			\
	LUA_OBJECT_FUNCS_DEFINE(name, ctype, 0)							\
	static inline void create_ ## name ## _meta(lua_State *L,				\
				const luaL_Reg *funcs, const luaL_Reg *gc)			\
	{											\
		static const luaL_Reg basemeths[] = {						\
			{ "__tostring",		rawmeth_ ## name ## _tostring		},	\
			{ NULL, NULL }								\
		};										\
		static const luaL_Reg rawmeths[] = {						\
			{ "type",		rawmeth_ ## name ## _type		},	\
			{ NULL, NULL }								\
		};										\
		createmeta3(L, #name, basemeths, METHOD_NAME_GC(name), gc,			\
			METHOD_NAME(name), funcs, METHOD_NAME_RAW(name), rawmeths);		\
	}

#define LUA_OBJECT_task_DEFINE(name, ctype, d)							\
	LUA_OBJECT_BLOB_FUNCS_DEFINE(name, ctype, d, task)
#define LUA_OBJECT_object_DEFINE(name, ctype, d)						\
	LUA_OBJECT_BLOB_FUNCS_DEFINE(name, ctype, d, object)


#define LUA_OBJECTS_LIST									\
	LUA_OBJECT(task,	kernel,		task,		struct task_struct *,	NULL)	\
	LUA_OBJECT(object,	kernel,		cred,		struct cred *,		NULL)	\
	LUA_OBJECT(func,	kernel,		perfevent,	struct perf_event *,	NULL)	\
	LUA_OBJECT(object,	ipc,		ipc,		struct kern_ipc_perm *,	NULL)	\
	LUA_OBJECT(object,	ipc,		msgmsg,		struct msg_msg *,	NULL)	\
	LUA_OBJECT(object,	net,		sock,		struct sock *,		NULL)	\
	LUA_OBJECT(func,	net,		ib,		void *,			NULL)	\
	LUA_OBJECT(func,	net,		tundev,		void *,			NULL)	\
	LUA_OBJECT(func,	net,		socket,		struct socket *,	NULL)	\
	LUA_OBJECT(func,	net,		skb,		struct sk_buff *,	NULL)	\
	LUA_OBJECT(func,	net,		sockaddr,	struct sockaddr *,	NULL)	\
	LUA_OBJECT(func,	security,	key,		struct key *,		NULL)	\
	LUA_OBJECT(object,	block,		bdev,		struct block_device *,	NULL)	\
	LUA_OBJECT(object,	fs,		inode,		struct inode *,		NULL)	\
	LUA_OBJECT(object,	fs,		file,		struct file *,		NULL)	\
	LUA_OBJECT(object,	fs,		superblock,	struct super_block *,	NULL)	\
	LUA_OBJECT(func,	fs,		dentry,		struct dentry *,	NULL)	\
	LUA_OBJECT(func,	fs,		binprm,		struct linux_binprm *,	NULL)	\
	LUA_OBJECT(func,	fs,		path,		struct path *,		NULL)	\
	LUA_OBJECT(func,	fs,		fscontext,	struct fs_context *,	NULL)	\
	LUA_OBJECT(func,	fs,		vfsmount,	struct vfsmount *,	NULL)	\
	LUA_OBJECT(func,	fs,		mntidmap,	struct mnt_idmap *,	NULL)	\
	LUA_OBJECT(func,	kernel,		cap,		kernel_cap_t,	CAP_EMPTY_SET)


#define LUA_OBJECT(blob, class, name, ctype, d)							\
	LUA_OBJECT_ ## blob ## _DEFINE(name, ctype, d)
LUA_OBJECTS_LIST
#undef LUA_OBJECT

#endif  /* ! _SECURITY_LUA_LSM_LUA_OBJECT_H */
