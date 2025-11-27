/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#ifndef _SECURITY_LUA_LSM_LUA_OBJECT_H
#define _SECURITY_LUA_LSM_LUA_OBJECT_H

#include "auxlib.h"

#define METHOD_NAME(class, name)	("method." #class "." #name)

#define LUA_OBJECT_DEFINE(class, name, ctype, d)						\
	static inline ctype *new ## name(lua_State *L)						\
	{											\
		ctype *p = (ctype *)lua_newuserdata(L, sizeof(ctype));				\
		*p = d;										\
		luaL_getmetatable(L, METHOD_NAME(class, name));					\
		lua_setmetatable(L, -2);							\
		return p;									\
	}											\
	static inline ctype *to ## name ## p(lua_State *L, int idx)				\
	{											\
		return (ctype *)luaL_checkudata(L, idx, METHOD_NAME(class, name));		\
	}											\
	static inline ctype to ## name(lua_State *L, int idx)					\
	{											\
		return *to ## name ## p(L, idx);						\
	}											\
	static inline ctype *checkudata_ ## name(lua_State *L, int idx)				\
	{											\
		return (ctype *)checkudata(L, idx, METHOD_NAME(class, name));			\
	}											\
	static int class ## _ ## name ## _tostring(lua_State *L)				\
	{											\
		ctype o = to ## name(L, 1);							\
		lua_pushfstring(L, #name " (%p)", o);						\
		return 1;									\
	}

#define LUA_OBJECT_KVCACHE_FUNC(class, name, ctype, blob, method, fname)			\
	static int class ## _ ## name ## _ ## method(lua_State *L)				\
	{											\
		ctype p = to ## name(L, 1);							\
		struct lua_lsm_ ## blob *ll = lua_lsm_ ## name(p);				\
		return lua_object_ ## fname(L, &ll->dict);					\
	}

#define LUA_OBJECT_BLOB_FUNCS_DEFINE(class, name, ctype, d, blob)				\
	LUA_OBJECT_DEFINE(class, name, ctype, d)						\
	LUA_OBJECT_KVCACHE_FUNC(class, name, ctype, blob, kvcache_get, get)			\
	LUA_OBJECT_KVCACHE_FUNC(class, name, ctype, blob, kvcache_incr, incr)			\
	LUA_OBJECT_KVCACHE_FUNC(class, name, ctype, blob, index, index)				\
	LUA_OBJECT_KVCACHE_FUNC(class, name, ctype, blob, newindex, newindex)			\
	static inline void create_ ## name ## _meta(lua_State *L,				\
						const luaL_Reg *funcs)				\
	{											\
		static const luaL_Reg object_meth[] = {						\
			{ "kvcache_set",	class ## _ ## name ## _newindex		},	\
			{ "kvcache_get",	class ## _ ## name ## _kvcache_get	},	\
			{ "kvcache_incr",	class ## _ ## name ## _kvcache_incr	},	\
			{ "__index",		class ## _ ## name ## _index		},	\
			{ "__newindex",		class ## _ ## name ## _newindex		},	\
			{ "__tostring",		class ## _ ## name ## _tostring		},	\
			{ NULL, NULL }								\
		};										\
		createmeta(L, METHOD_NAME(class, name), object_meth, 0, 0);			\
		if (funcs)									\
			luaL_register(L, NULL, funcs);						\
		lua_pop(L, 1);									\
	}

#define LUA_OBJECT_func_DEFINE(class, name, ctype, d)						\
	LUA_OBJECT_DEFINE(class, name, ctype, d)						\
	static inline void create_ ## name ## _meta(lua_State *L,				\
						const luaL_Reg *funcs)				\
	{											\
		createmeta(L, METHOD_NAME(class, name), NULL, 1, 0);				\
		lua_pushcfunction(L, class ## _ ## name ## _tostring);				\
		lua_setfield(L, -2, "__tostring");	/* mt.__tostring = func */		\
		if (funcs)									\
			luaL_register(L, NULL, funcs);						\
		lua_pop(L, 1);									\
	}

#define LUA_OBJECT_task_DEFINE(class, name, ctype, d)						\
	LUA_OBJECT_BLOB_FUNCS_DEFINE(class, name, ctype, d, task)
#define LUA_OBJECT_object_DEFINE(class, name, ctype, d)						\
	LUA_OBJECT_BLOB_FUNCS_DEFINE(class, name, ctype, d, object)


#define LUA_OBJECTS_LIST									\
	LUA_OBJECT(task,	kernel,		task,		struct task_struct *,	NULL)	\
	LUA_OBJECT(object,	kernel,		cred,		struct cred *,		NULL)	\
	LUA_OBJECT(object,	kernel,		perfevent,	struct perf_event *,	NULL)	\
	LUA_OBJECT(object,	ipc,		ipc,		struct kern_ipc_perm *,	NULL)	\
	LUA_OBJECT(object,	ipc,		msgmsg,		struct msg_msg *,	NULL)	\
	LUA_OBJECT(object,	net,		sock,		struct sock *,		NULL)	\
	LUA_OBJECT(func,	net,		socket,		struct socket *,	NULL)	\
	LUA_OBJECT(func,	net,		skb,		struct sk_buff *,	NULL)	\
	LUA_OBJECT(func,	net,		sockaddr,	struct sockaddr *,	NULL)	\
	LUA_OBJECT(object,	security,	key,		struct key *,		NULL)	\
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
	LUA_OBJECT_ ## blob ## _DEFINE(class, name, ctype, d)
LUA_OBJECTS_LIST
#undef LUA_OBJECT

#endif  /* ! _SECURITY_LUA_LSM_LUA_OBJECT_H */
