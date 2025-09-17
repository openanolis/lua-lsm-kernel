/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#ifndef _SECURITY_LUA_LSM_LSM_H
#define _SECURITY_LUA_LSM_LSM_H

#include <linux/list.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/msg.h>
#include <net/sock.h>
#include <linux/lsm_hooks.h>
#include <linux/spinlock.h>
#include <linux/lua.h>
#include "bitmap.h"
#include "kvcache.h"

/* Flag indicating whether initialization completed */
extern int lua_lsm_initialized __initdata;

#define LUA_LSM_VERSION		1


struct lua_lsm_hook_stat {
	const char *name;
	atomic_t nhooks;
#ifdef CONFIG_SECURITY_LUA_LSM_STATS
	atomic_t count;
	atomic64_t time;        /* ns */
	atomic64_t maxtime;
#endif
};

extern struct lua_lsm_hook_stat lua_lsm_hook_stats[];


#define LSM_HOOK(RET, DEFAULT, NAME, ...)				\
	int __prepare_ ## NAME(__VA_ARGS__);				\
	void __postpone_ ## NAME(__VA_ARGS__);

#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK


enum {
	#define LSM_HOOK(RET, DEFAULT, NAME, ...)	__LL_NR_ ## NAME,
	#include <linux/lsm_hook_defs.h>
	#undef LSM_HOOK
	__LL_NR_MAX
};

struct lua_module_shdict {
	struct list_head list;
	struct kvcache_dict dict;
	char name[];
};

struct lua_module {
	const char *name;
	const char *author;
	const char *description;
	const char *license;
	int version;
	struct list_head list;
	__BITMAP_TYPE(, uint32_t, __LL_NR_MAX) hookfuncs;
	int nhooks;
	char *chunk;
	size_t chunk_len;
	struct list_head shdicts;
	spinlock_t shdict_lock;
	atomic_t shdict_count;
	struct list_head kvnodes;
	spinlock_t kvnodes_lock;
};

extern struct list_head lsm_modules;
extern struct srcu_struct modules_ss;


#define TABLINE	"--------------------------------------------"		\
		"--------------------------------------------"

int lua_module_register(const char *code, size_t len);
int lua_module_unregister(const char *name);

int modules_show(struct seq_file *m, void *v);

#ifdef CONFIG_SECURITY_LUA_LSM_STATS
int lua_lsm_status_show(struct seq_file *m, void *v);
int lsmhook_stat_show(struct seq_file *m, void *v);
#endif


extern struct lsm_blob_sizes lua_lsm_blob_sizes;

struct lua_lsm_task {
	lua_State *L;
	struct kvcache_dict dict;
};

static inline struct lua_lsm_task *lua_lsm_task(const struct task_struct *task)
{
	return task->security + lua_lsm_blob_sizes.lbs_task;
}

/* common object */

struct lua_lsm_object {
	struct kvcache_dict dict;
};

static inline struct lua_lsm_object *lua_lsm_cred(const struct cred *cred)
{
	return cred->security + lua_lsm_blob_sizes.lbs_cred;
}

static inline struct lua_lsm_object *lua_lsm_file(const struct file *file)
{
	return file->f_security + lua_lsm_blob_sizes.lbs_file;
}

static inline struct lua_lsm_object *lua_lsm_ib(void *ib_sec)
{
	return ib_sec + lua_lsm_blob_sizes.lbs_ib;
}

static inline struct lua_lsm_object *lua_lsm_inode(const struct inode *inode)
{
	if (unlikely(!inode->i_security))
		return NULL;
	return inode->i_security + lua_lsm_blob_sizes.lbs_inode;
}

static inline struct lua_lsm_object *lua_lsm_inode_rcu(void *inode_security)
{
	return inode_security + lua_lsm_blob_sizes.lbs_inode;
}

static inline struct lua_lsm_object *lua_lsm_sock(const struct sock *sock)
{
	return sock->sk_security + lua_lsm_blob_sizes.lbs_sock;
}

static inline struct lua_lsm_object *lua_lsm_superblock(const struct super_block *superblock)
{
	return superblock->s_security + lua_lsm_blob_sizes.lbs_superblock;
}

static inline struct lua_lsm_object *lua_lsm_ipc(const struct kern_ipc_perm *ipc)
{
	return ipc->security + lua_lsm_blob_sizes.lbs_ipc;
}

static inline struct lua_lsm_object *lua_lsm_key(const struct key *key)
{
	return key->security + lua_lsm_blob_sizes.lbs_key;
}

static inline struct lua_lsm_object *lua_lsm_msgmsg(const struct msg_msg *msg)
{
	return msg->security + lua_lsm_blob_sizes.lbs_msg_msg;
}

static inline struct lua_lsm_object *lua_lsm_perfevent(void *perf_event)
{
	return perf_event + lua_lsm_blob_sizes.lbs_perf_event;
}

static inline struct lua_lsm_object *lua_lsm_tun_dev(void *security)
{
	return security + lua_lsm_blob_sizes.lbs_tun_dev;
}

static inline struct lua_lsm_object *lua_lsm_bdev(const struct block_device *bdev)
{
	return bdev->bd_security + lua_lsm_blob_sizes.lbs_bdev;
}

int lua_task_blob_init(struct task_struct *task);
void lua_task_blob_free(struct task_struct *task);

/* lua C module */

int luaopen_kernel(lua_State *L);
int luaopen_fs(lua_State *L);
int luaopen_net(lua_State *L);
int luaopen_errno(lua_State *L);
int luaopen_capability(lua_State *L);
int luaopen_signal(lua_State *L);

#endif  /* ! _SECURITY_LUA_LSM_LSM_H */
