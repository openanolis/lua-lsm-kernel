/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#define pr_fmt(fmt) "lsm-defs: " fmt

#include "debug.h"
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/compiler.h>
#include <linux/rwlock.h>
#include <linux/cred.h>
#include <linux/syscalls.h>     /* for __MAP */
#include <linux/timekeeping.h>  /* for ktime_get */
#include <net/ipv6.h>
#include <linux/lsm_hooks.h>
#include <uapi/linux/lsm.h>
#include <linux/lua.h>
#include <linux/lualib.h>
#include <linux/lauxlib.h>
#include "lsm.h"
#include "lua_object.h"
#include "lsm_defs.h"


/* LSM_RET_DEFAULT */
#define DECLARE_LSM_RET_DEFAULT_void(DEFAULT, NAME)             \
	const int __maybe_unused LSM_RET_DEFAULT(NAME) = 0;
#define DECLARE_LSM_RET_DEFAULT_int(DEFAULT, NAME)              \
	const int __maybe_unused LSM_RET_DEFAULT(NAME) = (DEFAULT);
#define LSM_HOOK(RET, DEFAULT, NAME, ...)                       \
	DECLARE_LSM_RET_DEFAULT_##RET(DEFAULT, NAME)

#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK


/**
 * binder_set_context_mgr
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(binder_set_context_mgr, const struct cred *, mgr)
{
	*(const struct cred **)newcred(L) = mgr;
}

/**
 * binder_transaction
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(binder_transaction, const struct cred *, from,
		const struct cred *, to)
{
	*(const struct cred **)newcred(L) = from;
	*(const struct cred **)newcred(L) = to;
}

/**
 * binder_transfer_binder
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(binder_transfer_binder, const struct cred *, from,
		const struct cred *, to)
{
	*(const struct cred **)newcred(L) = from;
	*(const struct cred **)newcred(L) = to;
}

/**
 * binder_transfer_file
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(binder_transfer_file, const struct cred *, from,
		const struct cred *, to, const struct file *, file)
{
	*(const struct cred **)newcred(L) = from;
	*(const struct cred **)newcred(L) = to;
	*(const struct file **)newfile(L) = file;
}

/**
 * ptrace_access_check
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(ptrace_access_check, struct task_struct *, child,
		unsigned int, mode)
{
	static const struct cflag_opt opts[] = {
		{ "read",	PTRACE_MODE_READ	},
		{ "attach",	PTRACE_MODE_ATTACH	},
		{ "noaudit",	PTRACE_MODE_NOAUDIT	},
		{ "fscreds",	PTRACE_MODE_FSCREDS	},
		{ "realcreds",	PTRACE_MODE_REALCREDS	},
		{ NULL, 0 }
	};
	static const unsigned int flags = PTRACE_MODE_READ |
		PTRACE_MODE_ATTACH | PTRACE_MODE_NOAUDIT |
		PTRACE_MODE_FSCREDS | PTRACE_MODE_REALCREDS;
	*newtask(L) = child;
	table_fromopts(L, opts, flags, mode);
}

/**
 * ptrace_traceme
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(ptrace_traceme, struct task_struct *, parent)
{
	*newtask(L) = parent;
}

/**
 * capget
 * Default: 0
 *
 * hooks result format:
 *   [any]              : -EPERM
 *   false, errno       : -errno
 *   nil, errno         : -errno
 *   cap_e, cap_i, cap_p: 0, must be cap class
 */
LUA_LSM_INT_NAKED_DEFINE4(capget, const struct task_struct *, target,
		kernel_cap_t *, effective, kernel_cap_t *, inheritable,
		kernel_cap_t *, permitted)
{
	int top = lua_gettop(L);
	int ret = LSM_RET_DEFAULT(capget);
	int status;

	*(const struct task_struct **)newtask(L) = target;

	lua_pushvalue(L, -1 - 4);       /* env */
	lua_setfenv(L, -1 - 6);         /* restore thread.env */

	status = lua_pcall(L, 1, LUA_MULTRET, -1 - 6);
	if (status != 0) {
		const char * __maybe_unused error = lua_tostring(L, -1);
		__log_err("pcall: status = %d, top = %d, %s\n",
			status, lua_gettop(L), error);
	} else {
		/* stack: [traceback, thread, env, _MODULES, _M, res1, ...] */
		int nres = lua_gettop(L) - top + 1;
		kernel_cap_t *e, *i, *p;
		switch (nres) {
		case 0:
			break;
		case 1:
			if (lua_type(L, top) == LUA_TBOOLEAN)
				ret = lua_toboolean(L, top) ? 0 : -EPERM;
			break;
		case 2:
			if (!lua_toboolean(L, top)) {
				int errno = lua_tointeger(L, top + 1);
				if (errno > 0 && errno <= MAX_ERRNO)
					ret = -errno;
			}
			break;
		default:
			e = checkudata_cap(L, top);
			i = checkudata_cap(L, top + 1);
			p = checkudata_cap(L, top + 2);
			if (e == NULL || i == NULL || p == NULL)
				break;
			*effective = *e;
			*inheritable = *i;
			*permitted = *p;
			ret = 0;
			break;
		}
	}
	return ret;
}

/**
 * capset
 * Default: 0
 */
LUA_LSM_INT_DEFINE5(capset, struct cred *, new, const struct cred *, old,
		const kernel_cap_t *, effective,
		const kernel_cap_t *, inheritable,
		const kernel_cap_t *, permitted)
{
	*newcred(L) = new;
	*(const struct cred **)newcred(L) = old;
	*newcap(L) = *effective;
	*newcap(L) = *inheritable;
	*newcap(L) = *permitted;
}

/**
 * TODO: capable
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(capable, const struct cred *, cred,
		struct user_namespace *, ns, int, cap, unsigned int, opts)
{
	*(const struct cred **)newcred(L) = cred;
	lua_pushnil(L);	/* TODO: ns */
	lua_pushinteger(L, (lua_Integer)cap);
	lua_pushinteger(L, (lua_Integer)opts);
}

/**
 * quotactl
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(quotactl, int, cmds, int, type, int, id,
		const struct super_block *, sb)
{
	lua_pushinteger(L, (lua_Integer)cmds);
	lua_pushinteger(L, (lua_Integer)type);
	lua_pushinteger(L, (lua_Integer)id);
	*(const struct super_block **)newsuperblock(L) = sb;
}

/**
 * quota_on
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(quota_on, struct dentry *, dentry)
{
	*newdentry(L) = dentry;
}

/**
 * syslog
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(syslog, int, type)
{
	lua_pushinteger(L, (lua_Integer)type);
}

/**
 * TODO: settime
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(settime, const struct timespec64 *, ts,
		const struct timezone *, tz)
{
	lua_pushnil(L);	/* TODO: ts */
	lua_pushnil(L);	/* TODO: tz */
}

/**
 * TODO: vm_enough_memory
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(vm_enough_memory, struct mm_struct *, mm, long, pages)
{
	lua_pushnil(L);	/* TODO: mm */
	lua_pushnil(L);	/* TODO: pages */
}

/**
 * bprm_creds_for_exec
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(bprm_creds_for_exec, struct linux_binprm *, bprm)
{
	*newbinprm(L) = bprm;
}

/**
 * bprm_creds_from_file
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(bprm_creds_from_file, struct linux_binprm *, bprm,
		const struct file *, file)
{
	*newbinprm(L) = bprm;
	*(const struct file **)newfile(L) = file;
}

/**
 * bprm_check_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(bprm_check_security, struct linux_binprm *, bprm)
{
	*newbinprm(L) = bprm;
}

/**
 * bprm_committing_creds
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(bprm_committing_creds, const struct linux_binprm *, bprm)
{
	*(const struct linux_binprm **)newbinprm(L) = bprm;
}

/**
 * bprm_committed_creds
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(bprm_committed_creds, const struct linux_binprm *, bprm)
{
	*(const struct linux_binprm **)newbinprm(L) = bprm;
}

/**
 * fs_context_submount
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(fs_context_submount, struct fs_context *, fc,
		struct super_block *, reference)
{
	*newfscontext(L) = fc;
	*newsuperblock(L) = reference;
}

/**
 * fs_context_dup
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(fs_context_dup, struct fs_context *, fc,
		struct fs_context *, src_sc)
{
	*newfscontext(L) = fc;
	*newfscontext(L) = src_sc;
}

/**
 * TODO: fs_context_parse_param
 * Default: -ENOPARAM
 */
LUA_LSM_INT_DEFINE2(fs_context_parse_param, struct fs_context *, fc,
		struct fs_parameter *, param)
{
	*newfscontext(L) = fc;
	lua_pushnil(L);	/* TODO: param */
}

/**
 * sb_alloc_security - prepare
 */
LUA_LSM_PREPARE_DEFINE1(sb_alloc_security, struct super_block *, sb)
{
	struct lua_lsm_object *llo = lua_lsm_superblock(sb);
	kvcache_dict_init(&llo->dict);
	return 0;
}

/**
 * sb_alloc_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(sb_alloc_security, struct super_block *, sb)
{
	*newsuperblock(L) = sb;
}

/**
 * sb_delete
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(sb_delete, struct super_block *, sb)
{
	*newsuperblock(L) = sb;
}

/**
 * sb_free_security - postpone
 */
LUA_LSM_POSTPONE_DEFINE1(sb_free_security, struct super_block *, sb)
{
	struct lua_lsm_object *llo = lua_lsm_superblock(sb);
	kvcache_dict_free(&llo->dict);
}

/**
 * sb_free_security
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(sb_free_security, struct super_block *, sb)
{
	*newsuperblock(L) = sb;
}

/**
 * TODO: sb_free_mnt_opts
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(sb_free_mnt_opts, void *, mnt_opts)
{
	lua_pushnil(L);	/* TODO: mnt_opts */
}

/**
 * TODO: sb_eat_lsm_opts
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(sb_eat_lsm_opts, char *, orig, void **, mnt_opts)
{
	lua_pushstring(L, (const char *)orig);
	lua_pushnil(L);	/* TODO: mnt_opts */
}

/**
 * TODO: sb_mnt_opts_compat
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(sb_mnt_opts_compat, struct super_block *, sb,
		void *, mnt_opts)
{
	*newsuperblock(L) = sb;
	lua_pushnil(L);	/* TODO: mnt_opts */
}

/**
 * TODO: sb_remount
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(sb_remount, struct super_block *, sb, void *, mnt_opts)
{
	*newsuperblock(L) = sb;
	lua_pushnil(L);	/* TODO: mnt_opts */
}

/**
 * sb_kern_mount
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(sb_kern_mount, const struct super_block *, sb)
{
	*(const struct super_block **)newsuperblock(L) = sb;
}

/**
 * TODO: sb_show_options
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(sb_show_options, struct seq_file *, m,
		struct super_block *, sb)
{
	lua_pushnil(L);	/* TODO: m */
	*newsuperblock(L) = sb;
}

/**
 * sb_statfs
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(sb_statfs, struct dentry *, dentry)
{
	*newdentry(L) = dentry;
}

/**
 * TODO: sb_mount
 * Default: 0
 */
LUA_LSM_INT_DEFINE5(sb_mount, const char *, dev_name, const struct path *, path,
		const char *, type, unsigned long, flags, void *, data)
{
	lua_pushstring(L, dev_name);
	*(const struct path **)newpath(L) = path;
	lua_pushstring(L, type);
	lua_pushnumber(L, (lua_Number)flags);
	lua_pushnil(L);	/* TODO: data */
}

/**
 * sb_umount
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(sb_umount, struct vfsmount *, mnt, int, flags)
{
	*newvfsmount(L) = mnt;
	lua_pushinteger(L, (lua_Integer)flags);
}

/**
 * sb_pivotroot
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(sb_pivotroot, const struct path *, old_path,
		const struct path *, new_path)
{
	*(const struct path **)newpath(L) = old_path;
	*(const struct path **)newpath(L) = new_path;
}

/**
 * TODO: sb_set_mnt_opts
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(sb_set_mnt_opts, struct super_block *, sb, void *, mnt_opts,
		unsigned long, kern_flags, unsigned long *, set_kern_flags)
{
	*newsuperblock(L) = sb;
	lua_pushnil(L);	/* TODO: mnt_opts */
	lua_pushnumber(L, (lua_Number)kern_flags);
	lua_pushnil(L);	/* TODO: set_kern_flags */
}

/**
 * TODO: sb_clone_mnt_opts
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(sb_clone_mnt_opts, const struct super_block *, oldsb,
		struct super_block *, newsb, unsigned long, kern_flags,
		unsigned long *, set_kern_flags)
{
	*(const struct super_block **)newsuperblock(L) = oldsb;
	*newsuperblock(L) = newsb;
	lua_pushnumber(L, (lua_Number)kern_flags);
	lua_pushnil(L);	/* TODO: set_kern_flags */
}

/**
 * move_mount
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(move_mount, const struct path *, from_path,
		const struct path *, to_path)
{
	*(const struct path **)newpath(L) = from_path;
	*(const struct path **)newpath(L) = to_path;
}

/**
 * TODO: dentry_init_security
 * Default: -EOPNOTSUPP
 */
LUA_LSM_INT_DEFINE5(dentry_init_security, struct dentry *, dentry,
		int, mode, const struct qstr *, name,
		const char **, xattr_name, struct lsm_context *, cp)
{
	*newdentry(L) = dentry;
	lua_pushinteger(L, (lua_Integer)mode);
	lua_pushnil(L);	/* TODO: name */
	lua_pushnil(L);	/* TODO: xattr_name */
	lua_pushnil(L);	/* TODO: cp */
}

/**
 * TODO: dentry_create_files_as
 * Default: 0
 */
LUA_LSM_INT_DEFINE5(dentry_create_files_as, struct dentry *, dentry,
		int, mode, struct qstr *, name,
		const struct cred *, old, struct cred *, new)
{
	*newdentry(L) = dentry;
	lua_pushinteger(L, (lua_Integer)mode);
	lua_pushnil(L);	/* TODO: name */
	*(const struct cred **)newcred(L) = old;
	*newcred(L) = new;
}

#ifdef CONFIG_SECURITY_PATH

/**
 * path_unlink
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(path_unlink, const struct path *, dir,
		struct dentry *, dentry)
{
	*(const struct path **)newpath(L) = dir;
	*newdentry(L) = dentry;
}

/**
 * path_mkdir
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(path_mkdir, const struct path *, dir,
		struct dentry *, dentry, umode_t, mode)
{
	*(const struct path **)newpath(L) = dir;
	*newdentry(L) = dentry;
	lua_pushinteger(L, (lua_Integer)mode);
}

/**
 * path_rmdir
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(path_rmdir, const struct path *, dir,
		struct dentry *, dentry)
{
	*(const struct path **)newpath(L) = dir;
	*newdentry(L) = dentry;
}

/**
 * path_mknod
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(path_mknod, const struct path *, dir,
		struct dentry *, dentry, umode_t, mode, unsigned int, dev)
{
	*(const struct path **)newpath(L) = dir;
	*newdentry(L) = dentry;
	lua_pushinteger(L, (lua_Integer)mode);
	lua_pushinteger(L, (lua_Integer)dev);
}

/**
 * path_post_mknod
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(path_post_mknod, struct mnt_idmap *, idmap,
		struct dentry *, dentry)
{
	*newmntidmap(L) = idmap;
	*newdentry(L) = dentry;
}

/**
 * path_truncate
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(path_truncate, const struct path *, path)
{
	*(const struct path **)newpath(L) = path;
}

/**
 * path_symlink
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(path_symlink, const struct path *, dir,
		struct dentry *, dentry, const char *, old_name)
{
	*(const struct path **)newpath(L) = dir;
	*newdentry(L) = dentry;
	lua_pushstring(L, old_name);
}

/**
 * path_link
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(path_link, struct dentry *, old_dentry,
		const struct path *, new_dir, struct dentry *, new_dentry)
{
	*newdentry(L) = old_dentry;
	*(const struct path **)newpath(L) = new_dir;
	*newdentry(L) = new_dentry;
}

/**
 * path_rename
 * Default: 0
 */
LUA_LSM_INT_DEFINE5(path_rename, const struct path *, old_dir,
		struct dentry *, old_dentry, const struct path *, new_dir,
		struct dentry *, new_dentry, unsigned int, flags)
{
	*(const struct path **)newpath(L) = old_dir;
	*newdentry(L) = old_dentry;
	*(const struct path **)newpath(L) = new_dir;
	*newdentry(L) = new_dentry;
	lua_pushinteger(L, (lua_Integer)flags);
}

/**
 * path_chmod
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(path_chmod, const struct path *, path, umode_t, mode)
{
	*(const struct path **)newpath(L) = path;
	lua_pushinteger(L, (lua_Integer)mode);
}

/**
 * TODO: path_chown
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(path_chown, const struct path *, path,
		kuid_t, uid, kgid_t, gid)
{
	*(const struct path **)newpath(L) = path;
	lua_pushnil(L);	/* TODO: uid */
	lua_pushnil(L);	/* TODO: gid */
}

/**
 * path_chroot
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(path_chroot, const struct path *, path)
{
	*(const struct path **)newpath(L) = path;
}

#endif /* CONFIG_SECURITY_PATH */

/**
 * path_notify
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(path_notify, const struct path *, path,
		u64, mask, unsigned int, obj_type)
{
	*(const struct path **)newpath(L) = path;
	lua_pushnumber(L, (lua_Number)mask);
	lua_pushinteger(L, (lua_Integer)obj_type);
}

/**
 * inode_alloc_security - prepare
 */
LUA_LSM_PREPARE_DEFINE1(inode_alloc_security, struct inode *, inode)
{
	struct lua_lsm_object *llo = lua_lsm_inode(inode);
	kvcache_dict_init(&llo->dict);
	return 0;
}

/**
 * inode_alloc_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(inode_alloc_security, struct inode *, inode)
{
	*newinode(L) = inode;
}

/**
 * inode_free_security
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(inode_free_security, struct inode *, inode)
{
	*newinode(L) = inode;
}

/**
 * inode_free_security_rcu - postpone
 */
LUA_LSM_POSTPONE_DEFINE1(inode_free_security_rcu, void *, inode_security)
{
	struct lua_lsm_object *llo = lua_lsm_inode_rcu(inode_security);
	kvcache_dict_free(&llo->dict);
}

/**
 * TODO: inode_free_security_rcu
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(inode_free_security_rcu, void *, inode_security)
{
	lua_pushnil(L);	/* TODO: inode_security */
}

/**
 * inode_init_security
 * Default: -EOPNOTSUPP
 *
 * hooks result format:
 *   [none]       : default value
 *   nil          : default value
 *   true         : 0
 *   false        : -EPERM
 *   false, errno : -errno
 *   nil, errno   : -errno
 *   name, value  : fill the xattr struct, XXX: name must not be freed
 */
LUA_LSM_INT_NAKED_DEFINE5(inode_init_security, struct inode *, inode,
		struct inode *, dir, const struct qstr *, qstr,
		struct xattr *, xattrs, int *, xattr_count)
{
	int top = lua_gettop(L);
	int ret = LSM_RET_DEFAULT(inode_init_security);
	int nres;
	int status;

	*newinode(L) = inode;
	dir ? *newinode(L) = dir : lua_pushnil(L);
	qstr ? lua_pushlstring(L, qstr->name, qstr->len) : lua_pushnil(L);

	lua_pushvalue(L, -3 - 4);       /* env */
	lua_setfenv(L, -3 - 6);         /* restore thread.env */

	status = lua_pcall(L, 3, LUA_MULTRET, -3 - 6);
	if (status != 0) {
		const char * __maybe_unused error = lua_tostring(L, -1);
		__log_err("pcall: status = %d, top = %d, %s\n",
			status, lua_gettop(L), error);
		return ret;
	}

	/* stack: [traceback, thread, env, _MODULES, _M, res1, ...] */
	nres = lua_gettop(L) - top + 1;
	switch (nres) {
	case 0:
		break;
	case 1:
		if (lua_type(L, top) == LUA_TBOOLEAN)
			ret = lua_toboolean(L, top) ? 0 : -EPERM;
		break;
	default:
		if (!lua_toboolean(L, top)) {
			int errno = lua_tointeger(L, top + 1);
			if (errno > 0 && errno <= MAX_ERRNO)
				ret = -errno;
		} else if (lua_isstring(L, top) && lua_isstring(L, top + 1)) {
			struct xattr *xattr;
			const char *value;
			size_t len;

			xattr = lsm_get_xattr_slot(xattrs, xattr_count);
			if (xattr) {
				value = lua_tolstring(L, top + 1, &len);
				xattr->value = kmemdup(value, len, GFP_NOFS);
				if (xattr->value == NULL) {
					ret = -ENOMEM;
					break;
				}
				xattr->value_len = len;
				xattr->name = lua_tostring(L, top);
				ret = 0;
			} else {
				/* TODO */
			}
		}
		break;
	}
	return ret;
}

/**
 * TODO: inode_init_security_anon
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(inode_init_security_anon, struct inode *, inode,
		const struct qstr *, name, const struct inode *, context_inode)
{
	*newinode(L) = inode;
	lua_pushnil(L);	/* TODO: name */
	*(const struct inode **)newinode(L) = context_inode;
}

/**
 * inode_create
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(inode_create, struct inode *, dir,
		struct dentry *, dentry, umode_t, mode)
{
	*newinode(L) = dir;
	*newdentry(L) = dentry;
	lua_pushinteger(L, (lua_Integer)mode);
}

/**
 * inode_post_create_tmpfile
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(inode_post_create_tmpfile, struct mnt_idmap *, idmap,
		struct inode *, inode)
{
	*newmntidmap(L) = idmap;
	*newinode(L) = inode;
}

/**
 * inode_link
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(inode_link, struct dentry *, old_dentry,
		struct inode *, dir, struct dentry *, new_dentry)
{
	*newdentry(L) = old_dentry;
	*newinode(L) = dir;
	*newdentry(L) = new_dentry;
}

/**
 * inode_unlink
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(inode_unlink, struct inode *, dir, struct dentry *, dentry)
{
	*newinode(L) = dir;
	*newdentry(L) = dentry;
}

/**
 * inode_symlink
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(inode_symlink, struct inode *, dir,
		struct dentry *, dentry, const char *, old_name)
{
	*newinode(L) = dir;
	*newdentry(L) = dentry;
	lua_pushstring(L, old_name);
}

/**
 * inode_mkdir
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(inode_mkdir, struct inode *, dir,
		struct dentry *, dentry, umode_t, mode)
{
	*newinode(L) = dir;
	*newdentry(L) = dentry;
	lua_pushinteger(L, (lua_Integer)mode);
}

/**
 * inode_rmdir
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(inode_rmdir, struct inode *, dir, struct dentry *, dentry)
{
	*newinode(L) = dir;
	*newdentry(L) = dentry;
}

/**
 * inode_mknod
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(inode_mknod, struct inode *, dir, struct dentry *, dentry,
		umode_t, mode, dev_t, dev)
{
	*newinode(L) = dir;
	*newdentry(L) = dentry;
	lua_pushinteger(L, (lua_Integer)mode);
	lua_pushinteger(L, (lua_Integer)dev);
}

/**
 * inode_rename
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(inode_rename,
		struct inode *, old_dir, struct dentry *, old_dentry,
		struct inode *, new_dir, struct dentry *, new_dentry)
{
	*newinode(L) = old_dir;
	*newdentry(L) = old_dentry;
	*newinode(L) = new_dir;
	*newdentry(L) = new_dentry;
}

/**
 * inode_readlink
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(inode_readlink, struct dentry *, dentry)
{
	*newdentry(L) = dentry;
}

/**
 * inode_follow_link
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(inode_follow_link, struct dentry *, dentry,
		struct inode *, inode, bool, rcu)
{
	*newdentry(L) = dentry;
	*newinode(L) = inode;
	lua_pushboolean(L, (int)rcu);
}

/**
 * inode_permission
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(inode_permission, struct inode *, inode, int, mask)
{
	*newinode(L) = inode;
	lua_pushinteger(L, (lua_Integer)mask);
}

/**
 * TODO: inode_setattr
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(inode_setattr, struct mnt_idmap *, idmap,
		struct dentry *, dentry, struct iattr *, attr)
{
	*newmntidmap(L) = idmap;
	*newdentry(L) = dentry;
	lua_pushnil(L);	/* TODO: attr */
}

/**
 * inode_post_setattr
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE3(inode_post_setattr, struct mnt_idmap *, idmap,
		struct dentry *, dentry, int, ia_valid)
{
	*newmntidmap(L) = idmap;
	*newdentry(L) = dentry;
	lua_pushinteger(L, (lua_Integer)ia_valid);
}

/**
 * inode_getattr
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(inode_getattr, const struct path *, path)
{
	*(const struct path **)newpath(L) = path;
}

/**
 * inode_xattr_skipcap
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(inode_xattr_skipcap, const char *, name)
{
	lua_pushstring(L, name);
}

/**
 * inode_setxattr
 * Default: 0
 */
LUA_LSM_INT_DEFINE6(inode_setxattr, struct mnt_idmap *, idmap,
		struct dentry *, dentry, const char *, name,
		const void *, value, size_t, size, int, flags)
{
	*newmntidmap(L) = idmap;
	*newdentry(L) = dentry;
	lua_pushstring(L, name);
	lua_pushlstring(L, value, size);
	lua_pushinteger(L, (lua_Integer)flags);
}

/**
 * inode_post_setxattr
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE5(inode_post_setxattr, struct dentry *, dentry,
		const char *, name, const void *, value,
		size_t, size, int, flags)
{
	*newdentry(L) = dentry;
	lua_pushstring(L, name);
	lua_pushlstring(L, value, size);
	lua_pushinteger(L, (lua_Integer)flags);
}

/**
 * inode_getxattr
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(inode_getxattr, struct dentry *, dentry, const char *, name)
{
	*newdentry(L) = dentry;
	lua_pushstring(L, name);
}

/**
 * inode_listxattr
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(inode_listxattr, struct dentry *, dentry)
{
	*newdentry(L) = dentry;
}

/**
 * inode_removexattr
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(inode_removexattr, struct mnt_idmap *, idmap,
		struct dentry *, dentry, const char *, name)
{
	*newmntidmap(L) = idmap;
	*newdentry(L) = dentry;
	lua_pushstring(L, name);
}

/**
 * inode_post_removexattr
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(inode_post_removexattr, struct dentry *, dentry,
		const char *, name)
{
	*newdentry(L) = dentry;
	lua_pushstring(L, name);
}

/**
 * TODO: inode_file_setattr
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(inode_file_setattr, struct dentry *, dentry,
		struct file_kattr *, fa)
{
	*newdentry(L) = dentry;
	lua_pushnil(L);	/* TODO: fa */
}

/**
 * TODO: inode_file_getattr
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(inode_file_getattr, struct dentry *, dentry,
		struct file_kattr *, fa)
{
	*newdentry(L) = dentry;
	lua_pushnil(L);	/* TODO: fa */
}

/**
 * TODO: inode_set_acl
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(inode_set_acl, struct mnt_idmap *, idmap,
		struct dentry *, dentry, const char *, acl_name,
		struct posix_acl *, kacl)
{
	*newmntidmap(L) = idmap;
	*newdentry(L) = dentry;
	lua_pushstring(L, acl_name);
	lua_pushnil(L);	/* TODO: kacl */
}

/**
 * TODO: inode_post_set_acl
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE3(inode_post_set_acl, struct dentry *, dentry,
		const char *, acl_name, struct posix_acl *, kacl)
{
	*newdentry(L) = dentry;
	lua_pushstring(L, acl_name);
	lua_pushnil(L);	/* TODO: kacl */
}

/**
 * inode_get_acl
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(inode_get_acl, struct mnt_idmap *, idmap,
		struct dentry *, dentry, const char *, acl_name)
{
	*newmntidmap(L) = idmap;
	*newdentry(L) = dentry;
	lua_pushstring(L, acl_name);
}

/**
 * inode_remove_acl
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(inode_remove_acl, struct mnt_idmap *, idmap,
		struct dentry *, dentry, const char *, acl_name)
{
	*newmntidmap(L) = idmap;
	*newdentry(L) = dentry;
	lua_pushstring(L, acl_name);
}

/**
 * inode_post_remove_acl
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE3(inode_post_remove_acl, struct mnt_idmap *, idmap,
		struct dentry *, dentry, const char *, acl_name)
{
	*newmntidmap(L) = idmap;
	*newdentry(L) = dentry;
	lua_pushstring(L, acl_name);
}

/**
 * inode_need_killpriv
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(inode_need_killpriv, struct dentry *, dentry)
{
	*newdentry(L) = dentry;
}

/**
 * inode_killpriv
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(inode_killpriv, struct mnt_idmap *, idmap,
		struct dentry *, dentry)
{
	*newmntidmap(L) = idmap;
	*newdentry(L) = dentry;
}

/**
 * inode_getsecurity
 * Default: -EOPNOTSUPP
 */
LUA_LSM_INT_NAKED_DEFINE5(inode_getsecurity, struct mnt_idmap *, idmap,
		struct inode *, inode, const char *, name,
		void **, buffer, bool, alloc)
{
	int top = lua_gettop(L);
	int ret = LSM_RET_DEFAULT(inode_getsecurity);
	int status;

	*newmntidmap(L) = idmap;
	*newinode(L) = inode;
	lua_pushstring(L, name);

	lua_pushvalue(L, -3 - 4);       /* env */
	lua_setfenv(L, -3 - 6);         /* restore thread.env */

	status = lua_pcall(L, 3, LUA_MULTRET, -3 - 6);
	if (status != 0) {
		const char * __maybe_unused error = lua_tostring(L, -1);
		__log_err("pcall: status = %d, top = %d, %s\n",
			status, lua_gettop(L), error);
	} else {
		/* stack: [traceback, thread, env, _MODULES, _M, res1, ...] */
		int nres = lua_gettop(L) - top + 1;
		int tt;
		switch (nres) {
		case 0:
			break;
		case 1:
			tt = lua_type(L, top);
			if (tt == LUA_TBOOLEAN) {
				ret = lua_toboolean(L, top) ? 0 : -EPERM;
			} else if (tt == LUA_TSTRING) {
				size_t len;
				const char *v = lua_tolstring(L, top, &len);
				ret = (int)len;
				if (alloc) {
					*buffer = kmemdup(v, len, GFP_NOFS);
					if (*buffer == NULL)
						ret = -ENOMEM;
				}
			}
			break;
		default:
			if (!lua_toboolean(L, top)) {
				int errno = lua_tointeger(L, top + 1);
				if (errno > 0 && errno <= MAX_ERRNO)
					ret = -errno;
			}
			break;
		}
	}
	return ret;
}

/**
 * inode_setsecurity
 * Default: -EOPNOTSUPP
 */
LUA_LSM_INT_DEFINE5(inode_setsecurity, struct inode *, inode,
		const char *, name, const void *, value,
		size_t, size, int, flags)
{
	*newinode(L) = inode;
	lua_pushstring(L, name);
	lua_pushlstring(L, value, size);
	lua_pushinteger(L, (lua_Integer)flags);
}

/**
 * inode_listsecurity
 * Default: 0
 */
LUA_LSM_INT_NAKED_DEFINE3(inode_listsecurity, struct inode *, inode,
		char *, buffer, size_t, buffer_size)
{
	int top = lua_gettop(L);
	int ret = LSM_RET_DEFAULT(inode_listsecurity);
	int status;

	*newinode(L) = inode;

	lua_pushvalue(L, -1 - 4);       /* env */
	lua_setfenv(L, -1 - 6);         /* restore thread.env */

	status = lua_pcall(L, 1, LUA_MULTRET, -1 - 6);
	if (status != 0) {
		const char * __maybe_unused error = lua_tostring(L, -1);
		__log_err("pcall: status = %d, top = %d, %s\n",
			status, lua_gettop(L), error);
	} else {
		/* stack: [traceback, thread, env, _MODULES, _M, res1, ...] */
		int nres = lua_gettop(L) - top + 1;
		int tt;
		switch (nres) {
		case 0:
			break;
		case 1:
			tt = lua_type(L, top);
			if (tt == LUA_TBOOLEAN) {
				ret = lua_toboolean(L, top) ? 0 : -EPERM;
			} else if (tt == LUA_TSTRING) {
				size_t len;
				const char *v = lua_tolstring(L, top, &len);
				ret = (int)len;
				if (buffer != NULL && len <= buffer_size)
					memcpy(buffer, v, buffer_size);
			}
			break;
		default:
			if (!lua_toboolean(L, top)) {
				int errno = lua_tointeger(L, top + 1);
				if (errno > 0 && errno <= MAX_ERRNO)
					ret = -errno;
			}
			break;
		}
	}
	return ret;
}

/**
 * TODO: inode_getlsmprop
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(inode_getlsmprop, struct inode *, inode,
		struct lsm_prop *, prop)
{
	*newinode(L) = inode;
	lua_pushnil(L);	/* TODO: prop */
}

/**
 * TODO: inode_copy_up
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(inode_copy_up, struct dentry *, src, struct cred **, new)
{
	*newdentry(L) = src;
	lua_pushnil(L);	/* TODO: new */
}

/**
 * inode_copy_up_xattr
 * Default: -EOPNOTSUPP
 */
LUA_LSM_INT_DEFINE2(inode_copy_up_xattr, struct dentry *, src,
		const char *, name)
{
	*newdentry(L) = src;
	lua_pushstring(L, name);
}

/**
 * TODO: inode_setintegrity
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(inode_setintegrity, const struct inode *, inode,
		enum lsm_integrity_type, type,
		const void *, value, size_t, size)
{
	*(const struct inode **)newinode(L) = inode;
	lua_pushnil(L);	/* TODO: type */
	lua_pushnil(L);	/* TODO: value */
	lua_pushnil(L);	/* TODO: size */
}

/**
 * TODO: kernfs_init_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(kernfs_init_security, struct kernfs_node *, kn_dir,
		struct kernfs_node *, kn)
{
	lua_pushnil(L);	/* TODO: kn_dir */
	lua_pushnil(L);	/* TODO: kn */
}

/**
 * file_permission
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(file_permission, struct file *, file, int, mask)
{
	*newfile(L) = file;
	lua_pushinteger(L, (lua_Integer)mask);
}

/**
 * file_alloc_security - prepare
 */
LUA_LSM_PREPARE_DEFINE1(file_alloc_security, struct file *, file)
{
	struct lua_lsm_object *llo = lua_lsm_file(file);
	kvcache_dict_init(&llo->dict);
	return 0;
}

/**
 * file_alloc_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(file_alloc_security, struct file *, file)
{
	*newrawfile(L) = file;
}

/**
 * file_release
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(file_release, struct file *, file)
{
	*newfile(L) = file;
}

/**
 * file_free_security - postpone
 */
LUA_LSM_POSTPONE_DEFINE1(file_free_security, struct file *, file)
{
	struct lua_lsm_object *llo = lua_lsm_file(file);
	kvcache_dict_free(&llo->dict);
}

/**
 * file_free_security
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(file_free_security, struct file *, file)
{
	*newrawfile(L) = file;
}

/**
 * file_ioctl
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(file_ioctl, struct file *, file,
		unsigned int, cmd, unsigned long, arg)
{
	*newfile(L) = file;
	lua_pushinteger(L, (lua_Integer)cmd);
	lua_pushnumber(L, (lua_Number)arg);
}

/**
 * file_ioctl_compat
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(file_ioctl_compat, struct file *, file,
		unsigned int, cmd, unsigned long, arg)
{
	*newfile(L) = file;
	lua_pushinteger(L, (lua_Integer)cmd);
	lua_pushnumber(L, (lua_Number)arg);
}

/**
 * mmap_addr
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(mmap_addr, unsigned long, addr)
{
	lua_pushnumber(L, (lua_Number)addr);
}

/**
 * mmap_file
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(mmap_file, struct file *, file, unsigned long, reqprot,
		unsigned long, prot, unsigned long, flags)
{
	file ? *newfile(L) = file : lua_pushnil(L);
	lua_pushnumber(L, (lua_Number)reqprot);
	lua_pushnumber(L, (lua_Number)prot);
	lua_pushnumber(L, (lua_Number)flags);
}

/**
 * TODO: file_mprotect
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(file_mprotect, struct vm_area_struct *, vma,
		unsigned long, reqprot, unsigned long, prot)
{
	lua_pushnil(L);	/* TODO: vma */
	lua_pushnumber(L, (lua_Number)reqprot);
	lua_pushnumber(L, (lua_Number)prot);
}

/**
 * file_lock
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(file_lock, struct file *, file, unsigned int, cmd)
{
	*newfile(L) = file;
	lua_pushinteger(L, (lua_Integer)cmd);
}

/**
 * file_fcntl
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(file_fcntl, struct file *, file,
		unsigned int, cmd, unsigned long, arg)
{
	*newfile(L) = file;
	lua_pushinteger(L, (lua_Integer)cmd);
	lua_pushnumber(L, (lua_Number)arg);
}

/**
 * file_set_fowner
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(file_set_fowner, struct file *, file)
{
	*newfile(L) = file;
}

/**
 * TODO: file_send_sigiotask
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(file_send_sigiotask, struct task_struct *, tsk,
		struct fown_struct *, fown, int, sig)
{
	*newtask(L) = tsk;
	lua_pushnil(L);	/* TODO: fown */
	lua_pushinteger(L, (lua_Integer)sig);
}

/**
 * file_receive
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(file_receive, struct file *, file)
{
	*newfile(L) = file;
}

/**
 * file_open
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(file_open, struct file *, file)
{
	*newfile(L) = file;
}

/**
 * file_post_open
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(file_post_open, struct file *, file, int, mask)
{
	static const struct cflag_opt opts[] = {
		{ "exec",     MAY_EXEC      },
		{ "write",    MAY_WRITE     },
		{ "read",     MAY_READ      },
		{ "append",   MAY_APPEND    },
		{ "access",   MAY_ACCESS    },
		{ "open",     MAY_OPEN      },
		{ "chdir",    MAY_CHDIR     },
		{ "notblock", MAY_NOT_BLOCK },
		{ NULL, 0 }
	};
	static const unsigned int flags = MAY_EXEC | MAY_WRITE | MAY_READ |
		MAY_APPEND | MAY_ACCESS | MAY_OPEN | MAY_CHDIR | MAY_NOT_BLOCK;
	*newfile(L) = file;
	table_fromopts(L, opts, flags, (unsigned int)mask);
}

/**
 * file_truncate
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(file_truncate, struct file *, file)
{
	*newfile(L) = file;
}

/**
 * task_alloc - prepare
 */
LUA_LSM_PREPARE_DEFINE2(task_alloc, struct task_struct *, task,
		unsigned long, clone_flags)
{
	return task_blob_init(task);
}

/**
 * task_alloc
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(task_alloc, struct task_struct *, task,
		unsigned long, clone_flags)
{
	*newtask(L) = task;
	lua_pushnumber(L, (lua_Number)clone_flags);
}

/**
 * task_free - postpone
 */
LUA_LSM_POSTPONE_DEFINE1(task_free, struct task_struct *, task)
{
	task_blob_free(task);
}

/**
 * task_free
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(task_free, struct task_struct *, task)
{
	*newtask(L) = task;
}

/**
 * cred_alloc_blank - prepare
 */
LUA_LSM_PREPARE_DEFINE2(cred_alloc_blank, struct cred *, cred, gfp_t, gfp)
{
	struct lua_lsm_object *llo = lua_lsm_cred(cred);
	kvcache_dict_init(&llo->dict);
	return 0;
}

/**
 * cred_alloc_blank
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(cred_alloc_blank, struct cred *, cred, gfp_t, gfp)
{
	*newcred(L) = cred;
	lua_pushinteger(L, (lua_Integer)gfp);
}

/**
 * cred_free - postpone
 */
LUA_LSM_POSTPONE_DEFINE1(cred_free, struct cred *, cred)
{
	struct lua_lsm_object *llo = lua_lsm_cred(cred);
	kvcache_dict_free(&llo->dict);
}

/**
 * cred_free
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(cred_free, struct cred *, cred)
{
	*newcred(L) = cred;
}

/**
 * cred_prepare - prepare
 */
LUA_LSM_PREPARE_DEFINE3(cred_prepare, struct cred *, new,
		const struct cred *, old, gfp_t, gfp)
{
	struct lua_lsm_object *llo = lua_lsm_cred(new);
	kvcache_dict_init(&llo->dict);
	return 0;
}

/**
 * cred_prepare
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(cred_prepare, struct cred *, new,
		const struct cred *, old, gfp_t, gfp)
{
	*newcred(L) = new;
	*(const struct cred **)newcred(L) = old;
	lua_pushinteger(L, (lua_Integer)gfp);
}

/**
 * cred_transfer
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(cred_transfer, struct cred *, new,
		const struct cred *, old)
{
	*newcred(L) = new;
	*(const struct cred **)newcred(L) = old;
}

/**
 * TODO: cred_getsecid
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(cred_getsecid, const struct cred *, c, u32 *, secid)
{
	*(const struct cred **)newcred(L) = c;
	lua_pushnil(L);	/* TODO: secid */
}

/**
 * TODO: cred_getlsmprop
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(cred_getlsmprop, const struct cred *, c,
		struct lsm_prop *, prop)
{
	*(const struct cred **)newcred(L) = c;
	lua_pushnil(L);	/* TODO: prop */
}

/**
 * kernel_act_as
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(kernel_act_as, struct cred *, new, u32, secid)
{
	*newcred(L) = new;
	lua_pushinteger(L, (lua_Integer)secid);
}

/**
 * kernel_create_files_as
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(kernel_create_files_as, struct cred *, new,
		struct inode *, inode)
{
	*newcred(L) = new;
	*newinode(L) = inode;
}

/**
 * kernel_module_request
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(kernel_module_request, char *, kmod_name)
{
	lua_pushstring(L, (const char *)kmod_name);
}

/**
 * TODO: kernel_load_data
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(kernel_load_data, enum kernel_load_data_id, id,
		bool, contents)
{
	lua_pushnil(L);	/* TODO: id */
	lua_pushboolean(L, (int)contents);
}

/**
 * TODO: kernel_post_load_data
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(kernel_post_load_data, char *, buf, loff_t, size,
		enum kernel_load_data_id, id, char *, description)
{
	lua_pushstring(L, (const char *)buf);
	lua_pushinteger(L, (lua_Integer)size);
	lua_pushnil(L);	/* TODO: id */
	lua_pushstring(L, (const char *)description);
}

/**
 * TODO: kernel_read_file
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(kernel_read_file, struct file *, file,
		enum kernel_read_file_id, id, bool, contents)
{
	*newfile(L) = file;
	lua_pushnil(L);	/* TODO: id */
	lua_pushboolean(L, (int)contents);
}

/**
 * TODO: kernel_post_read_file
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(kernel_post_read_file, struct file *, file,
		char *, buf, loff_t, size, enum kernel_read_file_id, id)
{
	*newfile(L) = file;
	lua_pushstring(L, (const char *)buf);
	lua_pushinteger(L, (lua_Integer)size);
	lua_pushnil(L);	/* TODO: id */
}

static void build_lsm_setid_flags(lua_State *L, int flags)
{
	const char *s = NULL;
	switch (flags) {
	case LSM_SETID_ID:	s = "lsm_setid_id";	break;
	case LSM_SETID_RE:	s = "lsm_setid_re";	break;
	case LSM_SETID_RES:	s = "lsm_setid_res";	break;
	case LSM_SETID_FS:	s = "lsm_setid_fs";	break;
	}
	lua_pushstring(L, s);
}

/**
 * task_fix_setuid
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(task_fix_setuid, struct cred *, new,
		const struct cred *, old, int, flags)
{
	*newcred(L) = new;
	*(const struct cred **)newcred(L) = old;
	build_lsm_setid_flags(L, flags);
}

/**
 * task_fix_setgid
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(task_fix_setgid, struct cred *, new,
		const struct cred *, old, int, flags)
{
	*newcred(L) = new;
	*(const struct cred **)newcred(L) = old;
	build_lsm_setid_flags(L, flags);
}

/**
 * task_fix_setgroups
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(task_fix_setgroups, struct cred *, new,
		const struct cred *, old)
{
	*newcred(L) = new;
	*(const struct cred **)newcred(L) = old;
}

/**
 * task_setpgid
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(task_setpgid, struct task_struct *, p, pid_t, pgid)
{
	*newtask(L) = p;
	lua_pushinteger(L, (lua_Integer)pgid);
}

/**
 * task_getpgid
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(task_getpgid, struct task_struct *, p)
{
	*newtask(L) = p;
}

/**
 * task_getsid
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(task_getsid, struct task_struct *, p)
{
	*newtask(L) = p;
}

/**
 * TODO: current_getlsmprop_subj
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(current_getlsmprop_subj, struct lsm_prop *, prop)
{
	lua_pushnil(L);	/* TODO: prop */
}

/**
 * TODO: task_getlsmprop_obj
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(task_getlsmprop_obj, struct task_struct *, p,
		struct lsm_prop *, prop)
{
	*newtask(L) = p;
	lua_pushnil(L);	/* TODO: prop */
}

/**
 * task_setnice
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(task_setnice, struct task_struct *, p, int, nice)
{
	*newtask(L) = p;
	lua_pushinteger(L, (lua_Integer)nice);
}

/**
 * task_setioprio
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(task_setioprio, struct task_struct *, p, int, ioprio)
{
	*newtask(L) = p;
	lua_pushinteger(L, (lua_Integer)ioprio);
}

/**
 * task_getioprio
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(task_getioprio, struct task_struct *, p)
{
	*newtask(L) = p;
}

/**
 * task_prlimit
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(task_prlimit, const struct cred *, cred,
		const struct cred *, tcred, unsigned int, flags)
{
	*(const struct cred **)newcred(L) = cred;
	*(const struct cred **)newcred(L) = tcred;
	lua_pushinteger(L, (lua_Integer)flags);
}

/**
 * TODO: task_setrlimit
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(task_setrlimit, struct task_struct *, p,
		unsigned int, resource, struct rlimit *, new_rlim)
{
	*newtask(L) = p;
	lua_pushinteger(L, (lua_Integer)resource);
	lua_pushnil(L);	/* TODO: new_rlim */
}

/**
 * task_setscheduler
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(task_setscheduler, struct task_struct *, p)
{
	*newtask(L) = p;
}

/**
 * task_getscheduler
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(task_getscheduler, struct task_struct *, p)
{
	*newtask(L) = p;
}

/**
 * task_movememory
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(task_movememory, struct task_struct *, p)
{
	*newtask(L) = p;
}

/**
 * TODO: task_kill
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(task_kill, struct task_struct *, p,
		struct kernel_siginfo *, info, int, sig,
		const struct cred *, cred)
{
	*newtask(L) = p;
	lua_pushnil(L);	/* TODO: info */
	lua_pushinteger(L, (lua_Integer)sig);
	cred ? *(const struct cred **)newcred(L) = cred : lua_pushnil(L);
}

/**
 * task_prctl
 * Default: -ENOSYS
 */
LUA_LSM_INT_DEFINE5(task_prctl, int, option, unsigned long, arg2,
		unsigned long, arg3, unsigned long, arg4, unsigned long, arg5)
{
	switch (option) {
	case PR_SET_PTRACER:
		lua_pushstring(L, "set_ptracer");
		lua_pushinteger(L, (lua_Integer)arg2);
		break;

	default:
		lua_pushinteger(L, (lua_Integer)option);
		lua_pushnumber(L, (lua_Number)arg2);
		lua_pushnumber(L, (lua_Number)arg3);
		lua_pushnumber(L, (lua_Number)arg4);
		lua_pushnumber(L, (lua_Number)arg5);
		break;
	}
}

/**
 * task_to_inode
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(task_to_inode, struct task_struct *, p,
		struct inode *, inode)
{
	*newtask(L) = p;
	*newinode(L) = inode;
}

/**
 * userns_create
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(userns_create, const struct cred *, cred)
{
	*(const struct cred **)newcred(L) = cred;
}

/**
 * ipc_permission
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(ipc_permission, struct kern_ipc_perm *, ipcp, short, flag)
{
	*newipc(L) = ipcp;
	lua_pushinteger(L, (lua_Integer)flag);
}

/**
 * TODO: ipc_getlsmprop
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(ipc_getlsmprop, struct kern_ipc_perm *, ipcp,
		struct lsm_prop *, prop)
{
	*newipc(L) = ipcp;
	lua_pushnil(L);	/* TODO: prop */
}

/**
 * msg_msg_alloc_security - prepare
 */
LUA_LSM_PREPARE_DEFINE1(msg_msg_alloc_security, struct msg_msg *, msg)
{
	struct lua_lsm_object *llo = lua_lsm_msgmsg(msg);
	kvcache_dict_init(&llo->dict);
	return 0;
}

/**
 * msg_msg_alloc_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(msg_msg_alloc_security, struct msg_msg *, msg)
{
	*newmsgmsg(L) = msg;
}

/**
 * msg_msg_free_security - postpone
 */
LUA_LSM_POSTPONE_DEFINE1(msg_msg_free_security, struct msg_msg *, msg)
{
	struct lua_lsm_object *llo = lua_lsm_msgmsg(msg);
	kvcache_dict_free(&llo->dict);
}

/**
 * msg_msg_free_security
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(msg_msg_free_security, struct msg_msg *, msg)
{
	*newmsgmsg(L) = msg;
}

/**
 * msg_queue_alloc_security - prepare
 */
LUA_LSM_PREPARE_DEFINE1(msg_queue_alloc_security, struct kern_ipc_perm *, perm)
{
	struct lua_lsm_object *llo = lua_lsm_ipc(perm);
	kvcache_dict_init(&llo->dict);
	return 0;
}

/**
 * msg_queue_alloc_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(msg_queue_alloc_security, struct kern_ipc_perm *, perm)
{
	*newipc(L) = perm;
}

/**
 * msg_queue_free_security - postpone
 */
LUA_LSM_POSTPONE_DEFINE1(msg_queue_free_security, struct kern_ipc_perm *, perm)
{
	struct lua_lsm_object *llo = lua_lsm_ipc(perm);
	kvcache_dict_free(&llo->dict);
}

/**
 * msg_queue_free_security
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(msg_queue_free_security, struct kern_ipc_perm *, perm)
{
	*newipc(L) = perm;
}

/**
 * msg_queue_associate
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(msg_queue_associate, struct kern_ipc_perm *, perm,
		int, msqflg)
{
	*newipc(L) = perm;
	lua_pushinteger(L, (lua_Integer)msqflg);
}

/**
 * msg_queue_msgctl
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(msg_queue_msgctl, struct kern_ipc_perm *, perm, int, cmd)
{
	*newipc(L) = perm;
	lua_pushinteger(L, (lua_Integer)cmd);
}

/**
 * msg_queue_msgsnd
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(msg_queue_msgsnd, struct kern_ipc_perm *, perm,
		struct msg_msg *, msg, int, msqflg)
{
	*newipc(L) = perm;
	*newmsgmsg(L) = msg;
	lua_pushinteger(L, (lua_Integer)msqflg);
}

/**
 * TODO: msg_queue_msgrcv
 * Default: 0
 */
LUA_LSM_INT_DEFINE5(msg_queue_msgrcv, struct kern_ipc_perm *, perm,
		struct msg_msg *, msg, struct task_struct *, target,
		long, type, int, mode)
{
	*newipc(L) = perm;
	*newmsgmsg(L) = msg;
	*newtask(L) = target;
	lua_pushnil(L);	/* TODO: type */
	lua_pushinteger(L, (lua_Integer)mode);
}

/**
 * shm_alloc_security - prepare
 */
LUA_LSM_PREPARE_DEFINE1(shm_alloc_security, struct kern_ipc_perm *, perm)
{
	struct lua_lsm_object *llo = lua_lsm_ipc(perm);
	kvcache_dict_init(&llo->dict);
	return 0;
}

/**
 * shm_alloc_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(shm_alloc_security, struct kern_ipc_perm *, perm)
{
	*newipc(L) = perm;
}

/**
 * shm_free_security - postpone
 */
LUA_LSM_POSTPONE_DEFINE1(shm_free_security, struct kern_ipc_perm *, perm)
{
	struct lua_lsm_object *llo = lua_lsm_ipc(perm);
	kvcache_dict_free(&llo->dict);
}

/**
 * shm_free_security
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(shm_free_security, struct kern_ipc_perm *, perm)
{
	*newipc(L) = perm;
}

/**
 * shm_associate
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(shm_associate, struct kern_ipc_perm *, perm, int, shmflg)
{
	*newipc(L) = perm;
	lua_pushinteger(L, (lua_Integer)shmflg);
}

/**
 * shm_shmctl
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(shm_shmctl, struct kern_ipc_perm *, perm, int, cmd)
{
	*newipc(L) = perm;
	lua_pushinteger(L, (lua_Integer)cmd);
}

/**
 * TODO: shm_shmat
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(shm_shmat, struct kern_ipc_perm *, perm,
		char __user *, shmaddr, int, shmflg)
{
	*newipc(L) = perm;
	lua_pushnil(L);	/* TODO: shmaddr */
	lua_pushinteger(L, (lua_Integer)shmflg);
}

/**
 * sem_alloc_security - prepare
 */
LUA_LSM_PREPARE_DEFINE1(sem_alloc_security, struct kern_ipc_perm *, perm)
{
	struct lua_lsm_object *llo = lua_lsm_ipc(perm);
	kvcache_dict_init(&llo->dict);
	return 0;
}

/**
 * sem_alloc_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(sem_alloc_security, struct kern_ipc_perm *, perm)
{
	*newipc(L) = perm;
}

/**
 * sem_free_security - postpone
 */
LUA_LSM_POSTPONE_DEFINE1(sem_free_security, struct kern_ipc_perm *, perm)
{
	struct lua_lsm_object *llo = lua_lsm_ipc(perm);
	kvcache_dict_free(&llo->dict);
}

/**
 * sem_free_security
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(sem_free_security, struct kern_ipc_perm *, perm)
{
	*newipc(L) = perm;
}

/**
 * sem_associate
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(sem_associate, struct kern_ipc_perm *, perm, int, semflg)
{
	*newipc(L) = perm;
	lua_pushinteger(L, (lua_Integer)semflg);
}

/**
 * sem_semctl
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(sem_semctl, struct kern_ipc_perm *, perm, int, cmd)
{
	*newipc(L) = perm;
	lua_pushinteger(L, (lua_Integer)cmd);
}

/**
 * TODO: sem_semop
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(sem_semop, struct kern_ipc_perm *, perm,
		struct sembuf *, sops, unsigned, nsops, int, alter)
{
	*newipc(L) = perm;
	lua_pushnil(L);	/* TODO: sops */
	lua_pushinteger(L, (lua_Integer)nsops);
	lua_pushinteger(L, (lua_Integer)alter);
}

/**
 * netlink_send
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(netlink_send, struct sock *, sk, struct sk_buff *, skb)
{
	*newsock(L) = sk;
	*newskb(L) = skb;
}

/**
 * d_instantiate
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(d_instantiate, struct dentry *, dentry,
		struct inode *, inode)
{
	dentry ? *newdentry(L) = dentry : lua_pushnil(L);
	inode ? *newinode(L) = inode : lua_pushnil(L);
}

/**
 * TODO: getselfattr
 * Default: -EOPNOTSUPP
 */
LUA_LSM_INT_DEFINE4(getselfattr, unsigned int, attr,
		struct lsm_ctx __user *, ctx, u32 *, size, u32, flags)
{
	lua_pushinteger(L, (lua_Integer)attr);
	lua_pushnil(L);	/* TODO: ctx */
	lua_pushnil(L);	/* TODO: size */
	lua_pushinteger(L, (lua_Integer)flags);
}

/**
 * TODO: setselfattr
 * Default: -EOPNOTSUPP
 */
LUA_LSM_INT_DEFINE4(setselfattr, unsigned int, attr, struct lsm_ctx *, ctx,
		u32, size, u32, flags)
{
	lua_pushinteger(L, (lua_Integer)attr);
	lua_pushnil(L);	/* TODO: ctx */
	lua_pushinteger(L, (lua_Integer)size);
	lua_pushinteger(L, (lua_Integer)flags);
}

/**
 * TODO: getprocattr
 * Default: -EINVAL
 */
LUA_LSM_INT_DEFINE3(getprocattr, struct task_struct *, p,
		const char *, name, char **, value)
{
	*newtask(L) = p;
	lua_pushstring(L, name);
	lua_pushnil(L);	/* TODO: value */
}

/**
 * setprocattr
 * Default: -EINVAL
 */
LUA_LSM_INT_DEFINE3(setprocattr, const char *, name,
		void *, value, size_t, size)
{
	lua_pushstring(L, name);
	lua_pushlstring(L, value, size);
}

/**
 * ismaclabel
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(ismaclabel, const char *, name)
{
	lua_pushstring(L, name);
}

/**
 * TODO: secid_to_secctx
 * Default: -EOPNOTSUPP
 */
LUA_LSM_INT_DEFINE2(secid_to_secctx, u32, secid, struct lsm_context *, cp)
{
	lua_pushinteger(L, (lua_Integer)secid);
	lua_pushnil(L);	/* TODO: cp */
}

/**
 * TODO: lsmprop_to_secctx
 * Default: -EOPNOTSUPP
 */
LUA_LSM_INT_DEFINE2(lsmprop_to_secctx, struct lsm_prop *, prop,
		struct lsm_context *, cp)
{
	lua_pushnil(L);	/* TODO: prop */
	lua_pushnil(L);	/* TODO: cp */
}

/**
 * TODO: secctx_to_secid
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(secctx_to_secid, const char *, secdata,
		u32, seclen, u32 *, secid)
{
	lua_pushstring(L, secdata);
	lua_pushinteger(L, (lua_Integer)seclen);
	lua_pushnil(L);	/* TODO: secid */
}

/**
 * TODO: release_secctx
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(release_secctx, struct lsm_context *, cp)
{
	lua_pushnil(L);	/* TODO: cp */
}

/**
 * inode_invalidate_secctx
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(inode_invalidate_secctx, struct inode *, inode)
{
	*newinode(L) = inode;
}

/**
 * TODO: inode_notifysecctx
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(inode_notifysecctx, struct inode *, inode,
		void *, ctx, u32, ctxlen)
{
	*newinode(L) = inode;
	lua_pushnil(L);	/* TODO: ctx */
	lua_pushinteger(L, (lua_Integer)ctxlen);
}

/**
 * TODO: inode_setsecctx
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(inode_setsecctx, struct dentry *, dentry,
		void *, ctx, u32, ctxlen)
{
	*newdentry(L) = dentry;
	lua_pushnil(L);	/* TODO: ctx */
	lua_pushinteger(L, (lua_Integer)ctxlen);
}

/**
 * TODO: inode_getsecctx
 * Default: -EOPNOTSUPP
 */
LUA_LSM_INT_DEFINE2(inode_getsecctx, struct inode *, inode,
		struct lsm_context *, cp)
{
	*newinode(L) = inode;
	lua_pushnil(L);	/* TODO: cp */
}

#if defined(CONFIG_SECURITY) && defined(CONFIG_WATCH_QUEUE)

/**
 * TODO: post_notification
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(post_notification, const struct cred *, w_cred,
		const struct cred *, cred, struct watch_notification *, n)
{
	*(const struct cred **)newcred(L) = w_cred;
	*(const struct cred **)newcred(L) = cred;
	lua_pushnil(L);	/* TODO: n */
}

#endif /* CONFIG_SECURITY && CONFIG_WATCH_QUEUE */

#if defined(CONFIG_SECURITY) && defined(CONFIG_KEY_NOTIFICATIONS)

/**
 * watch_key
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(watch_key, struct key *, key)
{
	*newkey(L) = key;
}

#endif /* CONFIG_SECURITY && CONFIG_KEY_NOTIFICATIONS */

#ifdef CONFIG_SECURITY_NETWORK

/**
 * unix_stream_connect
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(unix_stream_connect, struct sock *, sock,
		struct sock *, other, struct sock *, newsk)
{
	*newsock(L) = sock;
	*newsock(L) = other;
	*newsock(L) = newsk;
}

/**
 * unix_may_send
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(unix_may_send, struct socket *, sock,
		struct socket *, other)
{
	*newsocket(L) = sock;
	*newsocket(L) = other;
}

/**
 * socket_create
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(socket_create, int, family, int, type,
		int, protocol, int, kern)
{
	lua_pushinteger(L, (lua_Integer)family);
	lua_pushinteger(L, (lua_Integer)type);
	lua_pushinteger(L, (lua_Integer)protocol);
	lua_pushinteger(L, (lua_Integer)kern);
}

/**
 * socket_post_create
 * Default: 0
 */
LUA_LSM_INT_DEFINE5(socket_post_create, struct socket *, sock,
		int, family, int, type, int, protocol, int, kern)
{
	*newsocket(L) = sock;
	lua_pushinteger(L, (lua_Integer)family);
	lua_pushinteger(L, (lua_Integer)type);
	lua_pushinteger(L, (lua_Integer)protocol);
	lua_pushinteger(L, (lua_Integer)kern);
}

/**
 * socket_socketpair
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(socket_socketpair, struct socket *, socka,
		struct socket *, sockb)
{
	*newsocket(L) = socka;
	*newsocket(L) = sockb;
}

static int build_sockaddr(lua_State *L, struct sockaddr *address, int addrlen)
{
	if (addrlen < offsetofend(struct sockaddr, sa_family))
		return 0;

	switch (address->sa_family) {
	case AF_INET:
		if (addrlen < sizeof(struct sockaddr_in))
			return 0;
		break;
	case AF_INET6:
		if (addrlen < SIN6_LEN_RFC2133)
			return 0;
		break;
	}
	*newsockaddr(L) = address;
	return 1;
}

/**
 * socket_bind
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(socket_bind, struct socket *, sock,
		struct sockaddr *, address, int, addrlen)
{
	*newsocket(L) = sock;
	build_sockaddr(L, address, addrlen);
}

/**
 * socket_connect
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(socket_connect, struct socket *, sock,
		struct sockaddr *, address, int, addrlen)
{
	*newsocket(L) = sock;
	build_sockaddr(L, address, addrlen);
}

/**
 * socket_listen
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(socket_listen, struct socket *, sock, int, backlog)
{
	*newsocket(L) = sock;
	lua_pushinteger(L, (lua_Integer)backlog);
}

/**
 * socket_accept
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(socket_accept, struct socket *, sock,
		struct socket *, newsock)
{
	*newsocket(L) = sock;
	*newsocket(L) = newsock;
}

/**
 * TODO: socket_sendmsg
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(socket_sendmsg, struct socket *, sock,
		struct msghdr *, msg, int, size)
{
	*newsocket(L) = sock;
	lua_pushnil(L);	/* TODO: msg */
	lua_pushinteger(L, (lua_Integer)size);
}

/**
 * TODO: socket_recvmsg
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(socket_recvmsg, struct socket *, sock,
		struct msghdr *, msg, int, size, int, flags)
{
	*newsocket(L) = sock;
	lua_pushnil(L);	/* TODO: msg */
	lua_pushinteger(L, (lua_Integer)size);
	lua_pushinteger(L, (lua_Integer)flags);
}

/**
 * socket_getsockname
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(socket_getsockname, struct socket *, sock)
{
	*newsocket(L) = sock;
}

/**
 * socket_getpeername
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(socket_getpeername, struct socket *, sock)
{
	*newsocket(L) = sock;
}

/**
 * socket_getsockopt
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(socket_getsockopt, struct socket *, sock,
		int, level, int, optname)
{
	*newsocket(L) = sock;
	lua_pushinteger(L, (lua_Integer)level);
	lua_pushinteger(L, (lua_Integer)optname);
}

/**
 * socket_setsockopt
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(socket_setsockopt, struct socket *, sock,
		int, level, int, optname)
{
	*newsocket(L) = sock;
	lua_pushinteger(L, (lua_Integer)level);
	lua_pushinteger(L, (lua_Integer)optname);
}

/**
 * socket_shutdown
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(socket_shutdown, struct socket *, sock, int, how)
{
	*newsocket(L) = sock;
	lua_pushinteger(L, (lua_Integer)how);
}

/**
 * socket_sock_rcv_skb
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(socket_sock_rcv_skb, struct sock *, sk,
		struct sk_buff *, skb)
{
	*newsock(L) = sk;
	*newskb(L) = skb;
}

/**
 * TODO: socket_getpeersec_stream
 * Default: -ENOPROTOOPT
 */
LUA_LSM_INT_DEFINE4(socket_getpeersec_stream, struct socket *, sock,
		sockptr_t, optval, sockptr_t, optlen, unsigned int, len)
{
	*newsocket(L) = sock;
	lua_pushnil(L);	/* TODO: optval */
	lua_pushnil(L);	/* TODO: optlen */
	lua_pushinteger(L, (lua_Integer)len);
}

/**
 * TODO: socket_getpeersec_dgram
 * Default: -ENOPROTOOPT
 */
LUA_LSM_INT_DEFINE3(socket_getpeersec_dgram, struct socket *, sock,
		struct sk_buff *, skb, u32 *, secid)
{
	*newsocket(L) = sock;
	skb ? *newskb(L) = skb : lua_pushnil(L);
	lua_pushnil(L);	/* TODO: secid */
}

/**
 * sk_alloc_security - prepare
 */
LUA_LSM_PREPARE_DEFINE3(sk_alloc_security, struct sock *, sk,
		int, family, gfp_t, priority)
{
	struct lua_lsm_object *llo = lua_lsm_sock(sk);
	kvcache_dict_init(&llo->dict);
	return 0;
}

/**
 * sk_alloc_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(sk_alloc_security, struct sock *, sk,
		int, family, gfp_t, priority)
{
	*newsock(L) = sk;
	lua_pushinteger(L, (lua_Integer)family);
	lua_pushinteger(L, (lua_Integer)priority);
}

/**
 * sk_free_security - postpone
 */
LUA_LSM_POSTPONE_DEFINE1(sk_free_security, struct sock *, sk)
{
	struct lua_lsm_object *llo = lua_lsm_sock(sk);
	kvcache_dict_free(&llo->dict);
}

/**
 * sk_free_security
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(sk_free_security, struct sock *, sk)
{
	*newsock(L) = sk;
}

/**
 * sk_clone_security
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(sk_clone_security, const struct sock *, sk,
		struct sock *, newsk)
{
	*(const struct sock **)newsock(L) = sk;
	*newsock(L) = newsk;
}

/**
 * TODO: sk_getsecid
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(sk_getsecid, const struct sock *, sk, u32 *, secid)
{
	*(const struct sock **)newsock(L) = sk;
	lua_pushnil(L);	/* TODO: secid */
}

/**
 * sock_graft
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(sock_graft, struct sock *, sk, struct socket *, parent)
{
	*newsock(L) = sk;
	*newsocket(L) = parent;
}

/**
 * TODO: inet_conn_request
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(inet_conn_request, const struct sock *, sk,
		struct sk_buff *, skb, struct request_sock *, req)
{
	*(const struct sock **)newsock(L) = sk;
	*newskb(L) = skb;
	lua_pushnil(L);	/* TODO: req */
}

/**
 * TODO: inet_csk_clone
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(inet_csk_clone, struct sock *, newsk,
		const struct request_sock *, req)
{
	*newsock(L) = newsk;
	lua_pushnil(L);	/* TODO: req */
}

/**
 * inet_conn_established
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(inet_conn_established, struct sock *, sk,
		struct sk_buff *, skb)
{
	*newsock(L) = sk;
	*newskb(L) = skb;
}

/**
 * secmark_relabel_packet
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(secmark_relabel_packet, u32, secid)
{
	lua_pushinteger(L, (lua_Integer)secid);
}

/**
 * secmark_refcount_inc
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE0(secmark_refcount_inc)
{
	return;
}

/**
 * secmark_refcount_dec
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE0(secmark_refcount_dec)
{
	return;
}

/**
 * TODO: req_classify_flow
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE2(req_classify_flow, const struct request_sock *, req,
		struct flowi_common *, flic)
{
	lua_pushnil(L);	/* TODO: req */
	lua_pushnil(L);	/* TODO: flic */
}

/**
 * TODO: tun_dev_alloc_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(tun_dev_alloc_security, void *, security)
{
	lua_pushnil(L);	/* TODO: security */
}

/**
 * tun_dev_create
 * Default: 0
 */
LUA_LSM_INT_DEFINE0(tun_dev_create)
{
	return;
}

/**
 * TODO: tun_dev_attach_queue
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(tun_dev_attach_queue, void *, security)
{
	lua_pushnil(L);	/* TODO: security */
}

/**
 * TODO: tun_dev_attach
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(tun_dev_attach, struct sock *, sk, void *, security)
{
	*newsock(L) = sk;
	lua_pushnil(L);	/* TODO: security */
}

/**
 * TODO: tun_dev_open
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(tun_dev_open, void *, security)
{
	lua_pushnil(L);	/* TODO: security */
}

/**
 * TODO: sctp_assoc_request
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(sctp_assoc_request, struct sctp_association *, asoc,
		struct sk_buff *, skb)
{
	lua_pushnil(L);	/* TODO: asoc */
	*newskb(L) = skb;
}

/**
 * sctp_bind_connect
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(sctp_bind_connect, struct sock *, sk, int, optname,
		struct sockaddr *, address, int, addrlen)
{
	*newsock(L) = sk;
	lua_pushinteger(L, (lua_Integer)optname);
	build_sockaddr(L, address, addrlen);
}

/**
 * TODO: sctp_sk_clone
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE3(sctp_sk_clone, struct sctp_association *, asoc,
		struct sock *, sk, struct sock *, newsk)
{
	lua_pushnil(L);	/* TODO: asoc */
	*newsock(L) = sk;
	*newsock(L) = newsk;
}

/**
 * TODO: sctp_assoc_established
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(sctp_assoc_established, struct sctp_association *, asoc,
		struct sk_buff *, skb)
{
	lua_pushnil(L);	/* TODO: asoc */
	*newskb(L) = skb;
}

/**
 * mptcp_add_subflow
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(mptcp_add_subflow, struct sock *, sk, struct sock *, ssk)
{
	*newsock(L) = sk;
	*newsock(L) = ssk;
}

#endif /* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_INFINIBAND

/**
 * TODO: ib_pkey_access
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(ib_pkey_access, void *, sec, u64, subnet_prefix, u16, pkey)
{
	lua_pushnil(L);	/* TODO: sec */
	lua_pushnumber(L, (lua_Number)subnet_prefix);
	lua_pushinteger(L, (lua_Integer)pkey);
}

/**
 * TODO: ib_endport_manage_subnet
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(ib_endport_manage_subnet, void *, sec,
		const char *, dev_name, u8, port_num)
{
	lua_pushnil(L);	/* TODO: sec */
	lua_pushstring(L, dev_name);
	lua_pushinteger(L, (lua_Integer)port_num);
}

/**
 * TODO: ib_alloc_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(ib_alloc_security, void *, sec)
{
	lua_pushnil(L);	/* TODO: sec */
}

#endif /* CONFIG_SECURITY_INFINIBAND */

#ifdef CONFIG_SECURITY_NETWORK_XFRM

/**
 * TODO: xfrm_policy_alloc_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(xfrm_policy_alloc_security, struct xfrm_sec_ctx **, ctxp,
		struct xfrm_user_sec_ctx *, sec_ctx, gfp_t, gfp)
{
	lua_pushnil(L);	/* TODO: ctxp */
	lua_pushnil(L);	/* TODO: sec_ctx */
	lua_pushinteger(L, (lua_Integer)gfp);
}

/**
 * TODO: xfrm_policy_clone_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(xfrm_policy_clone_security, struct xfrm_sec_ctx *, old_ctx,
		struct xfrm_sec_ctx **, new_ctx)
{
	lua_pushnil(L);	/* TODO: old_ctx */
	lua_pushnil(L);	/* TODO: new_ctx */
}

/**
 * TODO: xfrm_policy_free_security
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(xfrm_policy_free_security, struct xfrm_sec_ctx *, ctx)
{
	lua_pushnil(L);	/* TODO: ctx */
}

/**
 * TODO: xfrm_policy_delete_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(xfrm_policy_delete_security, struct xfrm_sec_ctx *, ctx)
{
	lua_pushnil(L);	/* TODO: ctx */
}

/**
 * TODO: xfrm_state_alloc
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(xfrm_state_alloc, struct xfrm_state *, x,
		struct xfrm_user_sec_ctx *, sec_ctx)
{
	lua_pushnil(L);	/* TODO: x */
	lua_pushnil(L);	/* TODO: sec_ctx */
}

/**
 * TODO: xfrm_state_alloc_acquire
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(xfrm_state_alloc_acquire, struct xfrm_state *, x,
		struct xfrm_sec_ctx *, polsec, u32, secid)
{
	lua_pushnil(L);	/* TODO: x */
	lua_pushnil(L);	/* TODO: polsec */
	lua_pushinteger(L, (lua_Integer)secid);
}

/**
 * TODO: xfrm_state_free_security
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(xfrm_state_free_security, struct xfrm_state *, x)
{
	lua_pushnil(L);	/* TODO: x */
}

/**
 * TODO: xfrm_state_delete_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(xfrm_state_delete_security, struct xfrm_state *, x)
{
	lua_pushnil(L);	/* TODO: x */
}

/**
 * TODO: xfrm_policy_lookup
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(xfrm_policy_lookup, struct xfrm_sec_ctx *, ctx,
		u32, fl_secid)
{
	lua_pushnil(L);	/* TODO: ctx */
	lua_pushinteger(L, (lua_Integer)fl_secid);
}

/**
 * TODO: xfrm_state_pol_flow_match
 * Default: 1
 */
LUA_LSM_INT_DEFINE3(xfrm_state_pol_flow_match, struct xfrm_state *, x,
		struct xfrm_policy *, xp, const struct flowi_common *, flic)
{
	lua_pushnil(L);	/* TODO: x */
	lua_pushnil(L);	/* TODO: xp */
	lua_pushnil(L);	/* TODO: flic */
}

/**
 * TODO: xfrm_decode_session
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(xfrm_decode_session, struct sk_buff *, skb, u32 *, secid,
		int, ckall)
{
	*newskb(L) = skb;
	lua_pushnil(L);	/* TODO: secid */
	lua_pushinteger(L, (lua_Integer)ckall);
}

#endif /* CONFIG_SECURITY_NETWORK_XFRM */

#ifdef CONFIG_KEYS

/**
 * key_alloc
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(key_alloc, struct key *, key, const struct cred *, cred,
		unsigned long, flags)
{
	*newkey(L) = key;
	*(const struct cred **)newcred(L) = cred;
	lua_pushnumber(L, (lua_Number)flags);
}

/**
 * TODO: key_permission
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(key_permission, key_ref_t, key_ref,
		const struct cred *, cred, enum key_need_perm, need_perm)
{
	lua_pushnil(L);	/* TODO: key_ref */
	*(const struct cred **)newcred(L) = cred;
	lua_pushnil(L);	/* TODO: need_perm */
}

/**
 * TODO: key_getsecurity
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(key_getsecurity, struct key *, key, char **, buffer)
{
	*newkey(L) = key;
	lua_pushnil(L);	/* TODO: buffer */
}

/**
 * key_post_create_or_update
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE6(key_post_create_or_update, struct key *, keyring,
		struct key *, key, const void *, payload, size_t, payload_len,
		unsigned long, flags, bool, create)
{
	*newkey(L) = keyring;
	*newkey(L) = key;
	lua_pushlstring(L, payload, payload_len);
	lua_pushnumber(L, (lua_Number)flags);
	lua_pushboolean(L, (int)create);
}

#endif /* CONFIG_KEYS */

#ifdef CONFIG_AUDIT

/**
 * TODO: audit_rule_init
 * Default: 0
 */
LUA_LSM_INT_DEFINE5(audit_rule_init, u32, field, u32, op, char *, rulestr,
		void **, lsmrule, gfp_t, gfp)
{
	lua_pushinteger(L, (lua_Integer)field);
	lua_pushinteger(L, (lua_Integer)op);
	lua_pushstring(L, (const char *)rulestr);
	lua_pushnil(L);	/* TODO: lsmrule */
	lua_pushinteger(L, (lua_Integer)gfp);
}

/**
 * TODO: audit_rule_known
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(audit_rule_known, struct audit_krule *, krule)
{
	lua_pushnil(L);	/* TODO: krule */
}

/**
 * TODO: audit_rule_match
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(audit_rule_match, struct lsm_prop *, prop, u32, field,
		u32, op, void *, lsmrule)
{
	lua_pushnil(L);	/* TODO: prop */
	lua_pushinteger(L, (lua_Integer)field);
	lua_pushinteger(L, (lua_Integer)op);
	lua_pushnil(L);	/* TODO: lsmrule */
}

/**
 * TODO: audit_rule_free
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(audit_rule_free, void *, lsmrule)
{
	lua_pushnil(L);	/* TODO: lsmrule */
}

#endif /* CONFIG_AUDIT */

#ifdef CONFIG_BPF_SYSCALL

/**
 * TODO: bpf
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(bpf, int, cmd, union bpf_attr *, attr, unsigned int, size,
		bool, kernel)
{
	lua_pushinteger(L, (lua_Integer)cmd);
	lua_pushnil(L);	/* TODO: attr */
	lua_pushinteger(L, (lua_Integer)size);
	lua_pushboolean(L, kernel);
}

/**
 * TODO: bpf_map
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(bpf_map, struct bpf_map *, map, fmode_t, fmode)
{
	lua_pushnil(L);	/* TODO: map */
	lua_pushinteger(L, (lua_Integer)fmode);
}

/**
 * TODO: bpf_prog
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(bpf_prog, struct bpf_prog *, prog)
{
	lua_pushnil(L);	/* TODO: prog */
}

/**
 * TODO: bpf_map_create
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(bpf_map_create, struct bpf_map *, map,
		union bpf_attr *, attr, struct bpf_token *, token, bool, kernel)
{
	lua_pushnil(L);	/* TODO: map */
	lua_pushnil(L);	/* TODO: attr */
	lua_pushnil(L);	/* TODO: token */
	lua_pushboolean(L, kernel);
}

/**
 * TODO: bpf_map_free
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(bpf_map_free, struct bpf_map *, map)
{
	lua_pushnil(L);	/* TODO: map */
}

/**
 * TODO: bpf_prog_load
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(bpf_prog_load, struct bpf_prog *, prog,
		union bpf_attr *, attr, struct bpf_token *, token, bool, kernel)
{
	lua_pushnil(L);	/* TODO: prog */
	lua_pushnil(L);	/* TODO: attr */
	lua_pushnil(L);	/* TODO: token */
	lua_pushboolean(L, kernel);
}

/**
 * TODO: bpf_prog_free
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(bpf_prog_free, struct bpf_prog *, prog)
{
	lua_pushnil(L);	/* TODO: prog */
}

/**
 * TODO: bpf_token_create
 * Default: 0
 */
LUA_LSM_INT_DEFINE3(bpf_token_create, struct bpf_token *, token,
		union bpf_attr *, attr, const struct path *, path)
{
	lua_pushnil(L);	/* TODO: token */
	lua_pushnil(L);	/* TODO: attr */
	*(const struct path **)newpath(L) = path;
}

/**
 * TODO: bpf_token_free
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(bpf_token_free, struct bpf_token *, token)
{
	lua_pushnil(L);	/* TODO: token */
}

/**
 * TODO: bpf_token_cmd
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(bpf_token_cmd, const struct bpf_token *, token,
		enum bpf_cmd, cmd)
{
	lua_pushnil(L);	/* TODO: token */
	lua_pushnil(L);	/* TODO: cmd */
}

/**
 * TODO: bpf_token_capable
 * Default: 0
 */
LUA_LSM_INT_DEFINE2(bpf_token_capable, const struct bpf_token *, token,
		int, cap)
{
	lua_pushnil(L);	/* TODO: token */
	lua_pushinteger(L, (lua_Integer)cap);
}

#endif /* CONFIG_BPF_SYSCALL */

/**
 * TODO: locked_down
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(locked_down, enum lockdown_reason, what)
{
	lua_pushnil(L);	/* TODO: what */
}

#ifdef CONFIG_PERF_EVENTS

/**
 * perf_event_open
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(perf_event_open, int, type)
{
	lua_pushinteger(L, (lua_Integer)type);
}

/**
 * perf_event_alloc
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(perf_event_alloc, struct perf_event *, event)
{
	*newperfevent(L) = event;
}

/**
 * perf_event_read
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(perf_event_read, struct perf_event *, event)
{
	*newperfevent(L) = event;
}

/**
 * perf_event_write
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(perf_event_write, struct perf_event *, event)
{
	*newperfevent(L) = event;
}

#endif /* CONFIG_PERF_EVENTS */

#ifdef CONFIG_IO_URING

/**
 * uring_override_creds
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(uring_override_creds, const struct cred *, new)
{
	*(const struct cred **)newcred(L) = new;
}

/**
 * uring_sqpoll
 * Default: 0
 */
LUA_LSM_INT_DEFINE0(uring_sqpoll)
{
	return;
}

/**
 * TODO: uring_cmd
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(uring_cmd, struct io_uring_cmd *, ioucmd)
{
	lua_pushnil(L);	/* TODO: ioucmd */
}

/**
 * uring_allowed
 * Default: 0
 */
LUA_LSM_INT_DEFINE0(uring_allowed)
{
	return;
}

#endif /* CONFIG_IO_URING */

/**
 * initramfs_populated
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE0(initramfs_populated)
{
	return;
}

/**
 * bdev_alloc_security - prepare
 */
LUA_LSM_PREPARE_DEFINE1(bdev_alloc_security, struct block_device *, bdev)
{
	struct lua_lsm_object *llo = lua_lsm_bdev(bdev);
	kvcache_dict_init(&llo->dict);
	return 0;
}

/**
 * bdev_alloc_security
 * Default: 0
 */
LUA_LSM_INT_DEFINE1(bdev_alloc_security, struct block_device *, bdev)
{
	*newbdev(L) = bdev;
}

/**
 * bdev_free_security - postpone
 */
LUA_LSM_POSTPONE_DEFINE1(bdev_free_security, struct block_device *, bdev)
{
	struct lua_lsm_object *llo = lua_lsm_bdev(bdev);
	kvcache_dict_free(&llo->dict);
}

/**
 * bdev_free_security
 * Default: LSM_RET_VOID
 */
LUA_LSM_VOID_DEFINE1(bdev_free_security, struct block_device *, bdev)
{
	*newbdev(L) = bdev;
}

/**
 * TODO: bdev_setintegrity
 * Default: 0
 */
LUA_LSM_INT_DEFINE4(bdev_setintegrity, struct block_device *, bdev,
		enum lsm_integrity_type, type,
		const void *, value, size_t, size)
{
	*newbdev(L) = bdev;
	lua_pushnil(L);	/* TODO: type */
	lua_pushnil(L);	/* TODO: value */
	lua_pushnil(L);	/* TODO: size */
}

