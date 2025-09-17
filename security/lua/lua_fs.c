/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#include "debug.h"
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/xattr.h>
#include <linux/binfmts.h>
#include <linux/lua.h>
#include <linux/lualib.h>
#include <linux/lauxlib.h>
#include "lsm.h"
#include "auxlib.h"
#include "kvcache.h"
#include "lua_object.h"

#define FS_PATH_LEN    256

/********************************** util **********************************/

static int fs_xattr(lua_State *L, struct dentry *dentry,
		struct inode *inode, const char *name)
{
	char buffer[128];
	ssize_t len;

	if (!(inode->i_opflags & IOP_XATTR))
		return 0;

	dget(dentry);
	len = __vfs_getxattr(dentry, inode, name, buffer, sizeof(buffer));
	dput(dentry);
	if (len == 0) {
		lua_pushnil(L);
		return 1;
	} else if (len < 0) {
		lua_pushnil(L);
		lua_pushinteger(L, -len);
		return 2;
	} else {
		lua_pushlstring(L, (const char *)buffer, len);
		return 1;
	}
}

/********************************** dentry **********************************/

static int fs_dentry_dget(lua_State *L)
{
	struct dentry *dentry = todentry(L, 1);
	dget(dentry);
	lua_settop(L, 1);
	return 1;
}

static int fs_dentry_dput(lua_State *L)
{
	struct dentry *dentry = todentry(L, 1);
	dput(dentry);
	return 0;
}

static int fs_dentry_backing_inode(lua_State *L)
{
	struct dentry *dentry = todentry(L, 1);
	struct inode **inodep = newinode(L);
	*inodep = d_backing_inode(dentry);
	settopfenvfrom(L, 1);
	return 1;
}

static int fs_dentry_path(lua_State *L)
{
	struct dentry *dentry = todentry(L, 1);
	int use_path = lua_toboolean(L, 2);
	char buffer[FS_PATH_LEN];
	char *path;
	if (use_path)
		path = dentry_path(dentry, buffer, sizeof(buffer));
	else
		path = dentry_path_raw(dentry, buffer, sizeof(buffer));
	if (path == NULL)
		return 0;
	lua_pushstring(L, path);
	return 1;
}

static int fs_dentry_xattr(lua_State *L)
{
	struct dentry *dentry = todentry(L, 1);
	struct inode *inode = toinode(L, 2);
	const char *name = luaL_checkstring(L, 3);
	return fs_xattr(L, dentry, inode, name);
}

static const luaL_Reg fs_dentry_meth[] = {
	{ "dget",		fs_dentry_dget		},
	{ "dput",		fs_dentry_dput		},
	{ "backing_inode",	fs_dentry_backing_inode	},
	{ "path",		fs_dentry_path		},
	{ "xattr",		fs_dentry_xattr		},
	{ NULL, NULL }
};

/********************************** inode **********************************/

static int fs_inode_ino(lua_State *L)
{
	struct inode *inode = toinode(L, 1);
	lua_pushinteger(L, inode->i_ino);
	return 1;
}

static int fs_inode_xattr(lua_State *L)
{
	struct inode *inode = toinode(L, 1);
	struct dentry *dentry = todentry(L, 2);
	const char *name = luaL_checkstring(L, 3);
	return fs_xattr(L, dentry, inode, name);
}

static int fs_inode_size(lua_State *L)
{
	struct inode *inode = toinode(L, 1);
	lua_pushinteger(L, i_size_read(inode));
	return 1;
}

static const luaL_Reg fs_inode_meth[] = {
	{ "ino",	fs_inode_ino	},
	{ "xattr",	fs_inode_xattr	},
	{ "size",	fs_inode_size	},
	{ NULL, NULL }
};

/********************************** file **********************************/

static int fs_file_fput(lua_State *L)
{
	struct file *file = tofile(L, 1);
	fput(file);
	return 0;
}

static int fs_file_path(lua_State *L)
{
	struct file *file = tofile(L, 1);
	char buffer[FS_PATH_LEN];
	char *path = file_path(file, buffer, sizeof(buffer));
	if (IS_ERR(path)) {
		lua_pushnil(L);
		lua_pushinteger(L, PTR_ERR(path));
		return 2;
	}
	lua_pushstring(L, path);
	return 1;
}

static int fs_file_dentry(lua_State *L)
{
	const struct file *file = tofile(L, 1);
	struct dentry **dentryp = newdentry(L);
	*dentryp = file_dentry(file);
	settopfenvfrom(L, 1);
	return 1;
}

static int fs_file_inode(lua_State *L)
{
	struct file *file = tofile(L, 1);
	struct inode **inodep = newinode(L);
	*inodep = file_inode(file);
	settopfenvfrom(L, 1);
	return 1;
}

static int fs_file_xattr(lua_State *L)
{
	struct file *file = tofile(L, 1);
	const char *name = luaL_checkstring(L, 2);
	return fs_xattr(L, file_dentry(file), file_inode(file), name);
}

static int fs_file_size(lua_State *L)
{
	struct file *file = tofile(L, 1);
	lua_pushinteger(L, i_size_read(file_inode(file)));
	return 1;
}

/*
 * table = file:fmode()
 * bool = file:fmode('read')
 * bool = file:fmode(true, 'read', 'exec')
 */
static int fs_file_fmode(lua_State *L)
{
	static const struct cflag_opt opts[] = {
		{ "read",	FMODE_READ	},
		{ "write",	FMODE_WRITE	},
		{ "exec",	FMODE_EXEC	},
		{ "opened",	FMODE_OPENED	},
		{ "created",	FMODE_CREATED	},
		{ NULL, 0 }
	};
	struct file *file = tofile(L, 1);
	int top = lua_gettop(L);
	if (top >= 2) {
		int start = (top == 2) ? 2 : 3;
		int and = lua_isboolean(L, 2) && lua_toboolean(L, 2);
		fmode_t flags = tocflags(L, start, top, opts, 0);
		fmode_t res = file->f_mode & flags;
		lua_pushboolean(L, and ? res == flags : (int)res);
		return 1;
	} else if (top == 1) {
		table_fromopts(L, opts, 0, (unsigned int)file->f_mode);
		return 1;
	}
	return 0;
}

static const luaL_Reg fs_file_meth[] = {
	{ "fput",	fs_file_fput	},
	{ "path",	fs_file_path	},
	{ "dentry",	fs_file_dentry	},
	{ "inode",	fs_file_inode	},
	{ "xattr",	fs_file_xattr	},
	{ "size",	fs_file_size	},
	{ "fmode",	fs_file_fmode	},
	{ NULL, NULL }
};

/********************************** binprm **********************************/

#define DEF_BINPRM_FIELD(type, name)					\
	static int fs_binprm_ ## name(lua_State *L)			\
	{								\
		struct linux_binprm *bprm = tobinprm(L, 1);		\
		if (bprm->name) {					\
			*new ## type(L) = bprm->name;			\
			/* setfenv(file, getfenv(binprm)) */		\
			settopfenvfrom(L, 1);				\
			return 1;					\
		} else {						\
			return 0;					\
		}							\
	}

DEF_BINPRM_FIELD(file, executable)
DEF_BINPRM_FIELD(file, interpreter)
DEF_BINPRM_FIELD(file, file)
DEF_BINPRM_FIELD(cred, cred)

static const luaL_Reg fs_binprm_meth[] = {
	{ "executable",		fs_binprm_executable	},
	{ "interpreter",	fs_binprm_interpreter	},
	{ "file",		fs_binprm_file		},
	{ "cred",		fs_binprm_cred		},
	{ NULL, NULL }
};

/*********************************** path ************************************/

static int fs_path_vfsmount(lua_State *L)
{
	struct path *path = topath(L, 1);
	*newvfsmount(L) = path->mnt;
	settopfenvfrom(L, 1);
	return 1;
}

static int fs_path_dentry(lua_State *L)
{
	struct path *path = topath(L, 1);
	*newdentry(L) = path->dentry;
	settopfenvfrom(L, 1);
	return 1;
}

static int fs_path_eq(lua_State *L)
{
	struct path *path1 = topath(L, 1);
	struct path *path2 = topath(L, 2);
	lua_pushboolean(L, path_equal(path1, path2));
	return 1;
}

static const luaL_Reg fs_path_meth[] = {
	{ "vfsmount",	fs_path_vfsmount	},
	{ "dentry",	fs_path_dentry		},
	{ "__eq",	fs_path_eq		},
	{ NULL, NULL }
};

/******************************** super_block ********************************/

static int fs_superblock_magic(lua_State *L)
{
	struct super_block *sb = tosuperblock(L, 1);
	lua_pushinteger(L, sb->s_magic);
	return 1;
}

static int fs_superblock_root(lua_State *L)
{
	struct super_block *sb = tosuperblock(L, 1);
	*newdentry(L) = sb->s_root;
	settopfenvfrom(L, 1);
	return 1;
}

static int fs_superblock_fstype_name(lua_State *L)
{
	struct super_block *sb = tosuperblock(L, 1);
	lua_pushstring(L, sb->s_type->name);
	return 1;
}

static const luaL_Reg fs_superblock_meth[] = {
	{ "magic",		fs_superblock_magic		},
	{ "root",		fs_superblock_root		},
	{ "fstype_name",	fs_superblock_fstype_name	},
	{ NULL, NULL }
};

/******************************** fs_context *********************************/

static int fs_fscontext_parse_fs_string(lua_State *L)
{
	struct fs_context *fc = tofscontext(L, 1);
	const char *key = luaL_checkstring(L, 2);
	size_t size;
	const char *value = luaL_checklstring(L, 3, &size);
	int rc = vfs_parse_fs_string(fc, key, value, size);
	lua_pushboolean(L, rc == 0);
	return 1;
}

static const luaL_Reg fs_fscontext_meth[] = {
	{ "parse_fs_string",	fs_fscontext_parse_fs_string	},
	{ NULL, NULL }
};

/********************************* vfsmount **********************************/

static int fs_vfsmount_superblock(lua_State *L)
{
	struct vfsmount *mnt = tovfsmount(L, 1);
	*newsuperblock(L) = mnt->mnt_sb;
	return 1;
}

static int fs_vfsmount_mntidmap(lua_State *L)
{
	struct vfsmount *mnt = tovfsmount(L, 1);
	*newmntidmap(L) = mnt_idmap(mnt);
	return 1;
}

static const luaL_Reg fs_vfsmount_meth[] = {
	{ "superblock",	fs_vfsmount_superblock	},
	{ "mntidmap",	fs_vfsmount_mntidmap	},
	{ NULL, NULL }
};

/********************************* mnt_idmap *********************************/

static int fs_mntidmap_inode_owner_or_capable(lua_State *L)
{
	struct mnt_idmap *idmap = tomntidmap(L, 1);
	const struct inode *inode = toinode(L, 2);
	lua_pushboolean(L, inode_owner_or_capable(idmap, inode));
	return 1;
}

static int fs_mntidmap_capable_wrt_inode_uidgid(lua_State *L)
{
	struct mnt_idmap *idmap = tomntidmap(L, 1);
	const struct inode *inode = toinode(L, 2);
	int cap = luaL_checkint(L, 3);
	lua_pushboolean(L, capable_wrt_inode_uidgid(idmap, inode, cap));
	return 1;
}

static const luaL_Reg fs_mntidmap_meth[] = {
	{ "inode_owner_or_capable",	fs_mntidmap_inode_owner_or_capable	},
	{ "capable_wrt_inode_uidgid",	fs_mntidmap_capable_wrt_inode_uidgid	},
	{ NULL, NULL }
};

/************************************ lib ************************************/

static int fs_filp_open(lua_State *L)
{
	const char *filename = luaL_checkstring(L, 1);
	int flags = luaL_checkinteger(L, 2);
	umode_t mode = luaL_checkinteger(L, 3);
	struct file **filp = newfile(L);
	*filp = filp_open(filename, flags, mode);
	if (IS_ERR(*filp)) {
		lua_pushnil(L);
		lua_pushinteger(L, PTR_ERR(*filp));
		return 2;
	}
	return 1;
}

static const luaL_Reg fslib[] = {
	{ "filp_open",	fs_filp_open	},
	{ NULL, NULL }
};

LUALIB_API int luaopen_fs(lua_State *L)
{
	luaL_newlib(L, fslib);

	create_dentry_meta(L, fs_dentry_meth);
	create_inode_meta(L, fs_inode_meth);
	create_file_meta(L, fs_file_meth);
	create_binprm_meta(L, fs_binprm_meth);
	create_path_meta(L, fs_path_meth);
	create_superblock_meta(L, fs_superblock_meth);
	create_fscontext_meta(L, fs_fscontext_meth);
	create_vfsmount_meta(L, fs_vfsmount_meth);
	create_mntidmap_meta(L, fs_mntidmap_meth);

	return 1;
}
