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
	}
	if (len < 0) {
		lua_pushnil(L);
		lua_pushinteger(L, -len);
		return 2;
	}

	lua_pushlstring(L, (const char *)buffer, len);
	return 1;
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
	struct inode *inode = d_backing_inode(dentry);

	inode ? *newinode(L) = inode : lua_pushnil(L);
	return 1;
}

static int fs_dentry_xattr(lua_State *L)
{
	struct dentry *dentry = todentry(L, 1);
	struct inode *inode = toinode(L, 2);
	const char *name = luaL_checkstring(L, 3);

	return fs_xattr(L, dentry, inode, name);
}

static int fs_dentry_path(lua_State *L)
{
	struct dentry *dentry = todentry(L, 1);
	int rawpath = lua_toboolean(L, 2);

	return aux_dentry_path(L, dentry, rawpath);
}

static int meth_dentry_tostring(lua_State *L)
{
	struct dentry *dentry = todentry(L, 1);
	int nres = aux_dentry_path(L, dentry, 0);

	if (nres == 2)
		lua_pushfstring(L, "dentry: <err = %s>", lua_tostring(L, -1));
	else
		lua_pushfstring(L, "dentry: '%s'", lua_tostring(L, -1));
	return 1;
}

static const luaL_Reg fs_dentry_meth[] = {
	{ "dget",		fs_dentry_dget		},
	{ "dput",		fs_dentry_dput		},
	{ "backing_inode",	fs_dentry_backing_inode	},
	{ "xattr",		fs_dentry_xattr		},
	{ "path",		fs_dentry_path		},
	{ "__tostring",		meth_dentry_tostring	},
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

/*
 * ftype = inode:filetype()
 * bool = inode:filetype('sock')
 */
static int fs_inode_filetype(lua_State *L)
{
	static const struct cflag_opt opts[] = {
		{ "sock",	S_IFSOCK	},
		{ "lnk",	S_IFLNK		},
		{ "reg",	S_IFREG		},
		{ "blk",	S_IFBLK		},
		{ "dir",	S_IFDIR		},
		{ "chr",	S_IFCHR		},
		{ "fifo",	S_IFIFO		},
		{ NULL,	0 }
	};
	struct inode *inode = toinode(L, 1);
	int top = lua_gettop(L);
	int i;

	if (top == 1) {
		for (i = 0; opts[i].name; i++) {
			if ((inode->i_mode & S_IFMT) != opts[i].flag)
				continue;
			lua_pushstring(L, opts[i].name);
			return 1;
		}
	} else if (top == 2) {
		const char *s = luaL_checkstring(L, 2);

		for (i = 0; opts[i].name; i++) {
			if (strcasecmp(s, opts[i].name) != 0)
				continue;
			lua_pushboolean(L,
					(inode->i_mode & S_IFMT) == opts[i].flag);
			return 1;
		}
	}
	return 0;
}

/*
 * permissions_table = inode:mode()
 * bool = inode:mode('suid')
 * bool = inode:mode(true, 'suid', 'xgrp', 'xoth')
 */
static int fs_inode_mode(lua_State *L)
{
	static const struct cflag_opt opts[] = {
		{ "suid",	S_ISUID		},
		{ "sgid",	S_ISGID		},
		{ "vtx",	S_ISVTX		},
		{ "rusr",	S_IRUSR		},
		{ "wusr",	S_IWUSR		},
		{ "xusr",	S_IXUSR		},
		{ "rgrp",	S_IRGRP		},
		{ "wgrp",	S_IWGRP		},
		{ "xgrp",	S_IXGRP		},
		{ "roth",	S_IROTH		},
		{ "woth",	S_IWOTH		},
		{ "xoth",	S_IXOTH		},
		{ NULL,	0 }
	};
	struct inode *inode = toinode(L, 1);
	int top = lua_gettop(L);

	if (top >= 2) {
		int start = (top == 2) ? 2 : 3;
		int and = lua_isboolean(L, 2) && lua_toboolean(L, 2);
		unsigned int flags = tocflags(L, start, top, opts, 0);
		unsigned int res = inode->i_mode & flags;

		lua_pushboolean(L, and ? res == flags : (int)res);
		return 1;
	} else if (top == 1) {
		table_fromopts(L, opts, 0, (unsigned int)inode->i_mode);
		return 1;
	}
	return 0;
}

static int fs_inode_ids(lua_State *L)
{
	struct inode *inode = toinode(L, 1);

	lua_pushinteger(L, inode->i_uid.val);
	lua_pushinteger(L, inode->i_gid.val);
	return 2;
}

static int meth_inode_tostring(lua_State *L)
{
	struct inode *inode = toinode(L, 1);
	char buffer[128];
	int l = snprintf(buffer, sizeof(buffer), "inode: [%lu]", inode->i_ino);

	lua_pushlstring(L, buffer, l);
	return 1;
}

static const luaL_Reg fs_inode_meth[] = {
	{ "ino",	fs_inode_ino		},
	{ "xattr",	fs_inode_xattr		},
	{ "size",	fs_inode_size		},
	{ "filetype",	fs_inode_filetype	},
	{ "mode",	fs_inode_mode		},
	{ "ids",	fs_inode_ids		},
	{ "__tostring",	meth_inode_tostring	},
	{ NULL, NULL }
};

/********************************** file **********************************/

static int fs_file_dentry(lua_State *L)
{
	const struct file *file = tofile(L, 1);
	*newdentry(L) = file_dentry(file);
	return 1;
}

static int fs_file_inode(lua_State *L)
{
	struct file *file = tofile(L, 1);
	*newinode(L) = file_inode(file);
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

static int fs_file_path(lua_State *L)
{
	struct file *file = tofile(L, 1);

	return aux_file_path(L, file);
}

static int meth_file_tostring(lua_State *L)
{
	struct file *file = tofile(L, 1);
	int nres = aux_file_path(L, file);

	if (nres == 2)
		lua_pushfstring(L, "file: <err = %s>", lua_tostring(L, -1));
	else
		lua_pushfstring(L, "file: '%s'", lua_tostring(L, -1));
	return 1;
}

static int meth_file_gc(lua_State *L)
{
	struct file **filp = togcfilep(L, 1);

	if (*filp) {
		fput(*filp);
		*filp = NULL;
	}
	return 0;
}

static const luaL_Reg fs_file_meth[] = {
	{ "dentry",		fs_file_dentry		},
	{ "inode",		fs_file_inode		},
	{ "xattr",		fs_file_xattr		},
	{ "size",		fs_file_size		},
	{ "fmode",		fs_file_fmode		},
	{ "path",		fs_file_path		},
	{ "fput",		meth_file_gc		},
	{ "__tostring",		meth_file_tostring	},
	{ NULL, NULL }
};

static const luaL_Reg fs_file_gc_meth[] = {
	{ "__tostring",		meth_file_tostring	},
	{ "__gc",		meth_file_gc		},
	{ NULL, NULL }
};

/********************************** binprm **********************************/

#define DEF_BINPRM_FIELD(type, name)					\
	static int fs_binprm_ ## name(lua_State *L)			\
	{								\
		struct linux_binprm *bprm = tobinprm(L, 1);		\
		if (bprm->name) {					\
			*new ## type(L) = bprm->name;			\
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
	return 1;
}

static int fs_path_dentry(lua_State *L)
{
	struct path *path = topath(L, 1);
	*newdentry(L) = path->dentry;
	return 1;
}

static int fs_path_eq(lua_State *L)
{
	struct path *path1 = topath(L, 1);
	struct path *path2 = topath(L, 2);

	lua_pushboolean(L, path_equal(path1, path2));
	return 1;
}

static int meth_path_tostring(lua_State *L)
{
	struct path *path = topath(L, 1);
	int nres = aux_dentry_path(L, path->dentry, 0);

	if (nres == 2)
		lua_pushfstring(L, "path: <err = %d>", lua_tostring(L, -1));
	else
		lua_pushfstring(L, "path: '%s'", lua_tostring(L, -1));
	return 1;
}

static const luaL_Reg fs_path_meth[] = {
	{ "vfsmount",	fs_path_vfsmount	},
	{ "dentry",	fs_path_dentry		},
	{ "__eq",	fs_path_eq		},
	{ "__tostring",	meth_path_tostring	},
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
	return 1;
}

static int fs_superblock_fstype_name(lua_State *L)
{
	struct super_block *sb = tosuperblock(L, 1);
	struct file_system_type *type = sb->s_type;

	if (type)
		lua_pushstring(L, type->name);
	else
		lua_pushnil(L);
	return 1;
}

static int meth_superblock_tostring(lua_State *L)
{
	struct super_block *sb = tosuperblock(L, 1);
	struct file_system_type *type = sb->s_type;

	lua_pushfstring(L, "superblock: '%s'", type ? type->name : "<empty>");
	return 1;
}

static const luaL_Reg fs_superblock_meth[] = {
	{ "magic",		fs_superblock_magic		},
	{ "root",		fs_superblock_root		},
	{ "fstype_name",	fs_superblock_fstype_name	},
	{ "__tostring",		meth_superblock_tostring	},
	{ NULL, NULL }
};

/******************************** fs_context *********************************/

static int fs_fscontext_parse_fs_string(lua_State *L)
{
	struct fs_context *fc = tofscontext(L, 1);
	const char *key = luaL_checkstring(L, 2);
	const char *value = luaL_checkstring(L, 3);
	int rc = vfs_parse_fs_string(fc, key, value);
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
	struct file **filp = newgcfile(L);
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

	create_dentry_meta(L, fs_dentry_meth, NULL);
	create_inode_meta(L, fs_inode_meth, NULL);
	create_file_meta(L, fs_file_meth, fs_file_gc_meth);
	create_binprm_meta(L, fs_binprm_meth, NULL);
	create_path_meta(L, fs_path_meth, NULL);
	create_superblock_meta(L, fs_superblock_meth, NULL);
	create_fscontext_meta(L, fs_fscontext_meth, NULL);
	create_vfsmount_meta(L, fs_vfsmount_meth, NULL);
	create_mntidmap_meta(L, fs_mntidmap_meth, NULL);

	return 1;
}
