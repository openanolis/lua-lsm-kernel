/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#include "debug.h"
#include <linux/security.h>
#include <linux/kstrtox.h>
#include "lsm.h"


static bool lua_capable(int cap)
{
	bool allow = true;
	int rc;

	/*
	 * All kernel tasks are privileged
	 */
	if (unlikely(current->flags & PF_KTHREAD))
		return true;

	rc = cap_capable(current_cred(), &init_user_ns, cap, CAP_OPT_NONE);
	if (rc < 0) {
		allow = false;
		__log_info("NO capability: cap = %d, allow=%d\n", cap, allow);
	}

	return allow;
}

static int version_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%u", LUA_LSM_VERSION);
	return 0;
}

static int open_version(struct inode *inode, struct file *filp)
{
	return single_open(filp, version_show, NULL);
}

static const struct file_operations fops_version = {
	.open		= open_version,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};


static ssize_t register_write(struct file *file, const char __user *buf,
			size_t len, loff_t *ppos)
{
	char *buffer;
	int err;

	__log_info("len = %d, %pD\n", (int)len, file);

	if (!lua_capable(CAP_MAC_ADMIN))
		return -EPERM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;
	if (len == 0)
		return -EINVAL;

	buffer = memdup_user_nul(buf, len);
	if (IS_ERR(buffer))
		return PTR_ERR(buffer);

	__log_info("buffer = %s [%d]\n", buffer, (int)len);
	err = lua_module_register(buffer, len);
	kfree(buffer);
	if (err < 0)
		return err;

	return len;
}

static const struct file_operations fops_register = {
	.write		= register_write,
};


static ssize_t unregister_write(struct file *file, const char __user *buf,
		size_t len, loff_t *ppos)
{
	char *buffer, *p;
	int err;

	if (!lua_capable(CAP_MAC_ADMIN))
		return -EPERM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;
	if (len == 0)
		return -EINVAL;

	buffer = memdup_user_nul(buf, len);
	if (IS_ERR(buffer))
		return PTR_ERR(buffer);

	/* remove the tailing '\n' */
	p = &buffer[len - 1];
	while (p >= buffer && *p == '\n')
		*p-- = '\0';
	__log_info("buffer = %s [%d]\n", buffer, (int)len);
	err = lua_module_unregister(buffer);
	kfree(buffer);
	if (err < 0)
		return err;

	return len;
}

static const struct file_operations fops_unregister = {
	.write		= unregister_write,
};


static int open_module(struct inode *inode, struct file *filp)
{
	return single_open(filp, modules_show, NULL);
}

static const struct file_operations fops_module = {
	.open		= open_module,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#ifdef CONFIG_SECURITY_LUA_LSM_STATS

static int stats_show(struct seq_file *m, void *v)
{
	lvm_stats_show(m);
	kvcache_stats_show(m);
	return 0;
}

static int open_stats(struct inode *inode, struct file *filp)
{
	return single_open(filp, stats_show, NULL);
}

static const struct file_operations fops_stats = {
	.open		= open_stats,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int open_lsm_funcs(struct inode *inode, struct file *filp)
{
	return single_open(filp, lsm_funcs_show, NULL);
}

static const struct file_operations fops_lsm_funcs = {
	.open		= open_lsm_funcs,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#endif

static struct lua_file {
	const char *name;
	umode_t mode;
	const struct file_operations *fops;
	struct dentry *dentry;
} files[] = {
	{ "version",	0444,	&fops_version		},	/* r--r--r-- */
	{ "register",	0222,	&fops_register		},	/* -w--w--w- */
	{ "unregister",	0222,	&fops_unregister	},	/* -w--w--w- */
	{ "module",	0444,	&fops_module		},	/* r--r--r-- */
#ifdef CONFIG_SECURITY_LUA_LSM_STATS
	{ "stats",	0444,	&fops_stats		},	/* r--r--r-- */
	{ "lsm_funcs",	0444,	&fops_lsm_funcs		},	/* r--r--r-- */
#endif
	{ NULL, 0, NULL }
};

static int __init lua_securityfs_init(void)
{
	struct dentry *dir;
	struct dentry *dentry;
	struct lua_file *file;

	if (!lua_lsm_initialized)
		return 0;

	dir = securityfs_create_dir("lua", NULL);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	for (file = files; file->name; file++) {
		dentry = securityfs_create_file(file->name, file->mode,
						dir, NULL, file->fops);
		if (IS_ERR(dentry))
			break;
		file->dentry = dentry;
	}

	if (IS_ERR(dentry)) {
		for (file--; file >= files; file--)
			securityfs_remove(file->dentry);

		securityfs_remove(dir);
		return PTR_ERR(dentry);
	}

	return 0;
}
fs_initcall(lua_securityfs_init);
