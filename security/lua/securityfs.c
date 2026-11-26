/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#include "debug.h"
#include <linux/security.h>
#include <linux/hex.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include "lsm.h"

static bool lua_lsm_capable(int cap)
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

static ssize_t module_write(const char __user *buf, size_t len,
			    loff_t *ppos, int load)
{
	char *buffer, *p;
	int err;

	__log_info("len = %d\n", (int)len);
	if (!lua_lsm_capable(CAP_MAC_ADMIN))
		return -EPERM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;
	if (len == 0)
		return -EINVAL;

	buffer = memdup_user_nul(buf, len);
	if (IS_ERR(buffer))
		return PTR_ERR(buffer);

	__log_info("buffer = [%d] %s\n", (int)len, buffer);
	if (load) {
		err = lua_lsm_module_register(buffer, len);
	} else {
		/* remove the tailing '\n' */
		p = &buffer[len - 1];
		while (p >= buffer && *p == '\n')
			*p-- = '\0';

		err = lua_lsm_module_unregister(buffer);
	}
	kfree(buffer);
	if (err < 0)
		return err;

	return len;
}

static ssize_t register_write(struct file *file, const char __user *buf,
			      size_t len, loff_t *ppos)
{
	return module_write(buf, len, ppos, 1);
}

static const struct file_operations fops_register = {
	.write		= register_write,
};

static ssize_t unregister_write(struct file *file, const char __user *buf,
				size_t len, loff_t *ppos)
{
	return module_write(buf, len, ppos, 0);
}

static const struct file_operations fops_unregister = {
	.write		= unregister_write,
};

static int open_modules(struct inode *inode, struct file *filp)
{
	return single_open(filp, modules_show, NULL);
}

static const struct file_operations fops_modules = {
	.open		= open_modules,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/*
 * PoC shared-dict control file: /sys/kernel/security/lua/shdict
 *
 * UNSTABLE: development interface for the securityfs shared dict PoC
 * only.  Not a formal ABI; it may change or disappear without notice.
 *
 * One complete, line-oriented request per write (max SHDICT_IO_MAX bytes):
 *
 *   set <module> <dict> <key> <boolean|number|string|hex> <value>
 *   get <module> <dict> <key>
 *   delete <module> <dict> <key>
 *   incr <module> <dict> <key> [delta]
 *
 * A fresh read enumerates all LIVE shared dictionaries.  A read following a
 * request on the same file descriptor returns that request's scalar result.
 */
#define SHDICT_IO_MAX		4096
#define SHDICT_DUMP_MAX		(64 * 1024)
#define SHDICT_NAME_MAX		128

struct shdict_ctx {
	/* dup()/fork() share this context; serialize each syscall, not a transaction. */
	struct mutex lock;
	char *buf;	/* response or enumeration buffer */
	size_t capacity;
	size_t len;	/* bytes valid in buf */
	size_t pos;	/* next byte to return from read() */
	bool prepared;
};

static int shdict_open(struct inode *inode, struct file *filp)
{
	struct shdict_ctx *ctx;

	if (!lua_lsm_capable(CAP_MAC_ADMIN))
		return -EPERM;

	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	ctx->buf = kmalloc(SHDICT_IO_MAX, GFP_KERNEL);
	if (!ctx->buf) {
		kfree(ctx);
		return -ENOMEM;
	}
	ctx->capacity = SHDICT_IO_MAX;
	mutex_init(&ctx->lock);

	filp->private_data = ctx;
	/* Position belongs to ctx, not file->f_pos; no seek/pread/pwrite protocol. */
	return stream_open(inode, filp);
}

static int shdict_release(struct inode *inode, struct file *filp)
{
	struct shdict_ctx *ctx = filp->private_data;

	if (ctx) {
		kvfree(ctx->buf);
		kfree(ctx);
	}
	return 0;
}

static ssize_t shdict_read(struct file *file, char __user *buf, size_t len,
			   loff_t *ppos)
{
	struct shdict_ctx *ctx = file->private_data;
	size_t n;
	ssize_t ret;
	int err;

	if (!lua_lsm_capable(CAP_MAC_ADMIN))
		return -EPERM;
	if (!len)
		return 0;
	if (mutex_lock_interruptible(&ctx->lock))
		return -ERESTARTSYS;
	if (!ctx->prepared) {
		char *dump_buf;

		dump_buf = kvmalloc(SHDICT_DUMP_MAX, GFP_KERNEL);
		if (!dump_buf) {
			ret = -ENOMEM;
			goto out;
		}
		kvfree(ctx->buf);
		ctx->buf = dump_buf;
		ctx->capacity = SHDICT_DUMP_MAX;
		err = lua_lsm_shdict_dump(ctx->buf, ctx->capacity, &ctx->len);
		if (err) {
			ret = err;
			goto out;
		}
		ctx->pos = 0;
		ctx->prepared = true;
	}
	n = ctx->len - ctx->pos;
	if (n == 0) {
		ret = 0;
		goto out;
	}
	if (n > len)
		n = len;
	if (copy_to_user(buf, ctx->buf + ctx->pos, n)) {
		ret = -EFAULT;
		goto out;
	}
	ctx->pos += n;
	ret = n;
out:
	mutex_unlock(&ctx->lock);
	return ret;
}

static char *shdict_next_token(char **cursor)
{
	char *token;
	char *p = *cursor;

	while (*p == ' ' || *p == '\t')
		p++;
	if (!*p) {
		*cursor = p;
		return NULL;
	}
	token = p;
	while (*p && *p != ' ' && *p != '\t')
		p++;
	if (*p)
		*p++ = '\0';
	*cursor = p;
	return token;
}

static char *shdict_rest(char *cursor)
{
	while (*cursor == ' ' || *cursor == '\t')
		cursor++;
	return cursor;
}

static int shdict_name_valid(const char *name)
{
	size_t len;
	size_t i;

	if (!name)
		return -EINVAL;
	len = strlen(name);
	if (!len)
		return -EINVAL;
	if (len > SHDICT_NAME_MAX)
		return -E2BIG;
	for (i = 0; i < len; i++) {
		if ((unsigned char)name[i] <= 0x20 || name[i] == 0x7f)
			return -EINVAL;
	}
	return 0;
}

static int shdict_request_frame(char *input, size_t len)
{
	/* Literal NULs and multi-line commands are not valid text framing. */
	if (memchr(input, '\0', len))
		return -EINVAL;
	while (len && (input[len - 1] == '\n' || input[len - 1] == '\r'))
		input[--len] = '\0';
	if (!len || memchr(input, '\n', len) || memchr(input, '\r', len))
		return -EINVAL;
	return 0;
}

static int shdict_parse_set(char *cursor, struct lua_lsm_shdict_request *req,
			    char **decoded)
{
	const char *type = shdict_next_token(&cursor);
	const char *value = shdict_rest(cursor);
	size_t len;
	int err;

	if (!type)
		return -EINVAL;
	req->op = LUA_LSM_SHDICT_SET;
	if (!strcmp(type, "boolean")) {
		req->type = LUA_LSM_SHDICT_BOOLEAN;
		if (!strcmp(value, "true"))
			req->value.boolean = true;
		else if (!strcmp(value, "false"))
			req->value.boolean = false;
		else
			return -EINVAL;
	} else if (!strcmp(type, "number")) {
		req->type = LUA_LSM_SHDICT_NUMBER;
		return kstrtoll(value, 10, &req->value.number);
	} else if (!strcmp(type, "string")) {
		req->type = LUA_LSM_SHDICT_STRING;
		req->value.string.data = value;
		req->value.string.len = strlen(value);
	} else if (!strcmp(type, "hex")) {
		len = strlen(value);
		if (len & 1)
			return -EINVAL;
		len /= 2;
		*decoded = kmalloc(len ?: 1, GFP_KERNEL);
		if (!*decoded)
			return -ENOMEM;
		err = hex2bin(*decoded, value, len);
		if (err)
			return err;
		req->type = LUA_LSM_SHDICT_STRING;
		req->value.string.data = *decoded;
		req->value.string.len = len;
	} else {
		return -EOPNOTSUPP;
	}
	return 0;
}

static int shdict_parse_request(char *cursor,
				struct lua_lsm_shdict_request *req,
				char **decoded)
{
	const char *op = shdict_next_token(&cursor);
	const char *delta;
	int err;

	if (!op)
		return -EINVAL;
	req->module = shdict_next_token(&cursor);
	req->dict = shdict_next_token(&cursor);
	req->key = shdict_next_token(&cursor);
	err = shdict_name_valid(req->module);
	if (err)
		return err;
	err = shdict_name_valid(req->dict);
	if (err)
		return err;
	err = shdict_name_valid(req->key);
	if (err)
		return err;

	if (!strcmp(op, "set"))
		return shdict_parse_set(cursor, req, decoded);
	if (!strcmp(op, "get")) {
		req->op = LUA_LSM_SHDICT_GET;
	} else if (!strcmp(op, "delete")) {
		req->op = LUA_LSM_SHDICT_DELETE;
	} else if (!strcmp(op, "incr")) {
		req->op = LUA_LSM_SHDICT_INCR;
		delta = shdict_next_token(&cursor);
		if (shdict_next_token(&cursor))
			return -EINVAL;
		req->value.number = 1;
		return delta ? kstrtoll(delta, 10, &req->value.number) : 0;
	} else {
		return -EINVAL;
	}
	return shdict_next_token(&cursor) ? -EINVAL : 0;
}

static ssize_t shdict_write(struct file *file, const char __user *buf,
			    size_t len, loff_t *ppos)
{
	struct shdict_ctx *ctx = file->private_data;
	struct lua_lsm_shdict_request request = {};
	char *decoded = NULL;
	char *input;
	int err;

	if (!lua_lsm_capable(CAP_MAC_ADMIN))
		return -EPERM;
	if (!len)
		return -EINVAL;
	if (len > SHDICT_IO_MAX)
		return -E2BIG;
	if (mutex_lock_interruptible(&ctx->lock))
		return -ERESTARTSYS;

	/* Every accepted write replaces the response for this open file. */
	ctx->len = 0;
	ctx->pos = 0;
	ctx->prepared = true;

	input = memdup_user_nul(buf, len);
	if (IS_ERR(input)) {
		err = PTR_ERR(input);
		goto out_unlock;
	}

	err = shdict_request_frame(input, len);
	if (err)
		goto out_free;

	err = shdict_parse_request(input, &request, &decoded);
	if (err)
		goto out_free;

	err = lua_lsm_shdict_call(&request, ctx->buf, SHDICT_IO_MAX, &ctx->len);
out_free:
	kfree(decoded);
	kfree(input);
out_unlock:
	mutex_unlock(&ctx->lock);
	if (err)
		return err;
	return len;
}

static const struct file_operations fops_shdict = {
	.open		= shdict_open,
	.read		= shdict_read,
	.write		= shdict_write,
	.release	= shdict_release,
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

static struct lua_lsm_file {
	const char *name;
	umode_t mode;
	const struct file_operations *fops;
	struct dentry *dentry;
} files[] = {
	{ "version",	0444,	&fops_version		},	/* r--r--r-- */
	{ "register",	0222,	&fops_register		},	/* -w--w--w- */
	{ "unregister",	0222,	&fops_unregister	},	/* -w--w--w- */
	{ "modules",	0444,	&fops_modules		},	/* r--r--r-- */
	{ "shdict",	0600,	&fops_shdict		},	/* rw------- PoC */
#ifdef CONFIG_SECURITY_LUA_LSM_STATS
	{ "stats",	0444,	&fops_stats		},	/* r--r--r-- */
	{ "lsm_funcs",	0444,	&fops_lsm_funcs		},	/* r--r--r-- */
#endif
	{ NULL, 0, NULL }
};

int __init lua_lsm_securityfs_init(void)
{
	struct dentry *dir;
	struct dentry *dentry;
	struct lua_lsm_file *file;

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
