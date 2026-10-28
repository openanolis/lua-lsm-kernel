/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SHDICT_TEST_H
#define SHDICT_TEST_H
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SD_BASE "/sys/kernel/security/lua/"

static inline int sd_read(int fd, void *data, size_t size)
{
	size_t used = 0;
	ssize_t n;

	while (used < size) {
		n = read(fd, (char *)data + used, size - used);
		if (n < 0)
			return -errno;
		if (!n)
			return used;
		used += n;
	}
	return -E2BIG;
}

static inline int sd_write(int fd, const char *cmd)
{
	size_t len = strlen(cmd);
	ssize_t n = write(fd, cmd, len);

	return n < 0 ? -errno : n == (ssize_t)len ? 0 : -EIO;
}

static inline int sd_file(const char *path, const char *data)
{
	int fd = open(path, O_WRONLY), ret;

	if (fd < 0)
		return -errno;
	ret = sd_write(fd, data);
	close(fd);
	return ret;
}

static inline int sd_expect(int fd, const char *cmd, const char *expected)
{
	char buf[8193];
	int ret = sd_write(fd, cmd);

	if (ret)
		return ret;
	ret = sd_read(fd, buf, sizeof(buf));
	if (ret < 0)
		return ret;
	return ret == (int)strlen(expected) && !memcmp(buf, expected, ret) ? 0 : -EIO;
}

static inline int sd_unregister(const char *name)
{
	int i, ret;

	for (i = 0; i < 30; i++) {
		ret = sd_file(SD_BASE "unregister", name);
		if (!ret || ret == -ENOENT)
			return 0;
		if (ret != -EBUSY)
			return ret;
		usleep(100000);
	}
	return -EBUSY;
}
#endif
