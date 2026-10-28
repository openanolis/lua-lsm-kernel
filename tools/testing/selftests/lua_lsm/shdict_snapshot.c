// SPDX-License-Identifier: GPL-2.0
/* Snapshot consistency regression workload, not an administration client. */
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "../kselftest.h"
#include "shdict_test.h"

#define DUMP_SIZE 65537
#define ATTEMPTS 200
#define HOOK_PATH "/tmp/lua-lsm-snapshot-mkdir"

static const char policy_a[] = "return {name='enum_a',license='GPL-2.0',"
	"inode_mkdir=function() return true end}";
static const char policy_b[] = "return {name='enum_b',license='GPL-2.0',"
	"inode_mkdir=function() return true end}";
static const char policy_hook[] = "return {name='enum_hook',license='GPL-2.0',"
	"inode_mkdir=function() local n=shared.first:incr('value',1); "
	"shared.second:set('value',n); return true end}";
static atomic_bool stop;
static atomic_uint operations;
static atomic_int worker_error;

/* On EAGAIN not even one byte may escape from a rejected attempt. */
static int read_once(int fd, char *buf)
{
	size_t used = 0;
	ssize_t n;

	buf[0] = 'Q';
	while (used < DUMP_SIZE - 1) {
		n = read(fd, buf + used, DUMP_SIZE - 1 - used);
		if (n < 0) {
			if (errno == EAGAIN && (used || buf[0] != 'Q'))
				return -EIO;
			return -errno;
		}
		if (!n) {
			buf[used] = 0;
			return used;
		}
		used += n;
	}
	return -E2BIG;
}

static int snapshot(char *buf)
{
	int i, fd = open(SD_BASE "shdict", O_RDONLY), ret;

	if (fd < 0)
		return -errno;
	for (i = 0; i < ATTEMPTS; i++) {
		ret = read_once(fd, buf);
		if (ret != -EAGAIN)
			break;
		usleep(1000);
	}
	close(fd);
	return ret;
}

static int number(const char *buf, const char *prefix, long *value)
{
	const char *p = strstr(buf, prefix);
	char *end;

	if (!p || (p != buf && p[-1] != '\n'))
		return -ENOENT;
	errno = 0;
	*value = strtol(p + strlen(prefix), &end, 10);
	return errno || end == p + strlen(prefix) || *end != '\n' ? -EIO : 0;
}

static int check_pair(const char *buf, bool hook)
{
	long first, second;
	int ret;

	ret = number(buf, hook ? "enum_hook first value number " :
		     "enum_a first value number ", &first);
	if (!ret)
		ret = number(buf, hook ? "enum_hook second value number " :
			     "enum_b second value number ", &second);
	if (!ret && (first < second || first - second > 1)) {
		ksft_print_msg("impossible snapshot: first=%ld second=%ld\n", first, second);
		ret = -EIO;
	}
	return ret;
}

static int cached_snapshot(int fd, char *buf)
{
	int dump = open(SD_BASE "shdict", O_RDONLY), ret;
	size_t used = 1;
	ssize_t n = 0;
	long value;

	if (dump < 0)
		return -errno;
	if (read(dump, buf, 1) != 1) {
		ret = -EIO;
		goto out;
	}
	ret = sd_expect(fd, "delete enum_a first value", "true");
	if (!ret)
		ret = sd_expect(fd, "set enum_a newly_created flag boolean true", "true");
	while (!ret && (n = read(dump, buf + used, 17)) > 0) {
		used += n;
		if (used + 17 >= DUMP_SIZE)
			ret = -E2BIG;
	}
	if (!ret && n < 0)
		ret = -errno;
	buf[used] = 0;
	if (!ret)
		ret = number(buf, "enum_a first value number ", &value);
	if (!ret && (value || strstr(buf, "enum_a newly_created ")))
		ret = -EIO;
	if (!ret) {
		ret = snapshot(buf);
		if (ret >= 0)
			ret = strstr(buf, "enum_a first value ") ||
				!strstr(buf, "enum_a newly_created flag boolean true\n") ? -EIO : 0;
	}
out:
	close(dump);
	if (sd_expect(fd, "set enum_a first value number 0", "true") && !ret)
		ret = -EIO;
	return ret;
}

static void *writer(void *arg)
{
	bool hook = *(bool *)arg;
	int fd = -1, ret = 0;

	if (!hook) {
		fd = open(SD_BASE "shdict", O_RDWR);
		if (fd < 0)
			ret = -errno;
	}
	while (!ret && !atomic_load(&stop)) {
		if (hook) {
			if (mkdir(HOOK_PATH, 0700) || rmdir(HOOK_PATH))
				ret = -errno;
		} else {
			ret = sd_write(fd, "incr enum_a first value 1");
			if (!ret)
				ret = sd_write(fd, "incr enum_b second value 1");
		}
		atomic_fetch_add(&operations, 1);
		/* Quiescent windows allow readers to make measurable progress. */
		if (!(atomic_load(&operations) % 4))
			usleep(1000);
	}
	if (fd >= 0)
		close(fd);
	atomic_store(&worker_error, ret);
	return NULL;
}

static int concurrent_snapshot(bool hook, char *buf)
{
	pthread_t thread;
	unsigned int accepted = 0, busy = 0, i;
	int fd, ret = 0, err;

	atomic_store(&stop, false);
	atomic_store(&operations, 0);
	atomic_store(&worker_error, 0);
	err = pthread_create(&thread, NULL, writer, &hook);
	if (err)
		return -err;
	for (i = 0; i < 1000 && !atomic_load(&operations) &&
	     !atomic_load(&worker_error); i++)
		usleep(1000);
	for (i = 0; i < ATTEMPTS && !ret; i++) {
		fd = open(SD_BASE "shdict", O_RDONLY);
		if (fd < 0) {
			ret = -errno;
			break;
		}
		err = read_once(fd, buf);
		close(fd);
		if (err == -EAGAIN) {
			busy++;
			usleep(100);
			continue;
		}
		if (err < 0) {
			ret = err;
			break;
		}
		ret = check_pair(buf, hook);
		accepted++;
		usleep(100);
	}
	atomic_store(&stop, true);
	pthread_join(thread, NULL);
	ksft_print_msg("%s: accepted=%u EAGAIN=%u updates=%u writer_errno=%d\n",
		       hook ? "Lua hook" : "cross-module writer", accepted, busy,
		       atomic_load(&operations), -atomic_load(&worker_error));
	if (!ret && (atomic_load(&worker_error) || !accepted || !atomic_load(&operations)))
		ret = atomic_load(&worker_error) ?: -ENODATA;
	if (!ret) {
		ret = snapshot(buf);
		if (ret >= 0)
			ret = check_pair(buf, hook);
	}
	return ret;
}

int main(int argc, char **argv)
{
	char *buf = malloc(DUMP_SIZE), cmd[512];
	int fd, ret, failed = 0, i;

	if (!buf)
		return KSFT_FAIL;
	alarm(180);
	if (argc == 2 && !strcmp(argv[1], "--check")) {
		ret = snapshot(buf);
		free(buf);
		return ret < 0 ? KSFT_FAIL : KSFT_PASS;
	}
	if (argc != 1)
		return KSFT_FAIL;
	ksft_print_header();
	ksft_set_plan(3);
	if (sd_file(SD_BASE "register", policy_a) ||
	    sd_file(SD_BASE "register", policy_b) ||
	    sd_file(SD_BASE "register", policy_hook))
		ksft_exit_fail_msg("register snapshot fixtures\n");
	fd = open(SD_BASE "shdict", O_RDWR);
	if (fd < 0)
		ksft_exit_fail_msg("open shdict\n");
	if (sd_expect(fd, "set enum_a first value number 0", "true") ||
	    sd_expect(fd, "set enum_b second value number 0", "true") ||
	    sd_expect(fd, "set enum_hook first value number 0", "true") ||
	    sd_expect(fd, "set enum_hook second value number 0", "true"))
		ksft_exit_fail_msg("seed snapshot fixtures\n");
	/* Slow traversal so an unversioned implementation exposes mixed rows. */
	for (i = 0; i < 48; i++) {
		ret = snprintf(cmd, sizeof(cmd), "set enum_a first zpad%02d string ", i);
		memset(cmd + ret, 'p', 256);
		cmd[ret + 256] = 0;
		if (sd_expect(fd, cmd, "true"))
			ksft_exit_fail_msg("seed padding\n");
		ret = snprintf(cmd, sizeof(cmd), "set enum_hook first zpad%02d string ", i);
		memset(cmd + ret, 'p', 256);
		cmd[ret + 256] = 0;
		if (sd_expect(fd, cmd, "true"))
			ksft_exit_fail_msg("seed hook padding\n");
	}
	ret = cached_snapshot(fd, buf);
	ksft_test_result(!ret, "partial reads retain one snapshot across delete/create (errno=%d)\n", -ret);
	failed |= !!ret;
	ret = concurrent_snapshot(false, buf);
	ksft_test_result(!ret, "cross-module updates: coherent snapshot or EAGAIN (errno=%d)\n", -ret);
	failed |= !!ret;
	ret = concurrent_snapshot(true, buf);
	ksft_test_result(!ret, "Lua hook updates across dictionaries: coherent snapshot or EAGAIN (errno=%d)\n", -ret);
	failed |= !!ret;
	close(fd);
	free(buf);
	if (sd_unregister("enum_hook") || sd_unregister("enum_b") || sd_unregister("enum_a"))
		ksft_exit_fail_msg("snapshot fixture cleanup\n");
	return failed ? KSFT_FAIL : KSFT_PASS;
}
