// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include "../kselftest.h"
#include "shdict_test.h"

#define MODULE "boundary"
#define THREADS 8
#define LOOPS 500
#define DUMP_LIMIT (64 * 1024)
static const char policy[] = "return {name='boundary',license='GPL-2.0',"
	"author='OSPP',file_open=function() return true end}";
static pthread_barrier_t barrier;
struct worker { int mode; int error; };

static int drop_admin(void)
{
	struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct d[2];
	unsigned int bit = 1U << (CAP_MAC_ADMIN % 32);

	if (syscall(SYS_capget, &h, d))
		return -errno;
	d[CAP_MAC_ADMIN / 32].effective &= ~bit;
	d[CAP_MAC_ADMIN / 32].permitted &= ~bit;
	d[CAP_MAC_ADMIN / 32].inheritable &= ~bit;
	return syscall(SYS_capset, &h, d) ? -errno : 0;
}

static int permission(int mode, int inherited)
{
	char buf[32];
	int fd;

	if (mode == 0) {
		if (setgroups(0, NULL) || setgid(1000) || setuid(1000))
			return 1;
	} else if (mode == 3) {
		if (unshare(CLONE_NEWUSER))
			return 1;
		if (sd_file("/proc/self/setgroups", "deny") ||
		    sd_file("/proc/self/uid_map", "0 0 1") ||
		    sd_file("/proc/self/gid_map", "0 0 1") || getuid())
			return 1;
	} else if (drop_admin()) {
		return 1;
	}
	if (mode == 2) {
		if (read(inherited, buf, sizeof(buf)) != -1 || errno != EPERM)
			return 1;
		return sd_write(inherited, "get boundary runtime p") == -EPERM ? 0 : 1;
	}
	fd = open(SD_BASE "shdict", O_RDWR);
	if (fd >= 0) {
		close(fd);
		return 1;
	}
	return errno == (mode == 0 ? EACCES : EPERM) ? 0 : 1;
}

static int child_permission(int mode, int fd)
{
	int status;
	pid_t pid = fork();

	if (pid < 0)
		return -errno;
	if (!pid)
		_exit(permission(mode, fd));
	return waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
		!WEXITSTATUS(status) ? 0 : -EIO;
}

static void *concurrent(void *arg)
{
	struct worker *w = arg;
	int fd = open(SD_BASE "shdict", O_RDWR), ret = 0, i;

	pthread_barrier_wait(&barrier);
	if (fd < 0) {
		w->error = errno;
		return NULL;
	}
	for (i = 0; i < LOOPS && !ret; i++) {
		if (!w->mode) {
			ret = sd_write(fd, "incr boundary first counter 1");
		} else {
			ret = sd_expect(fd, "set boundary runtime race string value", "true");
			if (!ret)
				ret = sd_expect(fd, "delete boundary runtime race", "true");
		}
	}
	close(fd);
	w->error = -ret;
	return NULL;
}

static int run_race(int mode, int fd)
{
	struct worker workers[THREADS] = {};
	pthread_t threads[THREADS];
	int i, ret = 0;

	if (pthread_barrier_init(&barrier, NULL, THREADS))
		return -EIO;
	for (i = 0; i < THREADS; i++) {
		workers[i].mode = mode;
		if (pthread_create(&threads[i], NULL, concurrent, &workers[i]))
			exit(1); /* Do not strand a partial barrier. */
	}
	for (i = 0; i < THREADS; i++) {
		pthread_join(threads[i], NULL);
		if (workers[i].error)
			ret = -workers[i].error;
	}
	pthread_barrier_destroy(&barrier);
	if (!ret && !mode)
		ret = sd_expect(fd, "get boundary first counter", "4000");
	if (!ret && mode)
		ret = sd_expect(fd, "set boundary runtime race string recovered", "true");
	return ret;
}

static int length_limit(int fd)
{
	char cmd[4097], response[8193];
	int n = snprintf(cmd, sizeof(cmd), "set boundary runtime limit string ");
	int ret;

	memset(cmd + n, 'x', sizeof(cmd) - n);
	if (write(fd, cmd, 4096) != 4096)
		return -errno;
	if (sd_write(fd, "get boundary runtime limit"))
		return -EIO;
	ret = sd_read(fd, response, sizeof(response));
	if (ret != 4096 - n || memcmp(response, cmd + n, ret))
		return -EIO;
	if (write(fd, cmd, 4097) != -1 || errno != E2BIG)
		return -EIO;
	cmd[4096] = 0;
	if (sd_expect(fd, "get boundary runtime limit", cmd + n))
		return -EIO;
	return sd_expect(fd, "get boundary runtime p", "true");
}

static int overflow(int fd)
{
	char cmd[2200], buf[257];
	int i, n, dump, ret;

	for (i = 0; i < 40; i++) {
		n = snprintf(cmd, sizeof(cmd), "set boundary big k%d string ", i);
		memset(cmd + n, 'x', 2048);
		cmd[n + 2048] = 0;
		if (sd_expect(fd, cmd, "true"))
			return -EIO;
	}
	dump = open(SD_BASE "shdict", O_RDONLY);
	if (dump < 0)
		return -errno;
	if (read(dump, NULL, 0)) {
		close(dump);
		return -EIO;
	}
	ret = read(dump, buf, sizeof(buf));
	close(dump);
	if (ret != -1 || errno != E2BIG)
		return -EIO;
	for (i = 0; i < 40; i++) {
		snprintf(cmd, sizeof(cmd), "delete boundary big k%d", i);
		if (sd_expect(fd, cmd, "true"))
			return -EIO;
	}
	dump = open(SD_BASE "shdict", O_RDONLY);
	if (dump < 0)
		return -errno;
	ret = read(dump, buf, 1);
	close(dump);
	return ret == 1 ? 0 : -EIO;
}

static int incr_limits(int fd)
{
	static const struct {
		long long inside;
		long long limit;
		int delta;
	} cases[] = {
		{ LLONG_MAX - 1, LLONG_MAX, 1 },
		{ LLONG_MIN + 1, LLONG_MIN, -1 },
	};
	char cmd[128], value[32];
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(cases); i++) {
		snprintf(cmd, sizeof(cmd), "set boundary runtime limit number %lld",
			 cases[i].inside);
		if (sd_expect(fd, cmd, "true"))
			return -EIO;
		snprintf(cmd, sizeof(cmd), "incr boundary runtime limit %d",
			 cases[i].delta);
		snprintf(value, sizeof(value), "%lld", cases[i].limit);
		if (sd_expect(fd, cmd, value) || sd_write(fd, cmd) != -ERANGE)
			return -EIO;
		if (sd_expect(fd, "get boundary runtime limit", value))
			return -EIO;
	}
	return 0;
}

static int read_dump(char *buf, size_t size)
{
	int fd, ret;

	fd = open(SD_BASE "shdict", O_RDONLY);
	if (fd < 0)
		return -errno;
	ret = sd_read(fd, buf, size);
	close(fd);
	return ret;
}

static int exact_dump_limit(int fd)
{
	const int row_overhead = strlen("boundary exact k00 string ") + 1;
	char cmd[2200], *buf;
	int i = 0, remaining, len, text_len, ret, dump;
	ssize_t n;

	/* Account for rows from earlier tests before creating the last row. */
	buf = malloc(DUMP_LIMIT + 1);
	if (!buf)
		return -ENOMEM;
	ret = read_dump(buf, DUMP_LIMIT + 1);
	if (ret < 0)
		goto out;
	remaining = DUMP_LIMIT - ret;
	if (remaining < row_overhead) {
		ret = -EIO;
		goto out;
	}

	for (;;) {
		len = snprintf(cmd, sizeof(cmd), "set boundary exact k%02d string ", i++);
		text_len = remaining <= row_overhead + 2048 ?
			remaining - row_overhead : 1024;
		memset(cmd + len, 'x', text_len);
		cmd[len + text_len] = '\0';
		ret = sd_expect(fd, cmd, "true");
		if (ret)
			goto out;
		remaining -= row_overhead + text_len;
		if (!remaining)
			break;
	}

	ret = read_dump(buf, DUMP_LIMIT + 1);
	if (ret != DUMP_LIMIT || buf[DUMP_LIMIT - 1] != '\n') {
		ret = -EIO;
		goto out;
	}

	/* One byte over the limit must fail without returning a partial dump. */
	cmd[len + text_len++] = 'x';
	cmd[len + text_len] = '\0';
	ret = sd_expect(fd, cmd, "true");
	if (ret)
		goto out;
	dump = open(SD_BASE "shdict", O_RDONLY);
	if (dump < 0) {
		ret = -errno;
		goto out;
	}
	n = read(dump, buf, 1);
	ret = n < 0 && errno == E2BIG ? 0 : -EIO;
	close(dump);
out:
	free(buf);
	return ret;
}

int main(void)
{
	static const char * const names[] = {
		"ordinary user DAC denied",
		"root without MAC_ADMIN denied",
		"inherited FD read and write recheck",
		"user namespace root denied",
		"4096 accepted and 4097 refused",
		"concurrent first dictionary and atomic incr",
		"same-key set/delete race",
		"enumeration overflow refuses partial success",
		"incr range errors preserve the previous value",
		"enumeration accepts 64 KiB, rejects 64 KiB plus one byte",
	};
	int fd, ret, failed = 0, i;

	alarm(180);
	ksft_print_header();
	ksft_set_plan(ARRAY_SIZE(names));
	if (sd_file(SD_BASE "register", policy))
		ksft_exit_fail_msg("register boundary fixture\n");
	fd = open(SD_BASE "shdict", O_RDWR);
	if (fd < 0 || sd_expect(fd, "set boundary runtime p boolean true", "true"))
		ksft_exit_fail_msg("prepare boundary fixture\n");
	for (i = 0; i < (int)ARRAY_SIZE(names); i++) {
		if (i < 4)
			ret = child_permission(i, fd);
		else if (i == 4)
			ret = length_limit(fd);
		else if (i < 7)
			ret = run_race(i == 6, fd);
		else if (i == 7)
			ret = overflow(fd);
		else if (i == 8)
			ret = incr_limits(fd);
		else
			ret = exact_dump_limit(fd);
		ksft_test_result(!ret, "%s (errno=%d)\n", names[i], -ret);
		failed |= !!ret;
	}
	close(fd);
	if (sd_unregister(MODULE))
		ksft_exit_fail_msg("boundary fixture cleanup\n");
	return failed ? KSFT_FAIL : KSFT_PASS;
}
