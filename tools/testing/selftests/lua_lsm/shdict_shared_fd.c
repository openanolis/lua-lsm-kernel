// SPDX-License-Identifier: GPL-2.0
/* Exercise a shared open-file description, not a production control client. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../kselftest.h"

#define BASE "/sys/kernel/security/lua/"
#define MODULE "sharedfd"
#define SIZE 2048
#define THREADS 4
#define ITERATIONS 2000

static const char policy[] =
	"return {name='" MODULE "', license='GPL-2.0', author='OSPP', "
	"file_open=function(file) return true end}\n";
static pthread_barrier_t start;
static pthread_mutex_t transaction = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint readers_done;
static char payload[2][SIZE + 1];

struct worker {
	int fd;
	int id;
	int mode;
	int error;
	unsigned int operations;
	unsigned long bytes;
	unsigned long histogram[256];
	pthread_t thread;
};

static int send_cmd(int fd, const char *cmd)
{
	size_t len = strlen(cmd);
	ssize_t n = write(fd, cmd, len);

	return n < 0 ? -errno : n == (ssize_t)len ? 0 : -EIO;
}

static int read_all(int fd, char *buf, size_t size)
{
	size_t used = 0;
	ssize_t n;

	while (used < size) {
		n = read(fd, buf + used, size - used);
		if (n < 0)
			return -errno;
		if (!n)
			return used;
		used += n;
	}
	return -E2BIG;
}

static int expect(int fd, const char *cmd, const char *value)
{
	char buf[SIZE + 1];
	int ret = send_cmd(fd, cmd);

	if (ret)
		return ret;
	ret = read_all(fd, buf, sizeof(buf));
	return ret < 0 ? ret : ret == (int)strlen(value) &&
		!memcmp(buf, value, ret) ? 0 : -EIO;
}

static int control(bool load)
{
	int fd, ret;

	fd = open(BASE, O_RDONLY | O_DIRECTORY);
	if (fd < 0)
		return -errno;
	ret = openat(fd, load ? "register" : "unregister", O_WRONLY);
	close(fd);
	if (ret < 0)
		return -errno;
	fd = ret;
	ret = send_cmd(fd, load ? policy : MODULE "\n");
	close(fd);
	return ret;
}

static int alias_and_fork(void)
{
	char buf[SIZE + 1];
	int fd, alias, other, ret = -EIO, status;
	pid_t child;

	fd = open(BASE "shdict", O_RDWR);
	if (fd < 0)
		return -errno;
	alias = dup(fd);
	other = open(BASE "shdict", O_RDWR);
	if (alias < 0 || other < 0)
		goto out;
	if (send_cmd(fd, "get " MODULE " runtime a\n") || read(alias, buf, 3) != 3 ||
	    memcmp(buf, "AAA", 3))
		goto out;
	if (read_all(fd, buf, sizeof(buf)) != SIZE - 3)
		goto out;
	if (send_cmd(other, "get " MODULE " runtime a\n"))
		goto out;
	child = fork();
	if (child < 0)
		goto out;
	if (!child) {
		close(fd);
		_exit(send_cmd(alias, "get " MODULE " runtime b\n") ? 1 : 0);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status))
		goto out;
	if (read_all(alias, buf, sizeof(buf)) != SIZE || memcmp(buf, payload[1], SIZE))
		goto out;
	/* Separate opens retain their own response; closing an alias is harmless. */
	close(fd);
	fd = -1;
	if (read_all(other, buf, sizeof(buf)) != SIZE || memcmp(buf, payload[0], SIZE) ||
	    expect(alias, "get " MODULE " runtime a\n", payload[0]))
		goto out;
	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	if (alias >= 0)
		close(alias);
	if (other >= 0)
		close(other);
	return ret;
}

static void *run_worker(void *arg)
{
	struct worker *w = arg;
	char buf[SIZE + 1];
	const char *cmd = w->id & 1 ? "get " MODULE " runtime b\n" :
		"get " MODULE " runtime a\n";
	ssize_t n;
	int ret, i;

	pthread_barrier_wait(&start);
	if (w->mode == 0) {
		/* All readers share the first lazy snapshot and its cursor. */
		while ((n = read(w->fd, buf, 23)) > 0) {
			for (i = 0; i < n; i++)
				w->histogram[(unsigned char)buf[i]]++;
			w->bytes += n;
		}
		if (n < 0)
			w->error = errno;
	} else if (w->mode == 1 && w->id < 2) {
		do {
			ret = send_cmd(w->fd, cmd);
			if (ret) {
				w->error = -ret;
				break;
			}
			w->operations++;
			sched_yield();
		} while (w->operations < ITERATIONS || atomic_load(&readers_done) < 2);
	} else if (w->mode == 1) {
		for (i = 0; i < ITERATIONS; i++) {
			n = read(w->fd, buf, 19);
			if (n < 0 || n > 19) {
				w->error = n < 0 ? errno : EIO;
				break;
			}
			if (n) {
				if ((buf[0] != 'A' && buf[0] != 'B') ||
				    memcmp(buf, payload[buf[0] == 'B'], n)) {
					w->error = EIO;
					break;
				}
				w->bytes += n;
			}
			w->operations++;
			sched_yield();
		}
		if (!w->bytes && !w->error)
			w->error = ENODATA;
		atomic_fetch_add(&readers_done, 1);
	} else {
		/* Application locking is needed for write + all reads as one transaction. */
		for (i = 0; i < 500; i++) {
			pthread_mutex_lock(&transaction);
			ret = expect(w->fd, cmd, payload[w->id & 1]);
			pthread_mutex_unlock(&transaction);
			if (ret) {
				w->error = -ret;
				break;
			}
			w->operations++;
		}
	}
	return NULL;
}

static int concurrent(int mode)
{
	struct worker workers[THREADS] = {};
	unsigned long histogram[256] = {}, bytes = 0;
	char *snapshot = NULL;
	int fd, other = -1, ret, i, j, created = 0, length = 0;

	fd = open(BASE "shdict", O_RDWR);
	if (fd < 0)
		return -errno;
	if (!mode) {
		snapshot = malloc(65537);
		other = open(BASE "shdict", O_RDONLY);
		if (!snapshot || other < 0) {
			ret = -ENOMEM;
			goto out;
		}
		length = read_all(other, snapshot, 65537);
		if (length <= 0) {
			ret = length ? length : -ENODATA;
			goto out;
		}
	}
	if (mode == 1) {
		ret = send_cmd(fd, "get " MODULE " runtime a\n");
		if (ret)
			goto out;
	}
	ret = pthread_barrier_init(&start, NULL, THREADS + 1);
	if (ret) {
		ret = -ret;
		goto out;
	}
	atomic_store(&readers_done, 0);
	for (i = 0; i < THREADS; i++) {
		workers[i].fd = dup(fd);
		workers[i].id = i;
		workers[i].mode = mode;
		if (workers[i].fd < 0)
			ksft_exit_fail_msg("dup: %s\n", strerror(errno));
		ret = pthread_create(&workers[i].thread, NULL, run_worker, &workers[i]);
		if (ret)
			ksft_exit_fail_msg("pthread_create: %s\n", strerror(ret));
		created++;
	}
	pthread_barrier_wait(&start);
	ret = 0;
	for (i = 0; i < created; i++) {
		pthread_join(workers[i].thread, NULL);
		close(workers[i].fd);
		if (workers[i].error)
			ret = -workers[i].error;
		bytes += workers[i].bytes;
		for (j = 0; j < 256; j++)
			histogram[j] += workers[i].histogram[j];
	}
	pthread_barrier_destroy(&start);
	if (!ret && !mode) {
		if (bytes != (unsigned long)length)
			ret = -EIO;
		for (i = 0; i < length; i++)
			histogram[(unsigned char)snapshot[i]]--;
		for (i = 0; i < 256; i++)
			if (histogram[i])
				ret = -EIO;
	}
out:
	if (other >= 0)
		close(other);
	close(fd);
	free(snapshot);
	return ret;
}

static int faults(void)
{
	char *bad = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	char buf[SIZE + 1];
	int fd = open(BASE "shdict", O_RDWR), ret = -EIO;

	if (fd < 0 || bad == MAP_FAILED)
		goto out;
	if (lseek(fd, 0, SEEK_SET) != -1 || errno != ESPIPE ||
	    pread(fd, buf, 1, 0) != -1 || errno != ESPIPE ||
	    pwrite(fd, "x", 1, 0) != -1 || errno != ESPIPE)
		goto out;
	if (send_cmd(fd, "get " MODULE " runtime a\n"))
		goto out;
	if (read(fd, bad, 3) != -1 || errno != EFAULT)
		goto out;
	if (read_all(fd, buf, sizeof(buf)) != SIZE || memcmp(buf, payload[0], SIZE))
		goto out;
	if (write(fd, bad, 3) != -1 || errno != EFAULT || read(fd, buf, 1) != 0)
		goto out;
	if (send_cmd(fd, "bad command\n") != -EINVAL ||
	    expect(fd, "get " MODULE " runtime b\n", payload[1]))
		goto out;
	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	if (bad != MAP_FAILED)
		munmap(bad, 4096);
	return ret;
}

int main(void)
{
	char cmd[SIZE + 128];
	int fd, ret, i, failed = 0;

	ksft_print_header();
	if (access(BASE "shdict", F_OK))
		ksft_exit_skip("Lua-LSM securityfs is unavailable\n");
	alarm(120);
	ret = control(true);
	if (ret)
		ksft_exit_fail_msg("register private fixture: %s\n", strerror(-ret));
	fd = open(BASE "shdict", O_RDWR);
	if (fd < 0)
		ksft_exit_fail_msg("open: %s\n", strerror(errno));
	for (i = 0; i < 2; i++) {
		memset(payload[i], 'A' + i, SIZE);
		snprintf(cmd, sizeof(cmd), "set " MODULE " runtime %c string %.*s\n",
			 'a' + i, SIZE, payload[i]);
		if (expect(fd, cmd, "true"))
			ksft_exit_fail_msg("seed fixture\n");
	}
	close(fd);
	ksft_set_plan(5);
	ret = alias_and_fork();
	ksft_test_result(!ret, "dup/fork cursor sharing and separate-open isolation\n");
	failed += !!ret;
	ret = 0;
	for (i = 0; i < 20 && !ret; i++)
		ret = concurrent(0);
	ksft_test_result(!ret, "concurrent lazy enumeration: exact byte counts\n");
	failed += !!ret;
	ret = concurrent(1);
	ksft_test_result(!ret, "concurrent response replacement and partial reads\n");
	failed += !!ret;
	ret = concurrent(2);
	ksft_test_result(!ret, "userspace-serialized complete transactions\n");
	failed += !!ret;
	ret = faults();
	ksft_test_result(!ret, "stream offsets, EFAULT, invalid request and recovery\n");
	failed += !!ret;
	for (i = 0; i < 5; i++) {
		ret = control(false);
		if (!ret || ret == -ENOENT || ret != -EBUSY)
			break;
		usleep(100000);
	}
	if (ret && ret != -ENOENT)
		ksft_exit_fail_msg("fixture cleanup: %s\n", strerror(-ret));
	alarm(0);
	if (failed)
		ksft_exit_fail();
	ksft_exit_pass();
}
