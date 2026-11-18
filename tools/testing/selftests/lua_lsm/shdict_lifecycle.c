// SPDX-License-Identifier: GPL-2.0
/* Independent per-worker FDs: this is not a shared-FD concurrency test. */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../kselftest.h"

#define BASE "/sys/kernel/security/lua/"
#define MODULE "lifecycle"
#define FIXTURE "/tmp/lua-lsm-lifecycle-denied"
#define BUFFER_SIZE (64 * 1024 + 1)
#define WORKERS 5
#define MIN_OPERATIONS 100

enum phase { LIVE, WITHDRAWING, WITHDRAWN };
enum workload { WRITER, GETTER, ENUMERATOR, HOOK };

struct worker {
	pthread_t thread;
	enum workload workload;
	int id;
	atomic_uint live_ops;
	atomic_uint withdrawing_ops;
	atomic_uint post_ops;
	atomic_int error;
};

static atomic_int phase;
static atomic_bool stop;

/* Read responses completely, including the zero-byte EOF. */
static int read_all(int fd, char *buf, size_t size)
{
	size_t used = 0;
	ssize_t n;

	while (used < size - 1) {
		n = read(fd, buf + used, size - 1 - used);
		if (n < 0)
			return -errno;
		if (!n) {
			buf[used] = '\0';
			return used;
		}
		used += n;
	}
	return -E2BIG;
}

static int request(int fd, const char *cmd, const char *expected)
{
	char buf[128];
	size_t len = strlen(cmd);
	ssize_t n;
	int ret;

	n = write(fd, cmd, len);
	if (n < 0)
		return -errno;
	if (n != (ssize_t)len)
		return -EIO;
	ret = read_all(fd, buf, sizeof(buf));
	if (ret < 0)
		return ret;
	return strcmp(buf, expected) ? -EIO : 0;
}

static bool contains_module(const char *buf)
{
	const char *line = buf;

	do {
		if (!strncmp(line, MODULE, strlen(MODULE)) &&
		    isspace((unsigned char)line[strlen(MODULE)]))
			return true;
		line = strchr(line, '\n');
	} while (line && *++line);
	return false;
}

static int snapshot(const char *path, bool *present)
{
	char *buf = malloc(BUFFER_SIZE);
	int fd, ret, attempt;

	if (!buf)
		return -ENOMEM;
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		free(buf);
		return -errno;
	}
	for (attempt = 0; attempt < 200; attempt++) {
		ret = read_all(fd, buf, BUFFER_SIZE);
		if (ret != -EAGAIN)
			break;
		usleep(1000);
	}
	if (ret >= 0) {
		*present = contains_module(buf);
		ret = 0;
	}
	close(fd);
	free(buf);
	return ret;
}

static void *run_worker(void *arg)
{
	struct worker *worker = arg;
	char cmd[128];
	char value[128];
	bool present = false;
	int fd = -1, stage, ret;
	unsigned int sequence = 0;

	if (worker->workload == WRITER || worker->workload == GETTER) {
		fd = open(BASE "shdict", O_RDWR);
		if (fd < 0) {
			atomic_store(&worker->error, errno);
			return NULL;
		}
	}
	while (!atomic_load(&stop)) {
		stage = atomic_load(&phase);
		if (stage == WITHDRAWING)
			atomic_fetch_add(&worker->withdrawing_ops, 1);
		switch (worker->workload) {
		case WRITER:
			/* Two writers race on one key, retiring strings on every cycle. */
			switch (sequence++ % 5) {
			case 0:
				strcpy(cmd, "set " MODULE " runtime churn hex 610062\n");
				break;
			case 1:
				strcpy(cmd, "set " MODULE " runtime churn string replacement\n");
				break;
			case 2:
				strcpy(cmd, "set " MODULE " runtime churn number 7\n");
				break;
			case 3:
				strcpy(cmd, "set " MODULE " runtime churn boolean true\n");
				break;
			default:
				strcpy(cmd, "delete " MODULE " runtime churn\n");
			}
			ret = request(fd, cmd, "true");
			break;
		case GETTER:
			ret = write(fd, "get " MODULE " runtime churn\n",
				    sizeof("get " MODULE " runtime churn\n") - 1);
			if (ret < 0) {
				ret = -errno;
				/* A concurrent delete legitimately removes the key. */
				if (ret == -ENOENT && stage != WITHDRAWN)
					ret = 0;
			} else if (ret != sizeof("get " MODULE " runtime churn\n") - 1) {
				ret = -EIO;
			} else {
				ret = read_all(fd, value, sizeof(value));
				if ((ret == 3 && !memcmp(value, "a\0b", 3)) ||
				    (ret == 11 && !memcmp(value, "replacement", 11)) ||
				    (ret == 1 && value[0] == '7') ||
				    (ret == 4 && !memcmp(value, "true", 4)))
					ret = 0;
				else if (ret >= 0)
					ret = -EIO;
			}
			break;
		case ENUMERATOR:
			/* Each iteration opens a fresh, not a cached, snapshot. */
			ret = snapshot(BASE "shdict", &present);
			if (!ret && ((stage == WITHDRAWN && present) ||
				     (stage == LIVE && !present &&
				      atomic_load(&phase) == LIVE)))
				ret = -EIO;
			break;
		case HOOK:
			ret = open(FIXTURE, O_RDONLY);
			if (ret >= 0) {
				close(ret);
				ret = stage == LIVE && atomic_load(&phase) == LIVE ?
					-EIO : 0;
			} else {
				ret = errno == EPERM && stage != WITHDRAWN ?
					0 : -errno;
			}
			break;
		}
		if (worker->workload == WRITER || worker->workload == GETTER) {
			if (stage == WITHDRAWN) {
				/* New requests must not succeed after unregister returns. */
				ret = ret == -ESHUTDOWN || ret == -ENOENT ? 0 : -EIO;
			} else if (ret == -ESHUTDOWN || ret == -ENOENT) {
				if (atomic_load(&phase) != LIVE)
					ret = 0;
			}
		}
		if (ret) {
			atomic_store(&worker->error, -ret);
			break;
		}
		if (stage == LIVE)
			atomic_fetch_add(&worker->live_ops, 1);
		if (stage == WITHDRAWN)
			atomic_fetch_add(&worker->post_ops, 1);
		usleep(1000);
	}
	if (fd >= 0)
		close(fd);
	return NULL;
}

static int unregister_module(void)
{
	int fd, ret;
	ssize_t n;

	fd = open(BASE "unregister", O_WRONLY);
	if (fd < 0)
		return -errno;
	n = write(fd, MODULE "\n", sizeof(MODULE));
	ret = n < 0 ? -errno : n == sizeof(MODULE) ? 0 : -EIO;
	close(fd);
	return ret;
}

static int register_module(const char *policy)
{
	char buf[4096];
	int fd, ret, len;
	ssize_t n;

	fd = open(policy, O_RDONLY);
	if (fd < 0)
		return -errno;
	len = read_all(fd, buf, sizeof(buf));
	close(fd);
	if (len < 0)
		return len;
	fd = open(BASE "register", O_WRONLY);
	if (fd < 0)
		return -errno;
	n = write(fd, buf, len);
	ret = n < 0 ? -errno : n == len ? 0 : -EIO;
	close(fd);
	return ret;
}

static int wait_progress(struct worker *workers, enum phase stage)
{
	int attempt, i;
	bool ready;

	for (attempt = 0; attempt < 1000; attempt++) {
		ready = true;
		for (i = 0; i < WORKERS; i++) {
			if (atomic_load(&workers[i].error))
				return -atomic_load(&workers[i].error);
			if (atomic_load(stage == WITHDRAWN ? &workers[i].post_ops :
					stage == WITHDRAWING ? &workers[i].withdrawing_ops :
					&workers[i].live_ops) <
			    (stage == WITHDRAWING ? 1 : MIN_OPERATIONS))
				ready = false;
		}
		if (ready)
			return 0;
		usleep(10000);
	}
	return -ETIMEDOUT;
}

static int run_round(const char *policy)
{
	struct worker workers[WORKERS] = {};
	const enum workload workloads[] = { WRITER, WRITER, GETTER, ENUMERATOR, HOOK };
	bool present = false;
	char saved[128], *dump = NULL;
	int ret, fd, i, created = 0, cleanup, state_errno;
	int saved_fd = -1, dump_fd = -1;
	ssize_t n;

	ret = snapshot(BASE "modules", &present);
	if (ret || present)
		return ret ? ret : -EEXIST;
	ret = register_module(policy);
	if (ret)
		return ret;
	fd = open(BASE "shdict", O_RDWR);
	if (fd < 0) {
		ret = -errno;
		goto cleanup;
	}
	ret = request(fd, "set " MODULE " runtime stable string stable\n", "true");
	if (!ret)
		ret = request(fd, "set " MODULE " runtime blocked_path string " FIXTURE "\n",
			      "true");
	if (!ret)
		ret = request(fd, "set " MODULE " runtime churn hex 610062\n", "true");
	close(fd);
	if (ret)
		goto cleanup;
	/* Keep copied responses alive across node retirement and module removal. */
	saved_fd = open(BASE "shdict", O_RDWR);
	dump_fd = open(BASE "shdict", O_RDONLY);
	dump = malloc(BUFFER_SIZE);
	if (saved_fd < 0 || dump_fd < 0 || !dump) {
		ret = -ENOMEM;
		goto cleanup;
	}
	n = write(saved_fd, "get " MODULE " runtime churn\n",
		  sizeof("get " MODULE " runtime churn\n") - 1);
	if (n != sizeof("get " MODULE " runtime churn\n") - 1) {
		ret = n < 0 ? -errno : -EIO;
		goto cleanup;
	}
	/* One byte prepares the snapshot; keep the remaining copied bytes unread. */
	n = read(dump_fd, dump, 1);
	if (n != 1) {
		ret = n < 0 ? -errno : -EIO;
		goto cleanup;
	}
	atomic_store(&stop, false);
	atomic_store(&phase, LIVE);
	for (i = 0; i < WORKERS; i++) {
		workers[i].id = i;
		workers[i].workload = workloads[i];
		ret = pthread_create(&workers[i].thread, NULL, run_worker, &workers[i]);
		if (ret) {
			ret = -ret;
			goto join;
		}
		created++;
	}
	ret = wait_progress(workers, LIVE);
	if (ret)
		goto join;
	/* Do not stop or join workers until unregister and post-checks finish. */
	atomic_store(&phase, WITHDRAWING);
	/* Establish withdrawal-phase participation before a fast unregister can
	 * finish. Workers stay active across the syscall; these counters do not
	 * claim every worker crossed an instruction inside unregister itself.
	 */
	ret = wait_progress(workers, WITHDRAWING);
	if (ret)
		goto join;
	ret = unregister_module();
	if (ret && ret != -EBUSY)
		goto join;
	ksft_print_msg("unregister with workers active: %s\n", ret ? "EBUSY" : "removed");
	atomic_store(&phase, WITHDRAWN);
	ret = wait_progress(workers, WITHDRAWN);
join:
	atomic_store(&stop, true);
	for (i = 0; i < created; i++) {
		pthread_join(workers[i].thread, NULL);
		ksft_print_msg("worker %d: live=%u withdrawing=%u post=%u errno=%d\n", i,
			       atomic_load(&workers[i].live_ops),
			       atomic_load(&workers[i].withdrawing_ops),
			       atomic_load(&workers[i].post_ops),
			       atomic_load(&workers[i].error));
		if (!ret && atomic_load(&workers[i].error))
			ret = -atomic_load(&workers[i].error);
		if (!ret && !atomic_load(&workers[i].withdrawing_ops))
			ret = -ENODATA;
	}
	if (!ret) {
		ret = snapshot(BASE "modules", &present);
		state_errno = present ? ESHUTDOWN : ENOENT;
		fd = open(BASE "shdict", O_RDWR);
		if (fd < 0) {
			ret = -errno;
		} else {
			cleanup = request(fd, "get " MODULE " runtime stable\n", "stable");
			ksft_print_msg("post-unregister module: %s; get errno=%d\n",
				       present ? "retained, non-LIVE" : "removed", -cleanup);
			if (!ret && cleanup != -state_errno)
				ret = -EIO;
			close(fd);
		}
	}
cleanup:
	/* EBUSY is not completion: retry after all tasks stop, and prove removal. */
	for (i = 0; i < 3; i++) {
		cleanup = unregister_module();
		if (!cleanup || cleanup == -ENOENT)
			break;
		if (cleanup != -EBUSY)
			break;
		usleep(100000);
	}
	if (!ret && cleanup && cleanup != -ENOENT)
		ret = cleanup;
	cleanup = snapshot(BASE "modules", &present);
	if (!ret && (cleanup || present))
		ret = cleanup ? cleanup : -EBUSY;
	/* Old per-open copies remain readable even after complete module removal. */
	if (saved_fd >= 0) {
		cleanup = read_all(saved_fd, saved, sizeof(saved));
		if (!ret && (cleanup != 3 || memcmp(saved, "a\0b", 3)))
			ret = -EIO;
		close(saved_fd);
	}
	if (dump_fd >= 0 && dump) {
		cleanup = read_all(dump_fd, dump + 1, BUFFER_SIZE - 1);
		if (!ret && (cleanup < 0 || !contains_module(dump)))
			ret = cleanup < 0 ? cleanup : -EIO;
	}
	if (dump_fd >= 0)
		close(dump_fd);
	free(dump);
	if (!ret) {
		fd = open(BASE "shdict", O_RDWR);
		if (fd < 0)
			return -errno;
		cleanup = request(fd, "get " MODULE " runtime stable\n", "stable");
		close(fd);
		if (cleanup != -ENOENT)
			ret = -EIO;
	}
	return ret;
}

int main(int argc, char **argv)
{
	char *end;
	long rounds = 3;
	int i, fd, ret;

	ksft_print_header();
	if (argc < 2 || argc > 3)
		ksft_exit_fail_msg("usage: %s policy.lua [rounds]\n", argv[0]);
	if (argc == 3) {
		errno = 0;
		rounds = strtol(argv[2], &end, 10);
		if (errno || !*argv[2] || *end || rounds < 1 || rounds > 20)
			ksft_exit_fail_msg("rounds must be in 1..20\n");
	}
	if (access(BASE "shdict", F_OK))
		ksft_exit_skip("Lua-LSM securityfs is unavailable\n");
	fd = open(FIXTURE, O_CREAT | O_EXCL | O_WRONLY, 0600);
	if (fd < 0)
		ksft_exit_fail_msg("create fixture: %s\n", strerror(errno));
	close(fd);
	ksft_set_plan(rounds);
	/* Also catches a deadlock in teardown; the wrapper treats signals as failure. */
	alarm(300);
	for (i = 0; i < rounds; i++) {
		ret = run_round(argv[1]);
		ksft_test_result(!ret, "concurrent unregister round %d: %s\n", i + 1,
				 ret ? strerror(-ret) : "fully removed");
		if (ret) {
			unlink(FIXTURE);
			ksft_exit_fail();
		}
	}
	alarm(0);
	unlink(FIXTURE);
	ksft_exit_pass();
}
