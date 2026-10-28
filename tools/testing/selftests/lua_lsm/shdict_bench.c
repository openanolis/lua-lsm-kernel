// SPDX-License-Identifier: GPL-2.0
/* Optional benchmark, not a production administration client or default test. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BASE "/sys/kernel/security/lua/"
#define MAX_WORKERS 4
#define MAX_PAYLOAD 256
#define MODULE_PREFIX "perfbench_"

enum operation { OP_SET, OP_GET, OP_INCR };

struct scenario {
	enum operation op;
	unsigned int bytes;
	unsigned int threads;
	bool split;
};

struct worker {
	pthread_t thread;
	struct scenario scenario;
	pthread_barrier_t *ready;
	pthread_barrier_t *go;
	unsigned int count;
	unsigned int warmup;
	unsigned int id;
	char command[512];
	size_t command_len;
	char expected[MAX_PAYLOAD + 1];
	uint64_t *latency;
	uint64_t start;
	uint64_t end;
	long long last_counter;
	int error;
};

static uint64_t now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		perror("clock_gettime");
		exit(1);
	}
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static int read_response(int fd, char *buf, size_t size)
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

/* Timed part: one complete write and all reads through response EOF. */
static int exchange(int fd, const char *cmd, size_t len, char *response)
{
	ssize_t n = write(fd, cmd, len);

	if (n < 0)
		return -errno;
	if (n != (ssize_t)len)
		return -EIO;
	return read_response(fd, response, 512);
}

static int validate(struct worker *worker, const char *response)
{
	char *end;
	long long value;

	if (worker->scenario.op != OP_INCR)
		return strcmp(response, worker->expected) ? -EIO : 0;
	errno = 0;
	value = strtoll(response, &end, 10);
	if (errno || !*response || *end || value <= worker->last_counter)
		return -EIO;
	worker->last_counter = value;
	return 0;
}

static void *run_worker(void *arg)
{
	struct worker *worker = arg;
	char response[512];
	unsigned int i;
	uint64_t begin, end;
	int ret, fd;

	fd = open(BASE "shdict", O_RDWR);
	if (fd < 0)
		worker->error = -errno;
	for (i = 0; !worker->error && i < worker->warmup; i++) {
		ret = exchange(fd, worker->command, worker->command_len, response);
		worker->error = ret < 0 ? ret : validate(worker, response);
	}
	/* Even failed workers reach both barriers, so the main thread can exit. */
	pthread_barrier_wait(worker->ready);
	pthread_barrier_wait(worker->go);
	if (!worker->error) {
		worker->start = now_ns();
		for (i = 0; i < worker->count; i++) {
			begin = now_ns();
			ret = exchange(fd, worker->command, worker->command_len, response);
			end = now_ns();
			worker->latency[i] = end - begin;
			worker->end = end;
			/* Validation is outside request latency, but in group throughput. */
			worker->error = ret < 0 ? ret : validate(worker, response);
			if (worker->error)
				break;
		}
	}
	if (fd >= 0)
		close(fd);
	return NULL;
}

static int control(int fd, const char *cmd, const char *expected)
{
	char response[512];
	int ret = exchange(fd, cmd, strlen(cmd), response);

	return ret < 0 ? ret : strcmp(response, expected) ? -EIO : 0;
}

static int register_module(unsigned int id)
{
	char policy[512];
	ssize_t n;
	int fd, len, ret;

	len = snprintf(policy, sizeof(policy),
		       "return {name='%s%u', author='OSPP benchmark', "
		       "license='GPL-2.0', version=1, "
		       "file_open=function(file) return true end}\n", MODULE_PREFIX, id);
	fd = open(BASE "register", O_WRONLY);
	if (fd < 0)
		return -errno;
	n = write(fd, policy, len);
	ret = n < 0 ? -errno : n != len ? -EIO : 0;
	close(fd);
	return ret;
}

static int unregister_module(unsigned int id)
{
	char cmd[64];
	int fd, len, ret;
	ssize_t n;

	len = snprintf(cmd, sizeof(cmd), MODULE_PREFIX "%u\n", id);
	fd = open(BASE "unregister", O_WRONLY);
	if (fd < 0)
		return -errno;
	n = write(fd, cmd, len);
	ret = n < 0 ? -errno : n != len ? -EIO : 0;
	close(fd);
	return ret;
}

static int seed(int fd, unsigned int bytes)
{
	char payload[MAX_PAYLOAD + 1], cmd[512];
	unsigned int module, key;
	int ret;

	/* Four value keys and one counter in every dictionary, for every case. */
	memset(payload, 'a', bytes ? bytes : 32);
	payload[bytes ? bytes : 32] = '\0';
	for (module = 0; module < MAX_WORKERS; module++) {
		for (key = 0; key < MAX_WORKERS; key++) {
			snprintf(cmd, sizeof(cmd), "set " MODULE_PREFIX
				 "%u runtime value_%u string %s\n", module, key, payload);
			ret = control(fd, cmd, "true");
			if (ret)
				return ret;
		}
		snprintf(cmd, sizeof(cmd), "set " MODULE_PREFIX
			 "%u runtime counter number 0\n", module);
		ret = control(fd, cmd, "true");
		if (ret)
			return ret;
	}
	return 0;
}

static int compare_ns(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return (x > y) - (x < y);
}

static void make_command(struct worker *worker)
{
	unsigned int module = worker->scenario.split ? worker->id : 0;
	char payload[MAX_PAYLOAD + 1];

	memset(payload, 'a', worker->scenario.bytes);
	payload[worker->scenario.bytes] = '\0';
	switch (worker->scenario.op) {
	case OP_SET:
		snprintf(worker->command, sizeof(worker->command), "set " MODULE_PREFIX
			 "%u runtime value_%u string %s\n", module, worker->id, payload);
		strcpy(worker->expected, "true");
		break;
	case OP_GET:
		snprintf(worker->command, sizeof(worker->command), "get " MODULE_PREFIX
			 "%u runtime value_%u\n", module, worker->id);
		strcpy(worker->expected, payload);
		break;
	case OP_INCR:
		snprintf(worker->command, sizeof(worker->command), "incr " MODULE_PREFIX
			 "%u runtime counter 1\n", module);
		break;
	}
	worker->command_len = strlen(worker->command);
}

static int check_counter(int fd, struct scenario scenario,
			 unsigned int samples, unsigned int warmup)
{
	char cmd[128], expected[64];
	unsigned int i, modules = scenario.split ? scenario.threads : 1;
	unsigned int total = samples + warmup * scenario.threads;
	int ret;

	if (scenario.op != OP_INCR)
		return 0;
	for (i = 0; i < modules; i++) {
		snprintf(cmd, sizeof(cmd), "get " MODULE_PREFIX "%u runtime counter\n", i);
		snprintf(expected, sizeof(expected), "%u", total / modules);
		ret = control(fd, cmd, expected);
		if (ret)
			return ret;
	}
	return 0;
}

static int run_case(int fd, struct scenario scenario, unsigned int repeat,
		    unsigned int samples, unsigned int warmup)
{
	struct worker workers[MAX_WORKERS] = {};
	pthread_barrier_t ready, go;
	uint64_t *latency, start = UINT64_MAX, end = 0, elapsed;
	long double sum = 0;
	static const char * const names[] = { "set", "get", "incr" };
	unsigned int i, per_worker = samples / scenario.threads;
	int ret;

	ret = seed(fd, scenario.bytes);
	if (ret)
		return ret;
	latency = calloc(samples, sizeof(*latency));
	if (!latency)
		return -ENOMEM;
	ret = pthread_barrier_init(&ready, NULL, scenario.threads + 1);
	if (ret) {
		free(latency);
		return -ret;
	}
	ret = pthread_barrier_init(&go, NULL, scenario.threads + 1);
	if (ret) {
		pthread_barrier_destroy(&ready);
		free(latency);
		return -ret;
	}
	for (i = 0; i < scenario.threads; i++) {
		workers[i].scenario = scenario;
		workers[i].count = per_worker;
		workers[i].warmup = warmup;
		workers[i].id = i;
		workers[i].ready = &ready;
		workers[i].go = &go;
		workers[i].latency = latency + i * per_worker;
		make_command(&workers[i]);
		ret = pthread_create(&workers[i].thread, NULL, run_worker, &workers[i]);
		/* Exit rather than strand already-created workers at a partial barrier. */
		if (ret) {
			fprintf(stderr, "pthread_create: %s\n", strerror(ret));
			exit(1);
		}
	}
	pthread_barrier_wait(&ready);
	pthread_barrier_wait(&go);
	ret = 0;
	for (i = 0; i < scenario.threads; i++) {
		pthread_join(workers[i].thread, NULL);
		if (workers[i].error)
			ret = workers[i].error;
		if (workers[i].start < start)
			start = workers[i].start;
		if (workers[i].end > end)
			end = workers[i].end;
	}
	pthread_barrier_destroy(&ready);
	pthread_barrier_destroy(&go);
	if (!ret)
		ret = check_counter(fd, scenario, samples, warmup);
	if (!ret && end <= start)
		ret = -EIO;
	if (!ret) {
		elapsed = end - start;
		for (i = 0; i < samples; i++)
			sum += latency[i];
		qsort(latency, samples, sizeof(*latency), compare_ns);
		printf("%s,%u,%u,%s,%u,%u,0,%" PRIu64 ",%.3f,%.3Lf,%.3f,%.3f,%.3f,%.3f\n",
		       names[scenario.op], scenario.bytes, scenario.threads,
		       scenario.split ? "split" : "same", repeat, samples, elapsed,
		       (double)samples * 1e9 / elapsed, sum / samples / 1e3L,
		       latency[(samples + 1) / 2 - 1] / 1e3,
		       latency[(samples * 95 + 99) / 100 - 1] / 1e3,
		       latency[(samples * 99 + 99) / 100 - 1] / 1e3,
		       latency[samples - 1] / 1e3);
		fflush(stdout);
	}
	free(latency);
	return ret;
}

static unsigned int argument(const char *value, unsigned int low, unsigned int high)
{
	char *end;
	unsigned long n;

	errno = 0;
	n = strtoul(value, &end, 10);
	if (errno || !*value || *end || n < low || n > high) {
		fprintf(stderr, "invalid numeric input: %s\n", value);
		exit(1);
	}
	return n;
}

int main(int argc, char **argv)
{
	struct scenario cases[25];
	const enum operation ops[] = { OP_SET, OP_GET, OP_SET, OP_GET, OP_INCR };
	const unsigned int bytes[] = { 32, 32, 256, 256, 0 };
	const unsigned int threads[] = { 1, 2, 2, 4, 4 };
	const bool split[] = { false, false, true, false, true };
	unsigned int samples = 10000, repeats = 5, warmup = 500;
	unsigned int i, j, r, registered = 0;
	uint64_t begin, clock_sum = 0;
	char modules[16384];
	int fd, ret, result = 0;

	if (argc > 4) {
		fprintf(stderr, "usage: %s [total_samples repeats warmup_per_thread]\n", argv[0]);
		return 1;
	}
	if (argc > 1)
		samples = argument(argv[1], 16, 1000000);
	if (argc > 2)
		repeats = argument(argv[2], 1, 20);
	if (argc > 3)
		warmup = argument(argv[3], 1, 100000);
	if (samples % MAX_WORKERS) {
		fprintf(stderr, "total_samples must be divisible by four\n");
		return 1;
	}
	fd = open(BASE "modules", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "SKIP: mount Lua-LSM securityfs first\n");
		return 4;
	}
	ret = read_response(fd, modules, sizeof(modules));
	close(fd);
	if (ret < 0 || strstr(modules, MODULE_PREFIX)) {
		fprintf(stderr, "module listing failed or benchmark module already exists\n");
		return 1;
	}
	for (i = 0; i < MAX_WORKERS; i++) {
		ret = register_module(i);
		if (ret) {
			result = 1;
			goto cleanup;
		}
		registered++;
	}
	fd = open(BASE "shdict", O_RDWR);
	if (fd < 0) {
		result = 1;
		goto cleanup;
	}
	for (i = 0; i < 10000; i++) {
		begin = now_ns();
		clock_sum += now_ns() - begin;
	}
	printf("# samples=%u repeats=%u warmup_per_thread=%u clock=CLOCK_MONOTONIC\n",
	       samples, repeats, warmup);
	printf("# clock_pair_mean_ns=%.3f (not subtracted)\n", clock_sum / 10000.0);
	puts("BENCH_CSV_BEGIN");
	puts("op,bytes,threads,layout,repeat,requests,errors,elapsed_ns,ops_s,mean_us,p50_us,p95_us,p99_us,max_us");
	for (i = 0; i < 5; i++)
		for (j = 0; j < 5; j++)
			cases[i * 5 + j] = (struct scenario){ ops[i], bytes[i], threads[j], split[j] };
	/* Rotate case order between repetitions to reduce fixed-order bias. */
	for (r = 0; r < repeats; r++) {
		for (i = 0; i < 25; i++) {
			j = (i + r * 7) % 25;
			ret = run_case(fd, cases[j], r + 1, samples, warmup);
			if (ret) {
				fprintf(stderr, "BENCH ERROR: case=%u repeat=%u errno=%d (%s)\n",
					j, r + 1, -ret, strerror(-ret));
				result = 1;
				goto close_fd;
			}
		}
	}
	puts("BENCH_CSV_END");
close_fd:
	close(fd);
cleanup:
	/* Cleanup is excluded from all timings; never remove unrelated modules. */
	for (i = 0; i < registered; i++) {
		for (j = 0; j < 5; j++) {
			ret = unregister_module(i);
			if (!ret || ret == -ENOENT)
				break;
			if (ret != -EBUSY)
				break;
			usleep(100000);
		}
		if (ret && ret != -ENOENT) {
			fprintf(stderr, "benchmark cleanup errno=%d for module %u\n", -ret, i);
			result = 1;
		}
	}
	puts(result ? "LUA-LSM-SHDICT-BENCH: FAIL" : "LUA-LSM-SHDICT-BENCH: ALL PASS");
	return result;
}
