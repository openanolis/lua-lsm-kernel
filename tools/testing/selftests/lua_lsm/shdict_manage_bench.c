// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>
#include "shdict_test.h"

static const char policy[] = "return {name='managebench',license='GPL-2.0',"
	"inode_mkdir=function() return true end}";
static pthread_barrier_t ready;
static atomic_uint snapshot_retries;
struct worker {
	pthread_t thread;
	unsigned int id, samples;
	int mixed, error;
	uint64_t *latency, begin, end;
};

static uint64_t now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static int snapshot(void)
{
	char buf[65537];
	int fd = open(SD_BASE "shdict", O_RDONLY), ret, attempt;

	if (fd < 0)
		return -errno;
	for (attempt = 0; attempt < 200; attempt++) {
		ret = sd_read(fd, buf, sizeof(buf) - 1);
		if (ret != -EAGAIN)
			break;
		atomic_fetch_add(&snapshot_retries, 1);
		usleep(1000);
	}
	close(fd);
	if (ret <= 0)
		return ret ? ret : -EIO;
	buf[ret] = 0;
	return strstr(buf, "managebench runtime seed string ") ? 0 : -EIO;
}

static void *work(void *arg)
{
	struct worker *w = arg;
	char set[128], response[4097];
	int fd = open(SD_BASE "shdict", O_RDWR), ret = 0;
	unsigned int i;
	uint64_t start;

	snprintf(set, sizeof(set), "set managebench runtime writer%u string value", w->id);
	if (fd < 0)
		ret = -errno;
	if (!ret)
		ret = sd_expect(fd, set, "true"); /* Warm the task VM before timing. */
	pthread_barrier_wait(&ready);
	w->begin = now();
	for (i = 0; i < w->samples && !ret; i++) {
		start = now();
		if (!w->mixed || i % 4 == 0) {
			ret = snapshot();
		} else if (i % 4 == 1) {
			ret = sd_expect(fd, "get managebench runtime seed", "ssssssssssssssssssssssssssssssss");
		} else if (i % 4 == 2) {
			ret = sd_expect(fd, set, "true");
		} else {
			ret = sd_write(fd, "incr managebench runtime counter 1");
			if (!ret) {
				ret = sd_read(fd, response, sizeof(response) - 1);
				if (ret > 0) {
					char *end;

					response[ret] = 0;
					errno = 0;
					ret = strtoull(response, &end, 10) > 0 && !errno && !*end ? 0 : -EIO;
				} else if (!ret) {
					ret = -EIO;
				}
			}
		}
		w->latency[i] = now() - start;
	}
	w->end = now();
	w->error = ret;
	if (fd >= 0)
		close(fd);
	return NULL;
}

static int compare(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
	struct worker w[4];
	uint64_t *latency, begin, end;

	long double sum;
	unsigned int samples = 1000, repeats = 5, threads, r, i, mode, total;
	char cmd[160], expected[32], *tail;
	int fd, ret = 0;

	if (argc == 2) {
		unsigned long n = strtoul(argv[1], &tail, 10);

		if (*tail || n < 4 || n > 100000 || n % 4)
			return 1;
		samples = n;
		repeats = 1;
	} else if (argc != 1) {
		return 1;
	}
	alarm(180);
	if (sd_file(SD_BASE "register", policy))
		return 1;
	fd = open(SD_BASE "shdict", O_RDWR);
	if (fd < 0)
		return 1;
	if (sd_expect(fd, "set managebench runtime seed string ssssssssssssssssssssssssssssssss", "true"))
		return 1;
	for (i = 0; i < 128; i++) {
		snprintf(cmd, sizeof(cmd), "set managebench runtime k%u string ssssssssssssssssssssssssssssssss", i);
		if (sd_expect(fd, cmd, "true"))
			return 1;
	}
	puts("MANAGE_CSV_BEGIN");
	puts("op,threads,repeat,requests,errors,ops_s,mean_us,p50_us,p95_us,p99_us");
	for (mode = 0; mode < 2 && !ret; mode++) {
		for (threads = 1; threads <= 4 && !ret; threads *= 2) {
			for (r = 1; r <= repeats && !ret; r++) {
				if (sd_expect(fd, "set managebench runtime counter number 0", "true"))
					return 1;
				total = samples * threads;
				latency = calloc(total, sizeof(*latency));
				if (!latency || pthread_barrier_init(&ready, NULL, threads))
					return 1;
				for (i = 0; i < threads; i++) {
					w[i] = (struct worker){ .id = i, .samples = samples,
						.mixed = mode, .latency = latency + i * samples };
					if (pthread_create(&w[i].thread, NULL, work, &w[i]))
						exit(1);
				}
				begin = UINT64_MAX;
				end = 0;
				for (i = 0; i < threads; i++) {
					pthread_join(w[i].thread, NULL);
					ret |= w[i].error;
					if (w[i].begin < begin)
						begin = w[i].begin;
					if (w[i].end > end)
						end = w[i].end;
				}
				pthread_barrier_destroy(&ready);
				snprintf(expected, sizeof(expected), "%u", mode ? total / 4 : 0);
				ret |= sd_expect(fd, "get managebench runtime counter", expected);
				if (!ret) {
					sum = 0;
					for (i = 0; i < total; i++)
						sum += latency[i];
					qsort(latency, total, sizeof(*latency), compare);
					printf("%s,%u,%u,%u,0,%.3f,%.3Lf,%.3f,%.3f,%.3f\n",
						mode ? "mixed" : "enum", threads, r, total,
						total * 1e9 / (end - begin), sum / total / 1e3L,
						latency[(total - 1) / 2] / 1e3,
						latency[(total * 95 + 99) / 100 - 1] / 1e3,
						latency[(total * 99 + 99) / 100 - 1] / 1e3);
				}
				free(latency);
			}
		}
	}
	puts("MANAGE_CSV_END");
	printf("MANAGE_ENUM_RETRIES=%u (included in latency)\n", atomic_load(&snapshot_retries));
	close(fd);
	ret |= sd_unregister("managebench");
	puts(ret ? "LUA-LSM-MANAGE-BENCH: FAIL" : "LUA-LSM-MANAGE-BENCH: ALL PASS");
	return ret ? 1 : 0;
}
