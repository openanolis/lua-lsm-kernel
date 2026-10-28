// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/wait.h>
#include "../kselftest.h"
#include "shdict_test.h"

/* No file_open hook: opening /proc controls must not initialize the child VM. */
static const char policy[] = "return {name='faultcase',license='GPL-2.0',"
	"inode_mkdir=function() return true end}";

enum target { COLD, SET, GET, SNAPSHOT, OPEN, TARGETS };

/* 0 = injected and recovered; 1 = beyond last allocation; 2 = failure. */
static int attempt(enum target target, unsigned int nth)
{
	char command[2300], response[65537], control[32];
	int ctl, fd, n, err, consumed, ret, opened = -1;
	ssize_t result;

	ctl = open("/proc/self/fail-nth", O_RDWR);
	fd = open(SD_BASE "shdict", O_RDWR);
	if (ctl < 0 || fd < 0)
		return 2;
	if (target != COLD && sd_expect(fd, "get faultcase runtime ready", "true"))
		return 2;
	if (target == SNAPSHOT) {
		close(fd);
		fd = open(SD_BASE "shdict", O_RDWR);
		if (fd < 0)
			return 2;
	}
	if (target == GET)
		snprintf(command, sizeof(command), "get faultcase runtime payload");
	else {
		n = snprintf(command, sizeof(command), "set faultcase runtime changed string ");
		memset(command + n, 'z', 2048);
		command[n + 2048] = 0;
	}
	snprintf(control, sizeof(control), "%u", nth);
	if (sd_write(ctl, control))
		return 2;
	if (target == SNAPSHOT)
		result = read(fd, response, sizeof(response));
	else if (target == OPEN) {
		opened = open(SD_BASE "shdict", O_RDWR);
		result = opened;
	} else {
		result = write(fd, command, strlen(command));
	}
	err = errno;
	/* The fail-nth proc reader has no allocating seq-file implementation. */
	n = pread(ctl, control, sizeof(control) - 1, 0);
	if (n <= 0 || sd_write(ctl, "0"))
		return 2;
	control[n] = 0;
	consumed = atoi(control) == 0;
	close(ctl);
	if (opened >= 0)
		close(opened);
	if (result < 0 && err != ENOMEM)
		return 2;
	if (result >= 0 && target != SNAPSHOT && target != OPEN) {
		ret = sd_read(fd, response, sizeof(response));
		if (target == GET) {
			if (ret != 2048 || response[0] != 'p')
				return 2;
		} else if (ret != 4 || memcmp(response, "true", 4)) {
			return 2;
		}
	}
	/* Same task and same FD must recover after every failure. */
	if (sd_expect(fd, "set faultcase runtime recovery string alive", "true") ||
	    sd_expect(fd, "get faultcase runtime recovery", "alive") ||
	    sd_expect(fd, "delete faultcase runtime recovery", "true"))
		return 2;
	close(fd);
	return consumed ? 0 : 1;
}

int main(void)
{
	static const char * const names[] = { "cold VM and bridge setup", "string set allocation",
		"string get allocation and reference cleanup", "enumeration allocation",
		"open context allocation" };
	char command[2300];
	int fd, target, status, failed = 0, injected, result, n;
	unsigned int nth;
	pid_t pid;

	alarm(600);
	ksft_print_header();
	ksft_set_plan(TARGETS);
	if (access("/proc/self/fail-nth", R_OK | W_OK))
		ksft_exit_fail_msg("fault injection configuration is required\n");
	if (sd_file("/sys/kernel/debug/failslab/ignore-gfp-wait", "N") ||
	    sd_file("/sys/kernel/debug/fail_page_alloc/ignore-gfp-wait", "N") ||
	    sd_file("/sys/kernel/debug/failslab/verbose", "0") ||
	    sd_file("/sys/kernel/debug/fail_page_alloc/verbose", "0"))
		ksft_exit_fail_msg("configure isolated task fail-nth\n");
	if (sd_file(SD_BASE "register", policy))
		ksft_exit_fail_msg("register fault fixture\n");
	fd = open(SD_BASE "shdict", O_RDWR);
	if (fd < 0 || sd_expect(fd, "set faultcase runtime ready boolean true", "true"))
		ksft_exit_fail_msg("prepare fault fixture\n");
	n = snprintf(command, sizeof(command), "set faultcase runtime payload string ");
	memset(command + n, 'p', 2048);
	command[n + 2048] = 0;
	if (sd_expect(fd, command, "true"))
		ksft_exit_fail_msg("prepare string fixture\n");
	/* A later capture allocation may fail after the first dict holds refs. */
	if (sd_expect(fd, "set faultcase second payload string retained", "true"))
		ksft_exit_fail_msg("prepare second snapshot dictionary\n");
	close(fd);
	for (target = 0; target < TARGETS; target++) {
		injected = 0;
		result = 2;
		for (nth = 1; nth <= 4096; nth++) {
			pid = fork();
			if (!pid)
				_exit(attempt(target, nth));
			if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
				break;
			result = WEXITSTATUS(status);
			if (result)
				break;
			injected++;
		}
		ksft_test_result(result == 1 && injected > 0,
			"%s injected=%d last_nth=%u result=%d\n", names[target],
			injected, nth, result);
		failed |= result != 1 || injected == 0;
	}
	if (sd_unregister("faultcase"))
		ksft_exit_fail_msg("fault fixture must fully unregister\n");
	puts(failed ? "LUA-LSM-SHDICT-FAULT: FAIL" : "LUA-LSM-SHDICT-FAULT: ALL PASS");
	return failed ? KSFT_FAIL : KSFT_PASS;
}
