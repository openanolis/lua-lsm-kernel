# SPDX-License-Identifier: GPL-2.0
#
# Lua-LSM securityfs shared dict PoC selftest.
#
# The shell test drives /sys/kernel/security/lua/shdict and needs a kernel
# with CONFIG_SECURITY_LUA_LSM plus securityfs mounted; it is meant to run
# in the lua-lsm QEMU development initramfs (see README.md for the repro
# instructions).

TEST_PROGS := shdict_poc.sh shdict_stress.sh shdict_lifecycle.sh shdict_shared_fd.sh shdict_boundary.sh shdict_snapshot.sh
TEST_GEN_PROGS_EXTENDED := shdict_lifecycle shdict_bench shdict_shared_fd shdict_boundary shdict_fault shdict_manage_bench shdict_snapshot
TEST_FILES := shdict_test.h shdict_trace.sh shdict_kmemleak.sh qemu_init.sh shdict_poc.lua shdict_stress.lua shdict_lifecycle.lua

CFLAGS += -O2 -Wall -Wextra -pthread
LDLIBS += -pthread

include ../lib.mk
