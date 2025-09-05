# SPDX-License-Identifier: GPL-2.0-or-later
#
# Makefile for the Lua based LSM
#

obj-$(CONFIG_SECURITY_LUA_LSM) := lua-lsm.o

ccflags-$(CONFIG_SECURITY_LUA_LSM_DEBUG) += -DDEBUG

lua-lsm-y := lsm.o securityfs.o auxlib.o kvcache.o lsm_defs.o \
	lua_kernel.o lua_fs.o lua_net.o \
	lua_errno.o lua_capability.o lua_signal.o
