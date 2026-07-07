# SPDX-License-Identifier: GPL-2.0-or-later
#
# Makefile for the Lua based LSM
#

ccflags-$(CONFIG_SECURITY_LUA_LSM_DEBUG) += -DDEBUG

obj-$(CONFIG_SECURITY_LUA_LSM) += lua-lsm-core.o
lua-lsm-core-y := lsm.o securityfs.o auxlib.o kvcache.o lsm_defs.o \
	lib_registry.o lib_metatables.o

obj-$(CONFIG_LUA_LSM_LIB_KERNEL)     += lua_kernel.o
obj-$(CONFIG_LUA_LSM_LIB_FS)         += lua_fs.o
obj-$(CONFIG_LUA_LSM_LIB_NET)        += lua_net.o
obj-$(CONFIG_LUA_LSM_LIB_ERRNO)      += lua_errno.o
obj-$(CONFIG_LUA_LSM_LIB_CAPABILITY) += lua_capability.o
obj-$(CONFIG_LUA_LSM_LIB_SIGNAL)     += lua_signal.o
