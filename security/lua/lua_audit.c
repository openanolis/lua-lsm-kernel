/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#include "debug.h"
#include <linux/audit.h>
#include <linux/ctype.h>
#include <linux/lua.h>
#include <linux/lauxlib.h>
#include "lsm.h"
#include "auxlib.h"

/*
 * A key holding whitespace or '=' would forge extra fields and corrupt the
 * record for ausearch/aureport.
 */
static bool audit_key_valid(const char *key, size_t len)
{
	size_t i;

	if (len == 0 || isdigit(key[0]))
		return false;
	for (i = 0; i < len; i++) {
		if (!isalnum(key[i]) && key[i] != '_')
			return false;
	}
	return true;
}

/*
 * Modules are loaded with their name as the chunk name, so a policy function
 * reports it as its source. pcall() interposes a C frame between that function
 * and this one.
 */
static const char *audit_module_name(lua_State *L)
{
	lua_Debug ar;
	int level;

	for (level = 1; lua_getstack(L, level, &ar); level++) {
		if (!lua_getinfo(L, "S", &ar))
			break;
		if (ar.source && ar.what && ar.what[0] != 'C')
			return ar.source;
	}
	return NULL;
}

/* A rejected call must not leave a fieldless record behind. */
static void audit_check_fields(lua_State *L)
{
	lua_pushnil(L);
	while (lua_next(L, 1) != 0) {
		const char *key;
		size_t klen;

		if (lua_type(L, -2) != LUA_TSTRING)
			luaL_error(L, "audit.log: key must be a string");
		key = lua_tolstring(L, -2, &klen);
		if (!audit_key_valid(key, klen))
			luaL_error(L, "audit.log: invalid key '%s'", key);

		switch (lua_type(L, -1)) {
		case LUA_TSTRING:
		case LUA_TNUMBER:
		case LUA_TBOOLEAN:
			break;
		default:
			luaL_error(L, "audit.log: bad value for '%s'", key);
		}

		lua_pop(L, 1);
	}
}

static int lua_audit_log(lua_State *L)
{
	struct audit_buffer *ab;
	const char *module;

	/* audit_log_start() does not gate on audit_enabled itself. */
	if (!audit_enabled) {
		lua_pushboolean(L, 0);
		return 1;
	}

	luaL_checktype(L, 1, LUA_TTABLE);
	audit_check_fields(L);

	ab = audit_log_start(audit_context(), lua_lsm_gfp(), AUDIT_LUA);
	if (!ab) {
		lua_pushboolean(L, 0);
		return 1;
	}

	module = audit_module_name(L);
	audit_log_format(ab, "lmod=");
	audit_log_untrustedstring(ab, module ? module : "?");

	lua_pushnil(L);
	while (lua_next(L, 1) != 0) {
		/* stack: [..., table, key, value] */
		const char *key = lua_tostring(L, -2);

		switch (lua_type(L, -1)) {
		case LUA_TSTRING: {
			size_t vlen;
			/*
			 * strlen() would stop at an embedded NUL and silently
			 * drop the rest of the field.
			 */
			const char *val = lua_tolstring(L, -1, &vlen);

			audit_log_format(ab, " %s=", key);
			audit_log_n_untrustedstring(ab, val, vlen);
			break;
		}
		case LUA_TNUMBER:
			audit_log_format(ab, " %s=%lld", key,
					 (long long)lua_tointeger(L, -1));
			break;
		default:
			audit_log_format(ab, " %s=%d", key,
					 lua_toboolean(L, -1) ? 1 : 0);
			break;
		}

		lua_pop(L, 1);		/* pop value, keep key for lua_next */
	}

	audit_log_end(ab);
	lua_pushboolean(L, 1);
	return 1;
}

static const luaL_Reg auditlib[] = {
	{ "log",	lua_audit_log	},
	{ NULL, NULL }
};

LUALIB_API int luaopen_audit(lua_State *L)
{
	luaL_newlib(L, auditlib);
	return 1;
}
