// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
/* Host deadlines are cooperative checkpoints, never asynchronous interrupts. */
#include <linux/timekeeping.h>

#define LUA_CORE
#include <linux/lua.h>
#include "ldebug.h"
#include "ldo.h"
#include "lstate.h"

static int expired(global_State *g)
{
  if (!g->budget_active)
    return 0;
  if (!g->budget_expired && (s64)(ktime_get_ns() - g->deadline) >= 0)
    g->budget_expired = 1;
  return g->budget_expired;
}

LUA_API void lua_budget_begin(lua_State *L, u64 timeout_ns)
{
  global_State *g = G(L);

  /* A nested host call must never replenish an existing deadline. */
  if (g->budget_active)
    luaG_runerror(L, "execution budget already active");
  g->deadline = ktime_get_ns() + min_t(u64, timeout_ns, S64_MAX);
  g->budget_count = LUA_BUDGET_INTERVAL;
  g->budget_expired = 0;
  g->budget_active = 1;
}

void luaD_checkbudget(lua_State *L)
{
  if (expired(G(L)))
    luaD_throw(L, LUA_ERRTIME);
}

LUA_API void lua_budget_check(lua_State *L)
{
  luaD_checkbudget(L);
}

/* Also used outside the protected dispatch, after any ordinary error. */
LUA_API int lua_budget_end(lua_State *L)
{
  global_State *g = G(L);
  int status = expired(g) ? LUA_ERRTIME : 0;

  g->budget_active = g->budget_expired = 0;
  g->deadline = 0;
  g->budget_count = 0;
  return status;
}
