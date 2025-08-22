/*
** $Id: linit.c,v 1.14.1.1 2007/12/27 13:02:25 roberto Exp $
** Initialization of libraries for lua.c
** See Copyright Notice in lua.h
*/


#define linit_c
#define LUA_LIB

#include <linux/lua.h>

#include <linux/lualib.h>
#include <linux/lauxlib.h>


static const luaL_Reg lualibs[] = {
  {"", luaopen_base},
#ifndef __KERNEL__
  {LUA_LOADLIBNAME, luaopen_package},
#endif
  {LUA_TABLIBNAME, luaopen_table},
#ifndef __KERNEL__
  {LUA_IOLIBNAME, luaopen_io},
  {LUA_OSLIBNAME, luaopen_os},
#endif
  {LUA_STRLIBNAME, luaopen_string},
#ifndef __KERNEL__
  {LUA_MATHLIBNAME, luaopen_math},
#endif
  {LUA_DBLIBNAME, luaopen_debug},
  {NULL, NULL}
};


LUALIB_API void luaL_openlibs (lua_State *L) {
  const luaL_Reg *lib = lualibs;
  for (; lib->func; lib++) {
    lua_pushcfunction(L, lib->func);
    lua_pushstring(L, lib->name);
    lua_call(L, 1, 0);
  }
}

