/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TOOLS_ENDIAN_H_2
#define _TOOLS_ENDIAN_H_2

#ifdef __linux__
/*
 * Defer to libc so BYTE_ORDER/LITTLE_ENDIAN/BIG_ENDIAN stay defined;
 * the shim below would leave them undefined and break host tools
 * (e.g. relocs enables both endian branches and miscompiles).
 */
#include_next <endian.h>
#include <byteswap.h>
#else

#include <byteswap.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN

#ifndef htole16
#define htole16(x) (x)
#endif
#ifndef htole32
#define htole32(x) (x)
#endif
#ifndef htole64
#define htole64(x) (x)
#endif

#ifndef le16toh
#define le16toh(x) (x)
#endif

#ifndef le32toh
#define le32toh(x) (x)
#endif

#ifndef le64toh
#define le64toh(x) (x)
#endif

#else /* __BYTE_ORDER */

#ifndef htole16
#define htole16(x) __bswap_16(x)
#endif
#ifndef htole32
#define htole32(x) __bswap_32(x)
#endif
#ifndef htole64
#define htole64(x) __bswap_64(x)
#endif

#ifndef le16toh
#define le16toh(x) __bswap_16(x)
#endif

#ifndef le32toh
#define le32toh(x) __bswap_32(x)
#endif

#ifndef le64toh
#define le64toh(x) __bswap_64(x)
#endif

#endif

#endif /* __linux__ */

#endif /* _TOOLS_ENDIAN_H_2 */
