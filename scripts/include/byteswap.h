#ifndef _BITS_BYTESWAP_H
#define _BITS_BYTESWAP_H 1

#include <sys/types.h>

/* Swap bytes in 16-bit value.  */
#define __bswap_constant_16(x)					\
  ((__uint16_t) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))

static __inline __uint16_t
__bswap_16 (__uint16_t __bsx)
{
#if defined(__clang__) || defined(__GNUC__)
  return __builtin_bswap16 (__bsx);
#else
  return __bswap_constant_16 (__bsx);
#endif
}

/* Swap bytes in 32-bit value.  */
#define __bswap_constant_32(x)					\
  ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >> 8)	\
   | (((x) & 0x0000ff00u) << 8) | (((x) & 0x000000ffu) << 24))

static __inline __uint32_t
__bswap_32 (__uint32_t __bsx)
{
#if defined(__clang__) || defined(__GNUC__)
  return __builtin_bswap32 (__bsx);
#else
  return __bswap_constant_32 (__bsx);
#endif
}

/* Swap bytes in 64-bit value.  */
#define __bswap_constant_64(x)			\
  ((((x) & 0xff00000000000000ull) >> 56)	\
   | (((x) & 0x00ff000000000000ull) >> 40)	\
   | (((x) & 0x0000ff0000000000ull) >> 24)	\
   | (((x) & 0x000000ff00000000ull) >> 8)	\
   | (((x) & 0x00000000ff000000ull) << 8)	\
   | (((x) & 0x0000000000ff0000ull) << 24)	\
   | (((x) & 0x000000000000ff00ull) << 40)	\
   | (((x) & 0x00000000000000ffull) << 56))

__extension__ static __inline __uint64_t
__bswap_64 (__uint64_t __bsx)
{
#if defined(__clang__) || defined(__GNUC__)
  return __builtin_bswap64 (__bsx);
#else
  return __bswap_constant_64 (__bsx);
#endif
}



/* The following definitions must all be macros, otherwise some
   of the possible optimizations are not possible.  */

/* Return a value with both bytes in the 16 bit argument swapped.  */
#define bswap_16(x) __bswap_16 (x)

/* Return a value with all bytes in the 32 bit argument swapped.  */
#define bswap_32(x) __bswap_32 (x)

/* Return a value with all bytes in the 64 bit argument swapped.  */
#define bswap_64(x) __bswap_64 (x)

#endif /* _BITS_BYTESWAP_H */
