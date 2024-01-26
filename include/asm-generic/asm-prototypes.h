/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bitops.h>
#undef __memset
extern void *__memset(void *, int, __kernel_size_t);
#undef __memcpy
extern void *__memcpy(void *, const void *, __kernel_size_t);
#undef __memmove
extern void *__memmove(void *, const void *, __kernel_size_t);
#undef memset
extern void *memset(void *, int, __kernel_size_t);
#undef memcpy
extern void *memcpy(void *, const void *, __kernel_size_t);
#undef memmove
extern void *memmove(void *, const void *, __kernel_size_t);
struct label_t;
#undef setjmp
extern int setjmp(struct label_t *);
#undef longjmp
extern void longjmp(struct label_t *, int);
