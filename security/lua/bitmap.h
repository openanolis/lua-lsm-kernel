/*	$NetBSD: bitops.h,v 1.16 2024/05/12 10:34:56 rillig Exp $	*/

/*-
 * Copyright (c) 2007, 2010 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas and Joerg Sonnenberger.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _SYS_BITMAP_H_
#define _SYS_BITMAP_H_

#include <linux/log2.h>

#define __BITMAP_TYPE(__s, __t, __n) struct __s { \
    __t _b[__BITMAP_SIZE(__t, __n)]; \
}

#define __BITMAP_BITS(__t)		(sizeof(__t) * 8)
#define __BITMAP_SHIFT(__t)		(ilog2(__BITMAP_BITS(__t)))
#define __BITMAP_MASK(__t)		(__BITMAP_BITS(__t) - 1)
#define __BITMAP_SIZE(__t, __n) \
    (((__n) + (__BITMAP_BITS(__t) - 1)) / __BITMAP_BITS(__t))
#define __BITMAP_BIT(__n, __v) \
    ((__typeof__((__v)->_b[0]))1 << ((__n) & __BITMAP_MASK(*(__v)->_b)))
#define __BITMAP_WORD(__n, __v) \
    ((__n) >> __BITMAP_SHIFT(*(__v)->_b))

#define __BITMAP_SET(__n, __v) \
    ((__v)->_b[__BITMAP_WORD(__n, __v)] |= __BITMAP_BIT(__n, __v))
#define __BITMAP_CLR(__n, __v) \
    ((__v)->_b[__BITMAP_WORD(__n, __v)] &= ~__BITMAP_BIT(__n, __v))
#define __BITMAP_ISSET(__n, __v) \
    ((__v)->_b[__BITMAP_WORD(__n, __v)] & __BITMAP_BIT(__n, __v))

#define __BITMAP_ZERO(__v) do {						\
	size_t __i;							\
	for (__i = 0; __i < ARRAY_SIZE((__v)->_b); __i++)		\
		(__v)->_b[__i] = 0;					\
	} while (0)

#endif /* _SYS_BITMAP_H_ */
