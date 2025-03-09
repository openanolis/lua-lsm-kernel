/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 Alibaba Group.
 */

#include <linux/linkage.h>
#include <asm/assembler.h>


/*
 * int setjmp(struct label_t *label);
 */
.align 3
SYM_FUNC_START(setjmp)
	stp		x19, x20, [x0, #(0 * 8)]
	stp		x21, x22, [x0, #(2 * 8)]
	stp		x23, x24, [x0, #(4 * 8)]
	stp		x25, x26, [x0, #(6 * 8)]
	stp		x27, x28, [x0, #(8 * 8)]
	stp		x29, x30, [x0, #(10 * 8)]
	mov		x1, sp
	str		x1, [x0, #(12 * 8)]
	mov		x0, #0
	ret
SYM_FUNC_END(setjmp)
EXPORT_SYMBOL(setjmp)

/*
 * void longjmp(struct label_t *label, int val);
 */
.align 3
SYM_FUNC_START(longjmp)
	ldp		x19, x20, [x0, #(0 * 8)]
	ldp		x21, x22, [x0, #(2 * 8)]
	ldp		x23, x24, [x0, #(4 * 8)]
	ldp		x25, x26, [x0, #(6 * 8)]
	ldp		x27, x28, [x0, #(8 * 8)]
	ldp		x29, x30, [x0, #(10 * 8)]
	ldr		x0, [x0, #(12 * 8)]
	mov		sp, x0
	mov		x0, x1
	ret
SYM_FUNC_END(longjmp)
EXPORT_SYMBOL(longjmp)
