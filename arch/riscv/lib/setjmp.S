/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/export.h>
#include <linux/linkage.h>
#include <asm/asm.h>

/*
 * int setjmp(struct label_t *label);
 */
SYM_FUNC_START(setjmp)
	REG_S	ra,  0*SZREG(a0)
	REG_S	sp,  1*SZREG(a0)
	REG_S	s0,  2*SZREG(a0)
	REG_S	s1,  3*SZREG(a0)
	REG_S	s2,  4*SZREG(a0)
	REG_S	s3,  5*SZREG(a0)
	REG_S	s4,  6*SZREG(a0)
	REG_S	s5,  7*SZREG(a0)
	REG_S	s6,  8*SZREG(a0)
	REG_S	s7,  9*SZREG(a0)
	REG_S	s8, 10*SZREG(a0)
	REG_S	s9, 11*SZREG(a0)
	REG_S	s10, 12*SZREG(a0)
	REG_S	s11, 13*SZREG(a0)
#ifdef CONFIG_SHADOW_CALL_STACK
	REG_S	gp, 14*SZREG(a0)
#endif

	li	a0, 0
	ret
SYM_FUNC_END(setjmp)
EXPORT_SYMBOL(setjmp)

/*
 * void longjmp(struct label_t *label, int val);
 */
SYM_FUNC_START(longjmp)
#ifdef CONFIG_KASAN_STACK
	/* Unpoison only the stack frames bypassed by this jump. */
	REG_L	t0, 1*SZREG(a0)
	bgeu	sp, t0, 1f
	sub	t0, t0, sp
	addi	sp, sp, -16
	REG_S	a0, 0*SZREG(sp)
	REG_S	a1, 1*SZREG(sp)
	addi	a0, sp, 16
	mv	a1, t0
	call	__kasan_unpoison_range
	REG_L	a0, 0*SZREG(sp)
	REG_L	a1, 1*SZREG(sp)
	addi	sp, sp, 16
1:
#endif
	REG_L	ra,  0*SZREG(a0)
	REG_L	s0,  2*SZREG(a0)
	REG_L	s1,  3*SZREG(a0)
	REG_L	s2,  4*SZREG(a0)
	REG_L	s3,  5*SZREG(a0)
	REG_L	s4,  6*SZREG(a0)
	REG_L	s5,  7*SZREG(a0)
	REG_L	s6,  8*SZREG(a0)
	REG_L	s7,  9*SZREG(a0)
	REG_L	s8, 10*SZREG(a0)
	REG_L	s9, 11*SZREG(a0)
	REG_L	s10, 12*SZREG(a0)
	REG_L	s11, 13*SZREG(a0)
#ifdef CONFIG_SHADOW_CALL_STACK
	REG_L	gp, 14*SZREG(a0)
#endif
	REG_L	sp,  1*SZREG(a0)

	mv	a0, a1
	bnez	a0, 1f
	li	a0, 1
1:
	ret
SYM_FUNC_END(longjmp)
EXPORT_SYMBOL(longjmp)
