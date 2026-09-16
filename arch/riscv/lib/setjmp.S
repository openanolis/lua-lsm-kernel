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

	li	a0, 0
	ret
SYM_FUNC_END(setjmp)
EXPORT_SYMBOL(setjmp)

/*
 * void longjmp(struct label_t *label, int val);
 */
SYM_FUNC_START(longjmp)
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
	REG_L	sp,  1*SZREG(a0)

	mv	a0, a1
	bnez	a0, 1f
	li	a0, 1
1:
	ret
SYM_FUNC_END(longjmp)
EXPORT_SYMBOL(longjmp)
