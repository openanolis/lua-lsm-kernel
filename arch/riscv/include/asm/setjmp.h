/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_SETJMP_H
#define _ASM_RISCV_SETJMP_H

struct label_t {
	/*
	 * ABI return address, stack pointer, and callee-saved registers
	 * (ra, sp, s0-s11).
	 */
	unsigned long regs[14];
};

extern int setjmp(struct label_t *label);
extern void longjmp(struct label_t *label, int val);

#endif /* _ASM_RISCV_SETJMP_H */
