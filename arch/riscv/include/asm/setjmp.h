/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_SETJMP_H
#define _ASM_RISCV_SETJMP_H

struct label_t {
	/*
	 * Register slots in the order saved by setjmp and restored by
	 * longjmp in arch/riscv/lib/setjmp.S: return address (ra),
	 * stack pointer (sp), then the callee-saved registers (s0-s11).
	 */
	unsigned long regs[14];
#ifdef CONFIG_SHADOW_CALL_STACK
	unsigned long scs_sp;
#endif
};

extern int setjmp(struct label_t *label);
extern void longjmp(struct label_t *label, int val);

#endif /* _ASM_RISCV_SETJMP_H */
