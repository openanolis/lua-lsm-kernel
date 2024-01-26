/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SETJMP_H
#define _ASM_X86_SETJMP_H

#include <linux/types.h>

struct label_t {
#ifdef CONFIG_X86_32
	/* ABI (ebx, esp, ebp, esi, edi) and eip. */
	uint32_t regs[6];
#else
	/* ABI (rbx, rsp, rbp, r12-r15) and rip. */
	uint64_t regs[8];
#endif
};

extern int setjmp(struct label_t *label);
extern void longjmp(struct label_t *label, int val);

#endif /* _ASM_X86_SETJMP_H */
