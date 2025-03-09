/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_SETJMP_H
#define _ASM_ARM64_SETJMP_H

#include <linux/types.h>

struct label_t {
	/* ABI x19 .. x30 (lr), sp */
	uint64_t regs[13];
};

extern int setjmp(struct label_t *label);
extern void longjmp(struct label_t *label, int val);

#endif /* _ASM_ARM64_SETJMP_H */
