/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/export.h>
#include <linux/linkage.h>

/*
 * int setjmp(struct label_t *label);
 */
SYM_FUNC_START(setjmp)
	movl		4(%esp), %eax
	movl		%ebx,   (%eax)		/* save ebx */
	movl		%esp,  4(%eax)		/* save esp */
	movl		%ebp,  8(%eax)		/* save ebp */
	movl		%esi, 12(%eax)		/* save esi */
	movl		%edi, 16(%eax)		/* save edi */
	movl		(%esp), %edx		/* get retaddr */
	movl		%edx, 20(%eax)		/* save eip */
	xorl		%eax, %eax		/* return 0 */
	RET
SYM_FUNC_END(setjmp)
EXPORT_SYMBOL(setjmp)

/*
 * void longjmp(struct label_t *label, int val);
 */
SYM_FUNC_START(longjmp)
	movl		4(%esp), %eax
	movl		8(%esp), %edx
	movl		  (%eax), %ebx		/* restore ebx */
	movl		 4(%eax), %esp		/* restore esp */
	movl		 8(%eax), %ebp		/* restore ebp */
	movl		12(%eax), %esi		/* restore esi */
	movl		16(%eax), %edi		/* restore edi */
	movl		20(%eax), %eax		/* get retaddr */
	movl		%eax, (%esp)		/* put in return frame */
	movl		%edx, %eax		/* return val */
	RET
SYM_FUNC_END(longjmp)
EXPORT_SYMBOL(longjmp)
