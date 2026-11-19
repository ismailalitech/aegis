/* SPDX-License-Identifier: Apache-2.0 */
	.syntax unified
	.thumb
	.section .text.start
	.global _start
	.thumb_func
_start:
	cpsid i
	movs r0, #0
	msr MSPLIM, r0          @ the interrupted firmware's stack limits would fault our stack (STKOF)
	msr PSPLIM, r0
	ldr r0, =__stack_top
	mov sp, r0
	bl main
	bkpt #0x42
1:	b 1b
