# SD17489 patches for rgh2 XDK kernel 
# can be used on all rgh2 hadware revisons 

	.include "macros.S"
	.globl _start
	_start:

#============================================================================
# branch to smc xell eject check
#============================================================================	
	MAKEPATCH 0X310 
0:
		bl 0x4c20 
9:
#============================================================================
# branch to patch engine apply khv patches
#============================================================================
	MAKEPATCH 0X6b4  
0:
		b 0x4b48
9:
#============================================================================
# 
#============================================================================
	MAKEPATCH 0Xd28
0:
		li %r3, 0
9:
#============================================================================
# 
#============================================================================
	MAKEPATCH 0Xce0
0:
		b 0x8
9:
#============================================================================
# 
#============================================================================
	MAKEPATCH 0Xd7c 
0:
		nop
9:

.ifdef vfuse
#============================================================================
# read vfuses
#============================================================================
	MAKEPATCH 0XA80
0:
	lis %r3, 0x1800
	ori %r3, %r3, 0
	lwz %r4, 0x64(%r3)
	lwz %r5, 0x70(%r3)
	add %r3, %r3, %r4
	add %r4, %r3, %r5
	mr %r3, %r10
	li %r5, 0xc
	bl 0x460
	nop 
9:
.endif
#============================================================================
# boot xell and patching engine plus pci inits
#============================================================================	
	MAKEPATCH 0X4f30
0:
	loc_4E50:				
		li	  %r5, 0x200
		oris	  %r5, %r5, 0x8000
		sldi	  %r5, %r5, 32
		oris	  %r5, %r5, 0xC800
		lbz	  %r4, 0x4D(%r5)
		isync
		cmplwi	  %r4, 0
		beq	  loc_4E88
		lis	  %r3, -0x51FF
		lis	  %r4, -0x8000 
		ori	  %r4, %r4, 0x200	
		sldi	  %r4, %r4, 32
		oris	  %r4, %r4, 0xEA00
		stw	  %r3, 0x101C(%r4)

	loc_4E88:				
		mflr	  %r12
		bl	  sub_50F0
		mtlr	  %r12
		li	  %r8, 0x200
		oris	  %r8, %r8, 0x8000
		sldi	  %r8, %r8, 32
		oris	  %r8, %r8, 0xEA00
		lis	  %r9, 0x400
		lis	  %r10, 0x100
		li	  %r11, 0
		stw	  %r9, 0x1084(%r8)
		stw	  %r10, 0x1080(%r8)
		stw	  %r11, 0x1080(%r8)
		stw	  %r11, 0x1080(%r8)
		stw	  %r11, 0x1080(%r8)
		stw	  %r11, 0x1084(%r8)

	loc_4EC8:				
		lwz	  %r12, 0x1094(%r8)
		and.	  %r12, %r12, %r9
		beq	  loc_4EC8
		stw	  %r9, 0x1094(%r8)
		lwz	  %r12, 0x1090(%r8)
		lwz	  %r3, 0x1090(%r8)
		lwz	  %r3, 0x1090(%r8)
		lwz	  %r3, 0x1090(%r8)
		stw	  %r11, 0x1094(%r8)
		srwi	  %r3, %r12, 24
		cmpwi	  %r3, 1
		bne	  loc_4EC8
		extrwi	  %r3, %r12, 8,8
		cmpwi	  %r3, 0
		beq	  loc_4F1C
		lbz	  %r4, 0x4F(%r5)
		cmplw	  %r3, %r4
		beq	  loc_4F24
		lbz	  %r4, 0x4E(%r5)
		cmplw	  %r3, %r4
		beq	  loc_4F24

	loc_4F1C:				
		lis	  %r3, 0x300
		blr

	loc_4F24:				
		li	  %r7, 0x200
		oris	  %r7, %r7, 0x8000
		sldi	  %r7, %r7, 32
		oris	  %r7, %r7, 6
		ori	  %r7, %r7, 0x1010
		li	  %r3, 0x10
		sldi	  %r3, %r3, 56
		std	  %r3, 0(%r7)
		bl	  sub_4FCC
		li	  %r5, 0x200
		oris	  %r5, %r5, 0x8000
		sldi	  %r5, %r5, 32
		oris	  %r5, %r5, 0xC80f #xell loaction in flash 0xc8b8 for full flash fs
		mr	  %r5, %r5
		lis	  %r6, -0x8000
		sldi	  %r6, %r6, 32
		oris	  %r6, %r6, 0x1C00
		mr	  %r9, %r6
		mtspr	  0x139, %r11
		li	  %r3, 0x11
		sldi	  %r3, %r3, 56
		std	  %r3, 0(%r7)
		lis	  %r4, 1
		mtctr	  %r4

	loc_4F84:				
		lwz	  %r8, 0(%r5)
		stw	  %r8, 0(%r6)
		dcbst	  %r0, %r6
		icbi	  %r0, %r6
		sync
		isync
		addi	  %r6, %r6, 4
		addi	  %r5, %r5, 4
		bdnz	  loc_4F84
		li	  %r3, 0x12
		sldi	  %r3, %r3, 56
		std	  %r3, 0(%r7)
		li	  %r4, 0x30 # '0'
		mfmsr	  %r3
		andc	  %r3, %r3, %r4
		mtsrr1	  %r3
		mtsrr0	  %r9
		rfid

	sub_4FCC:				
		lis	  %r3, -0x8000
		ori %r3, %r3, 0x17c	
		sldi	  %r3, %r3, 32
		oris	  %r3, %r3, 0x400
		ori	  %r3, %r3, 0x50fC
		li	  %r30, 0x200
		oris	  %r30, %r30, 0x8000
		sldi	  %r30, %r30, 32

	loc_4FEC:				
		lwzu	  %r4, 4(%r3)
		cmplwi	  %r4, 0
		beqlr
		lwzu	  %r31, 4(%r3)
		stwbrx	  %r31, %r30, %r4
		li	  %r31, 0xFF
		andc	  %r4, %r4, %r31
		ori	  %r4, %r4, 4
		lwbrx	  %r31, %r30, %r4
		lwzu	  %r29, 4(%r3)
		or	  %r31, %r31, %r29
		stwbrx	  %r31, %r30, %r4
		b	  loc_4FEC
	# End of function sub_4FCC

		.long 0xD0000010
		.long 0xEA000000
		.long 0x00000156
		.long 0xD0008010
		.long 0xE0000000
		.long 0x00000002
		.long 0xD0010010
		.long 0xEC800000
		.long 0x00000002
		.long 0xD0100010
		.long 0xEA001800
		.long 0x00000002
		.long 0xD0108010
		.long 0xEA001200
		.long 0x00000006
		.long 0xD0108014
		.long 0xEA001220
		.long 0x00000006
		.long 0xD0110010
		.long 0xEA001300
		.long 0x00000006
		.long 0xD0110014
		.long 0xEA001320
		.long 0x00000006
		.long 0xD0120010
		.long 0xEA002000
		.long 0x00000156
		.long 0xD0121010
		.long 0xEA003000
		.long 0x00000106
		.long 0xD0128010
		.long 0xEA004000
		.long 0x00000156
		.long 0xD0129010
		.long 0xEA005000
		.long 0x00000106
		.long 0xD0138010
		.long 0xEA001400
		.long 0x00000006
		.long 0xD0140010
		.long 0xEA00C000
		.long 0x00000006
		.long 0xD0140014
		.long 0xC8000000
		.long 0x00000006
		.long 0xD0148010
		.long 0xEA001600
		.long 0x00000006
		.long 0xD0150010
		.long 0xEA001000
		.long 0x00000002
		.long 0x00000000

	sub_50F0:				
		li	  %r3, 0x2E 
		lis	  %r4, -0x8000 
		ori	  %r4, %r4, 0x200	
		sldi	  %r4, %r4, 32
		oris	  %r4, %r4, 0xEA00
		slwi	  %r3, %r3, 24
		stw	  %r3, 0x1014(%r4)

	loc_510C:				
		lwz	  %r3, 0x1018(%r4)
		rlwinm.	  %r3, %r3, 0,6,6
		beq	  loc_510C
		blr
	# End of function sub_50F0

	loc_511C:				
		mfmsr	  %r7
		li	  %r8, 0x10
		andc	  %r8, %r7, %r8
		mtmsrd	  %r8
		bl	  sub_50F0
		li	  %r5, 0x200 
		oris	  %r5, %r5, 0x8000
		sldi	  %r5, %r5, 32
		oris	  %r5, %r5, 0xC800 
		mr	  %r5, %r5
		lwz	  %r6, 0x70(%r5)
		lwz	  %r4, 0x64(%r5)
		cmplwi	  %r6, 0
		bne	  loc_5158
		lis	  %r6, 1

	loc_5158:				
		add	  %r4, %r4, %r6
		addi	  %r4, %r4, 0x5C #location of patches jasper bb 0x5c
		or	  %r3, %r5, %r4
		isync

	loc_5168:				
		mtmsrd	  %r8
		isync
		lwzu	  %r4, 4(%r3)
		cmpwi	  %r4, -1
		beq	  loc_51B0
		addi	  %r4, %r4, -4
		lwzu	  %r6, 4(%r3)
		mtctr	  %r6

	loc_5188:				
		mtmsrd	  %r8
		isync
		lwzu	  %r6, 4(%r3)
		mtmsrd	  %r7
		isync
		stwu	  %r6, 4(%r4)
		dcbst	  %r0, %r4
		icbi	  %r0, %r4
		bdnz	  loc_5188
		b	  loc_5168

	loc_51B0:				
		sync
		isync
		mtmsrd	  %r7
	    rfid
9:
#============================================================================
	.long 0xFFFFFFFF
	.end
#============================================================================
