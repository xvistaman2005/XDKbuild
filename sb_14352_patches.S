.include "macros.S"
#.globl _start
#_start:

.ifdef vfuse
#============================================================================
# extend the ldr size
#============================================================================
   	MAKEPATCH 0xc
0:
	.long 0x4110
9:
.endif

.ifdef vfuse
#============================================================================
#   Branch To Header Fixer
#============================================================================
	MAKEPATCH 0x3d0
0:
	b 0x3d18
9:
.endif

.ifdef vfuse
#============================================================================
#	Vfuses patch #1 credits to cOz
#============================================================================
	   	MAKEPATCH 0x12f4
0:
	ld %r3, 0x258(%r29)	#Flashaddr in SB top
	lwz %r4, 0x64(%r3)	#addr to patch slot	
	lwz %r5, 0x70(%r3)	#patch slot size
	add %r3, %r3, %r4
	add %r4, %r3, %r5
	mr %r3, %r10	
	li %r5, 0xc	#number of fuse rows
	bl 0xb20
	ld %r31, 0xa0(%r1)
	rldicr %r11, %r31, 0, 1
	cmpldi %cr6, %r11, 0
	nop 

9:
.endif

#============================================================================
# patch out the fuse row 2 check post 0x9b why? vfuses dont fix ?
#============================================================================
	  	MAKEPATCH 0x1398
0:
	b 0x14
9:

.ifdef sboot
#============================================================================
# patch out the fuse row 4 check post 0x9e 
#============================================================================
	  	MAKEPATCH 0x13d8
0:
	b 0x14
9:
.endif

.ifdef sboot
#============================================================================
# patch out the fuse row 5 check post 0x9f 
#============================================================================
	  	MAKEPATCH 0x140c
0:
	b 0x14
9:
.endif

.ifdef sboot
#============================================================================
# patch out the fuse row 6 check post 0x9f 
#============================================================================
	  	MAKEPATCH 0x14c8
0:
	b 0x14
9:
.endif

.ifdef vfuse
#============================================================================
#	Vfuses patch #2 credits to cOz
#============================================================================
	   	MAKEPATCH 0x16b8
0:
	ld %r3, 0x258(%r26)	#Flashaddr in SB top
	lwz %r4, 0x64(%r3)	#addr to patch slot	
	lwz %r5, 0x70(%r3)	#patch slot size
	add %r3, %r3, %r4
	add %r4, %r3, %r5
	mr %r3, %r10
	li %r5, 0xc
	bl 0x75c
9:
.endif

#============================================================================
#  patch out the signature check on the SC bl
#============================================================================
   	MAKEPATCH 0x1b18
0:
	b 0x14
9:

#============================================================================
#  patch out the signature check on the SD bl
#============================================================================
   	MAKEPATCH 0x1d70
0:
	b 0x14
9:

.ifdef vfuse
#============================================================================
#  HdrFixer
#============================================================================
   	MAKEPATCH 0x40e0
	.set HdrFixer, PatchAddr
0:
	.long 0x53423810 #sb header magic
	.long 0x00000000 #sb header flags set to 0x0 on boot same as would be on devkit
		
	li %r9, 0x40e0 #adress of new hdr
	addis %r9, %r9, 1 #make it addr in soc ram 0x140e0
	addis %r10, %r10, 1 #dest addr in soc ram 0x10000
	ld %r8, 0(%r9)
	std %r8, 0(%r10)
	li %r8, 0 #reg clean up r8 r9 r10 so it never happend
	li %r9, 0
	li %r10, 0
	lis %r3, 0x100 #first inst in sb
	b -0x3D38 #branch back to next inst	
9:
.endif
#============================================================================
	.long 0xFFFFFFFF
	.end
#============================================================================



