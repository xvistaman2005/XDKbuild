
# ============================================================================
#	Set SystemRoot to HDD
# note: empty space
# ============================================================================
	.set Paddr, 0x1c1850
	.set strLen,  (2f - 1f)
	.set RootPatch, (Paddr + 0x80000000)	
		
	MAKEPATCH 0x1C1850
0:
	.word strLen-2  #//length
	.word strLen-1  #//maxlength
	
	.long (RootPatch+8) #//ptr to string
	
1:
	.string "\\Device\\Harddisk0\\Partition1\\17489\0"
2:
	.align 2
9:



	MAKEPATCH 0x8102C 
0:
	nop              #  nop out the hardware flags check
	lis   %r11, RootPatch@h
	ori  %r4, %r11, RootPatch@l
9:



# ============================================================================
#	System root panic function 
# ============================================================================

.set  SysRootRecovery,  0x81050 
.set  SysRootAddr, 0x81090

	MAKEPATCH 0x81090
0:
	b -0x40
	#b (SysRootAddr - SysRootRecovery)
9:

	MAKEPATCH 0x810B0
0:
	b -0x60
	#b (SysRootAddr+0x20 - SysRootRecovery)
9:

	MAKEPATCH 0x810DC
0:
	b -0x8C
	#b (SysRootAddr+0x4C - SysRootRecovery)
9:

	MAKEPATCH 0x81158
0:
	b -0x108
	#b (SysRootAddr+0x68 - SysRootRecovery)
9:



