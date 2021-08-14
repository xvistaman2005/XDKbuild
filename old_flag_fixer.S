# ============================================================================
#	HV Flag fixing function
# note: store at empty space
# ============================================================================
	MAKEPATCH 0xB188 
0:
	lhz     %r3, 0x6(%r0)  # load flag byte into r3
	li      %r4, 0x21
	andc    %r3, %r3, %r4 # clear bit
	sth     %r3, 0x6(%r0)      # store new flag
	cmpldi   %r21,  0    # do what we patched
	ba      0x18BC  #CHANGE THIS ADDR TO JUMP BACK
9:
# ============================================================================
#	HV jump to flag fixer
# ============================================================================
	MAKEPATCH 0x18B8 
0:
	ba  0xB188      #(CHANGE THE ADDR TO FLAG FIXING FUNCTIONS ADDR) ^
9:

# 