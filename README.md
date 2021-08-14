# XDKbuild
Sources used in making XDKbuild Patches and Tool

XDKbuild v0.05b

This is BETA software you are using this at your own risk make sure you fully understand what it does before flashing any thing always have a backup of your consoles image before using.

This will make you a more or less stock XDK flash for your retail console. The patches included in this release are the minimum required for an XDK kernel to run on a retail console.  All 16  megabytes images require the hard drive file system located in the 17489 folder. It should be installed in the root of the HDD in a folder labeled 17489. 


Features:

Any thing that works on an XDK should work on this flash.

Boot loader patches include disable signature checking on both the SC and SD boot loaders they need not be signed.

Virtual fuses for the entire boot process from boot loaders to kernel

Full devkit boot loader chain using CBA, SB, SC, SD, SE

Shadow booting is possible although not the focus of the project


For shadow booting the core patch set for the kernel is required along with the pre patched SB for retail consoles. 



Credits

cOz reverse engineering on bootldrs and lots of the patch code derived for use in this project you have always been there for me man thnx XD.

Tydye81 for Rgloader and XDK kernel reversing XD

Visual studio for awesome python and patch library release some patches where ported from his lib.

Octal450 for j runner integration and flash testing nice work man. 

justanyone, promodz (jimmy brown), jenkins.xui beta testers.


How to install ? 

1. Open Jrunner

2. Select your orginal dump

3. Enter your cpu key

4. Select Dash 17489

5. Check XDKbuild/Devgl for 0 fuse

6. Build xebuild image 

7. You should see XDKbuild run in the Jr log window

8. Flash the corret timming to your glitch chip (not needed for 0 fuse)

9. If not using a 4g corona, BB jasper or BB trinity install 17489-fs folder in xebuild kernel folder to HDD root on the xbox remove the -fs from the folder name simply name it 17489

10. Enjoy
