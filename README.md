# XDKbuild v0.05b
By Xvistaman2005

This will make you a more or less stock XDK flash for your retail console. The patches included in this release are the minimum required for an XDK kernel to run on a retail console.  All 16MB images require the hard drive file system located in the 17489-xdk folder. It should be installed in the root of the HDD in a folder labeled 17489.

## Disclaimer:

This is BETA software, you are using this at your own risk. Make sure that you fully understand what it does before flashing anything, and always keep a backup of your console's image before using.

## Features:

- Anything that works on an XDK should work on this flash.
- Bootloader patches include disable signature checking on both the SC and SD boot loaders they need not be signed.
- Virtual eFuses for the entire boot process from boot loaders to kernel
- Full devkit boot loader chain using CBA, SB, SC, SD, SE
- Shadowbooting is possible although not the focus of the project

For shadow booting the core patch set for the kernel is required along with the pre patched SB for retail consoles. Thees are in shadow boot folder in the release any shadow boot image builder should be able to build a working image if patches are applied properly also we recommend you use HDD file system for shadow booting as well.

## Credits:

cOz -  Bootloader reverse engineering, and lots of the patch code derived for use in this project. You have always been there for me man, thanks XD!

Visual Studio - Python and patch library release, some patches were ported from his lib

Octal450 - J-Runner integration, creating compatible timing files, and flash testing, nice work man

JustAnyone, Pro-Moddz (Jimmy Brown), Jenkins - beta testing

## How to Install:

1) Open J-Runner with Extras

2) Load your NAND dump

3) Enter your CPU key

4) Select 17489 dashboard

5) Select Glitch2m or DEVGL, and XDKbuild

6) Click Create XeBuild Image

7) When XDKbuild finishes, the image is ready

8) RGH only: Flash a compatible timing file, they are located in J-Runner with Extras\common\XDKbuild-Timings.rar

9) 16MB only: Copy the J-Runner with Extras\xeBuild\17489\17489-fs to your hard drive root, named just 17489

10) Enjoy
