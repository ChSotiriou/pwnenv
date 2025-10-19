#!/bin/sh

set -e

# ensure decompressed is named `root`
# ensure filesystem (cpio file) is named debugfs.cpio

exploit/compile.sh "`pwd`/exploit"
cp exploit/xpl initramfs
cd initramfs; find . -print0 | cpio -o --null --format=newc | gzip -2 > ../debugfs.cpio.gz
cd ..

# start tmux windows with gdb
if [ "$1" = "GDB" ]; then
    CMD='sleep 2 && gdb-pwndbg -p `pidof qemu-system-x86_64` -x script.gdb ./qemu-system-x86_64'
    tmux split -v "$CMD"


    # copy from original run.sh
else
    # copy from original run.sh
fi
