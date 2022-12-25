#!/bin/sh

# ensure decompressed is named `root`
# ensure filesystem (cpio file) is named debugfs.cpio

exploit/compile.sh "`pwd`/exploit"
cp exploit/xpl initramfs
cd initramfs; find . -print0 | cpio -o --null --format=newc | gzip -2 > ../debugfs.cpio.gz
cd ..

# start tmux windows with gdb
tmux split -v -p 50 "gdb-pwndbg -x script.gdb"

# replace with challenge run command
qemu-system-x86_64 \
    -kernel ./bzImage \
    -initrd ./debugfs.cpio.gz \
    -monitor /dev/null \
    -nographic -append "console=ttyS0" \
    -s -S
