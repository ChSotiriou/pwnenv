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
    tmux split -v -p 50 "gdb-pwndbg -x script.gdb"

    qemu-system-x86_64 \
        -m 64M \
        -nographic \
        -kernel bzImage \
        -append "console=ttyS0 oops=panic panic=-1 nopti nokaslr" \
        -no-reboot \
        -cpu qemu64 \
        -smp 1 \
        -monitor /dev/null \
        -initrd ./debugfs.cpio.gz \
        -net nic,model=virtio \
        -net user \
        -s -S
else
    qemu-system-x86_64 \
        -m 64M \
        -nographic \
        -kernel bzImage \
        -append "console=ttyS0 oops=panic panic=-1 nopti nokaslr" \
        -no-reboot \
        -cpu qemu64 \
        -smp 1 \
        -monitor /dev/null \
        -initrd ./debugfs.cpio.gz \
        -net nic,model=virtio \
        -net user
fi
