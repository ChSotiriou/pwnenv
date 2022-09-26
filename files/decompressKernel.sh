#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Usage: $0 <initramfs.cpio.gz>"
    exit -1
fi

# Decompress a .cpio.gz packed file system
mkdir initramfs
pushd . && pushd initramfs
cp "../$1" .
gzip -dc "$1" | cpio -idm &>/dev/null && rm "$1"
popd
