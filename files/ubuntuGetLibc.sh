#!/bin/sh

CURRENT=`pwd`
URL="$1"

if [ -z "$URL" ]; then
    echo "Usage: $0 <url>"
    exit 1
fi

TMPFILE="$(mktemp -d)"
trap "rm -rf '$TMPFILE'" 0               # EXIT
trap "rm -rf '$TMPFILE'; exit 1" 2       # INT
trap "rm -rf '$TMPFILE'; exit 1" 1 15    # HUP TERM

curl "$URL" -o /$TMPFILE/libc.deb
cd $TMPFILE

ar x libc.deb
tar --use-compress-program=unzstd -xf data.tar.zst
cp ./lib/x86_64-linux-gnu/libc.so.6 ./lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 "$CURRENT"
