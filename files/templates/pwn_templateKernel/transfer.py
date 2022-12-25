#!/usr/bin/env python3

# Source: https://pawnyable.cafe/linux-kernel/introduction/compile-and-transfer.html

from ptrlib import *
import time
import base64
import os


def run(cmd):
    sock.sendlineafter("$ ", cmd)
    sock.recvline()


with open("./initramfs/xpl", "rb") as f:
    payload = bytes2str(base64.b64encode(f.read()))

host = ""
port = 0
sock = Socket(host, port)

run("cd /tmp")

logger.info("Uploading...")
for i in range(0, len(payload), 512):
    print(f"Uploading... {i:x} / {len(payload):x}")
    run('echo "{}" >> b64exp'.format(payload[i : i + 512]))
run("base64 -d b64exp > xpl")
run("rm b64exp")
run("chmod +x xpl")

sock.interactive()
