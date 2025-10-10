#!/usr/bin/env python
from pwn import *

context.terminal = ['tmux', 'splitw', '-v']
context.arch = "i386"

binary = '[binary]'
elf = context.binary = ELF(binary)

ssh_en = False
if args.R:
    host = args.HOST or ''
    port = args.PORT or 0

def start() -> tube:
    if args.R:
        return remote(host, port)
    else:
        gs = '''
        init-pwndbg
        c
        '''
        if args.GDB: return gdb.debug(elf.path, gs, api=True)
        else: return process(elf.path)

# Safelinking functions [https://github.com/mdulin2/mangle/]
def protect_ptr(target, addr):
	return (addr >> 12) ^ target

def reveal_ptr(mangled_ptr, addr):
	return protect_ptr(mangled_ptr, addr)

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

def log_addr(name, addr):
    log.info('{}: 0x{:x}'.format(name, addr))

io = start()

toBytes = lambda x: x.encode() if type(x) == str else x
sl = lambda x, **kw : io.sendline(toBytes(x), **kw)
sla = lambda x, y, **kw : io.sendlineafter(toBytes(x), toBytes(y), **kw)
se = lambda x, **kw : io.send(toBytes(x), **kw)
sa = lambda x, y, **kw : io.sendafter(toBytes(x), toBytes(y), **kw)
ru = lambda x, **kw : io.recvuntil(toBytes(x))
rl = lambda **kw : io.recvline(**kw)
cl = lambda **kw : io.clean(**kw)
uu32 = lambda x : u32(x.ljust(4, b'\x00'))
uu64 = lambda x : u64(x.ljust(8, b'\x00'))

io.interactive()
