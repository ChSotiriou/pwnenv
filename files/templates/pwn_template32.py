#!/usr/bin/python3
from pwn import *

context.terminal = ['tmux', 'splitw', '-v']
context.arch = 'i386'

binary = './rop'
elf = ELF(binary)

ssh_en = False
if args.R:
	host = '2019shell1.picoctf.com'
	port = 22

	if ssh_en:
		user = ''
		password = ''
		r = ssh(user=user, host=host, port=port, password=password)

def start():
	if args.R:
		if not ssh_en: return remote(host, port)
		else: return r.process(binary, cwd='/problems/leap-frog_1_2944cde4843abb6dfd6afa31b00c703c')

	else:
		gs = '''
        br _start
        c
		init-pwndbg
		c
		'''
		if args.GDB: return gdb.debug(elf.path, gs)
		else: return process(elf.path)

def log_addr(name, addr):
    log.info('{}: 0x{:x}'.format(name, addr))


io = start()

sl = lambda x : io.sendline(x)
sla = lambda x, y : io.sendlineafter(x, y)
se = lambda x : io.send(x)
sa = lambda x, y : io.sendafter(x, y)
ru = lambda x : io.recvuntil(x)
rl = lambda : io.recvline()
cl = lambda : io.clean()
uu32 = lambda x : u32(x.ljust(4, b'\x00'))


io.interactive()
