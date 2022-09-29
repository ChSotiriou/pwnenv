#!/usr/bin/python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-v']

binary = '[binary]'
elf = context.binary = ELF(binary)
rop = ROP(elf)

ssh_en = False
if args.R:
	host = args.HOST or ''
	port = args.PORT or 0

	if ssh_en:
		user = ''
		password = ''
		r = ssh(user=user, host=host, port=port, password=password)


def start():
	if args.R:
		if not ssh_en: return remote(host, port)
		else: return r.process(binary, cwd='')

	else:
		gs = '''
		br _start
		c
		init-pwndbg
		c
		'''
		if args.GDB: return gdb.debug(elf.path, gs)
		else: return process(elf.path)

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

def log_addr(name, addr):
	log.info('{}: 0x{:x}'.format(name, addr))

io = start()

sl = lambda x : io.sendline(x.encode() if type(x) == str else x)
sla = lambda x, y : io.sendlineafter(x.encode() if type(x) == str else x, y.encode() if type(y) == str else y)
se = lambda x : io.send(x.encode() if type(x) == str else x)
sa = lambda x, y : io.sendafter(x.encode() if type(x) == str else x, y.encode() if type(y) == str else y)
ru = lambda x : io.recvuntil(x.encode() if type(x) == str else x)
rl = lambda : io.recvline()
cl = lambda : io.clean()
i = lambda : io.interactive()
uu32 = lambda x : u32(x.ljust(4. b'\x00'))
uu64 = lambda x : u64(x.ljust(8, b'\x00'))

i()