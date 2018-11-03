#SVATTT2018{W3lc0m3_t0_th3_TEA_P4rtY}

from pwn import *


request = 'Hi, my name is '+ name +', and my register code is aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
FLAG = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

a = request.format(name = "aaa", code = FLAG)

r = remote("171.244.141.82", 12345)

r.recvuntil("2. Log in\n")
r.sendline("1")
r.recvuntil("Your name: ")
r.sendline("a"*100)
r.recvuntil("Here is your credential: ")
cip = r.recvline().strip()
log.info(cip)
cip = cip.decode('hex')
newcip = cip[:16]+cip[-40:]+cip[48:]
assert(len(newcip)%8==0)
log.info(newcip.encode('hex'))
r.recvuntil("2. Log in\n")
r.sendline("2")
r.recvuntil("Who are you? ")
r.sendline(newcip.encode('hex'))
r.interactive()
