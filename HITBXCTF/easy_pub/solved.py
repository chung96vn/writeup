from pwn import *
from gmpy2 import invert

def register(name):
	r.recvuntil('Please [r]egister or [l]ogin :>>')
	r.sendline('r')
	r.recvuntil('please input your username:>>')
	r.sendline(name)
	
def login(ticket, sig_0, sig_1):
	r.recvuntil('Please [r]egister or [l]ogin :>>')
	r.sendline('l')
	r.recvuntil('ticket:>>')
	r.sendline(str(ticket))
	r.recvuntil('sig[0]')
	r.sendline(str(sig_0))
	r.recvuntil('sig[1]')
	r.sendline(str(sig_1))

#r = process(['python3', './easy_pub.py'])

r = remote('47.75.53.178', 9999)
r.recvline()
e = int(r.recvline())
n = int(r.recvline())
p = int(r.recvline())
g = int(r.recvline())
y = int(r.recvline())
log.info("e: %s" %e)
log.info("n: %s" %n)
log.info("p: %s" %p)
log.info("g: %s" %g)
log.info("y: %s" %y)

sig = [0,0]
register("chung")
ticket = int(r.recvline())
log.info("ticket: %s" %ticket)
sig[0] = int(r.recvline())
sig[1] = int(r.recvline())
log.info("sig[0]: %s" %sig[0])
log.info("sig[1]: %s" %sig[1])

c = ticket
c = (c * pow(invert(2, n), e, n)) % n
login(c, sig[0], sig[1])
r.recvuntil('Welcome!')
tmp = "k = "+r.recvline()[:-1]
exec(tmp)
k = int(k.encode('hex'), 16)*2
log.info(hex(k))
log.info(hex(k)[2:].decode('hex'))
r.interactive()