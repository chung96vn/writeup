from pwn import *

#r = process(['python3', './easy_block.py'])
r = remote('47.90.125.237', 9999)
bs = 16

def register(name):
	r.recvuntil('Please [r]egister or [l]ogin :>>')
	r.sendline('r')
	r.recvuntil('your name is:>>')
	r.sendline(name)
	r.recvuntil("Here is your cookie:\n")
	return r.recvline().strip()
	
def login(cookie):
	r.recvuntil('Please [r]egister or [l]ogin :>>')
	r.sendline('l')
	r.recvuntil('your cookie:>>')
	r.sendline(cookie)
	
def gethash(data):
	r.recvuntil('Please [r]egister or [l]ogin :>>')
	r.sendline('c')
	r.recvuntil('your username:>>')
	r.sendline(data)
	return r.recvline().strip()

def xor(st1, st2):
	rs = ''
	for i in range(len(st1)):
		rs += chr(ord(st1[i]) ^ ord(st2[i]))
	return rs

cookie = register("a"*11) # "a"*11+"user"
cookie = cookie.decode('hex')
iv = cookie[:bs]
mac = cookie[bs:4 * bs]
ciphertext = cookie[4 * bs:]
user = "a"*11+"user"
admin = "a"*10+"admin"

new_iv = xor(xor(user+"\x01", admin+"\x01"), iv)
log.info("iv: %s" %new_iv.encode('hex'))
user_hash = gethash(user).decode('hex')
admin_hash = gethash(admin).decode('hex')
log.info("user_hash: %s" %user_hash.encode('hex'))
log.info("admin_hash: %s" %admin_hash.encode('hex'))


fake_block_2 = xor(xor("\x10"*16, mac[16:32]), admin_hash[17:32]+"\x01")

fake_mac = admin_hash[1:17] + fake_block_2 + mac[-16:]

fake_cookie = new_iv + fake_mac + ciphertext

login(fake_cookie.encode('hex'))
print r.recvuntil('the suppposed first 136 bits is:>>')
tmp = r.recvline().split("'")
print tmp
tmp = tmp[-2]
enchash = tmp[2:].decode('hex')

log.info(enchash.encode('hex'))

fake_mac = enchash + fake_block_2 + mac[-16:]

cookie = new_iv + fake_mac + ciphertext

login(cookie.encode('hex'))

r.interactive()