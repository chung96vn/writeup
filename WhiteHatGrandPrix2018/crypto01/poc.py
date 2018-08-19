from pwn import *

stdin = process.PTY
stdout = process.PTY
key = "Hi. I am Mr. ChatBot. Who are you?"


r = process(['./chatclient', '43.224.35.245', '3425'], stdout=stdout, stdin=stdin)

r.recvuntil('Your id: ')
r.sendline('manh')
r.recvuntil('Input your key: ')
r.sendline('0x7f6949db22eeada0')
log.info(r.recvline())
r.sendline("super")
r.recvuntil('Enter supper mode!\n')

ar = ""
i = 1
while True:
    r.sendline("a")
    tmp = r.recvline()
    log.info(tmp.encode('hex'))
    if len(tmp) == 35:
        ar = tmp
        break

key_1 = "How are you?"
rs = ""
for i in range(len(key_1)):
    k = ord(key_1[i])^ord(key[i])^ord(ar[i])
    rs += chr(k)

ar_1 = ""
for i in range(10):
    r.sendline(rs)
    tmp = r.recvline()
    log.info(tmp.encode('hex'))
    if len(tmp) >= 55:
        ar_1 = tmp
        break
        
r.sendline("secret")
tmp = r.recvline()
log.info(tmp.encode('hex'))
        
        
secret = "secret"
rs = ""
for i in range(len(secret)):
    k = ord(secret[i])^ord(key[i])^ord(ar[i])
    rs += chr(k)

log.info("secret: %s" %rs.encode('hex'))
r.sendline(rs)
tmp = r.recvline()
log.info(ar_1.encode('hex')) # Encrypt of "I'm a bot, I don't feel much of anything, how about you?"
log.info("Secret: %s" %tmp.encode('hex')) # Encrypt of FLAG
r.interactive()
