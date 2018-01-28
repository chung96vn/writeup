from pwn import *
from hashlib import md5
from time import ctime
from base64 import b64decode, b64encode

def xor(dest, src):
    if len(dest) == 0:
        return src
    elif len(src) == 0:
        return dest
    elif len(dest) >= len(src):
        return ''.join(chr(ord(dest[i])^ord(src[i])) for i in range(len(src)))
    else:
        return ''.join(chr(ord(dest[i])^ord(src[i])) for i in range(len(dest)))


def Register(name, username):
    r.recvuntil("Your choice: ")
    r.sendline("1")
    r.recvuntil("Name: ")
    r.sendline(name)
    r.recvuntil("Username: ")
    r.sendline(username)
    raw = "CNVService" + "*" + "user="+ username + "*" + ctime() + "*" + "xxxxxxxxxx" #please set your time is same server maybe UTC+000
    r.recvuntil("Cookie: ")
    return r.recvline(), raw

def Login(cookie):
    r.recvuntil("Your choice: ")
    r.sendline("2")
    r.recvuntil("Cookie: ")
    r.sendline(cookie)
    r.recvuntil("This is flag: ")
    return r.recvline()

r = remote("cnvservice.acebear.site", 1337)

md5_hidden = "0c6734e3fc02a0d0a119f1cf2a567fc1" # please try it with some thing to get md5(__HIDDEN__)

def main():
    h = md5_hidden.decode('hex')
    fakerawcookie = "CNVService*user=root*"+"a"*15
    cookie, rawcookie = Register("a"*16, "a"*15)
    cookie = b64decode(cookie)
    iv = md5(cookie[32:48]).digest()
    iv = xor(iv, rawcookie[32:48])
    iv = xor(iv, fakerawcookie[:16])
    name = xor(iv, h)
    username = fakerawcookie[16:32]
    username = xor(username, md5(cookie[48:64]).digest())
    username = xor(username, md5(cookie[16:32]).digest())
    cookie2 , rawcookie2 = Register(name, username)
    cookie2 = b64decode(cookie2)
    fakecookie = cookie[:32]+cookie2[32:]
    fakecookie = b64encode(fakecookie)
    log.info(fakecookie)
    log.info("Flag is: %s" %Login(fakecookie))
if __name__ == '__main__':
    main()
