## Problem

Binary: [once](once)

Libc: [libc-2.23.so](libc-2.23.so)

## Solution

In case technique i used is overwrite `top chunk` of `main arena`

```c
void __fastcall main(__int64 a1, char **a2, char **a3)
{
  char buf; // [rsp+10h] [rbp-20h]
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]
  __int64 savedregs; // [rsp+30h] [rbp+0h]

  v4 = __readfsqword(0x28u);
  Init();
  while ( 1 )
  {
    terminal();
    read(0, &buf, 8uLL);
    atoi(&buf);
    switch ( (unsigned int)&savedregs )
    {
      case 1u:
        PUSH();
        break;
      case 2u:
        Read_In_First();
        break;
      case 3u:
        POP();
        break;
      case 4u:
        Heap();
        break;
      case 5u:
        puts("See you next time.");
        exit(0);
        return;
      default:
        puts("Invalid choice");
        printf("%p", &puts);
        break;
    }
  }
}
```
To solved i have any step:

First is `printf("%p", &puts);` . From it i will have libc address information.

Second is `Read_In_First()`

```c
int Read_In_First()
{
  if ( CHECK_READ_FIRST == 1 )
    return -1;
  read_input((char *)LAST_NOTE, 0x20u);
  CHECK_READ_FIRST = 1;
  return puts("success.");
}
```
```
.data:0000555555756020 FIRST_NOTE      db    0                 ; DATA XREF: PUSH+67↑o
.data:0000555555756020                                         ; POP+47↑o ...
.data:0000555555756021                 db    0
.data:0000555555756022                 db    0
.data:0000555555756023                 db    0
.data:0000555555756024                 db    0
.data:0000555555756025                 db    0
.data:0000555555756026                 db    0
.data:0000555555756027                 db    0
.data:0000555555756028                 db    0
.data:0000555555756029                 db    0
.data:000055555575602A                 db    0
.data:000055555575602B                 db    0
.data:000055555575602C                 db    0
.data:000055555575602D                 db    0
.data:000055555575602E                 db    0
.data:000055555575602F                 db    0
.data:0000555555756030                 dq offset FIRST_NOTE
.data:0000555555756038 ; note *LAST_NOTE
.data:0000555555756038 LAST_NOTE       dq offset FIRST_NOTE    ; DATA XREF: PUSH+4D↑r
.data:0000555555756038                                         ; PUSH+5C↑w ...
```
In case i will READ in `LAST_NOTE` first time is `FIRST_NOTE` to overwrite `LAST_NOTE` to `top_chunk_addr - 0x10`

Next i use `PUSH();` to init main arena.

Next i use `POP();` to overwrite `top chunk` to `FIRST_NOTE`
```c
int POP()
{
  if ( CHECK_POP == 1 )
    return -1;
  LAST_NOTE = LAST_NOTE->prev;
  LAST_NOTE->next = (note *)&FIRST_NOTE;
  CHECK_POP = 1;
  return puts("success.");
}
```
Before overwrite top chunk i will use `Heap();` to overwrite `LAST_NOTE` and `CHECK_READ_FIRST` and to do any things.
Please see more in my solution: [exploit.py](exploit.py)