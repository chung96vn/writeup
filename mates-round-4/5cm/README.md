Mở với IDA ta có:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setbuf(stdout, 0LL);
  signal(14, ALARMhandler);
  alarm(0);
  read(0, &shellcode, 5uLL);
  ((void (__fastcall *)(_QWORD, void *))shellcode)(0LL, &shellcode);
  myspecialexitfunction();
  return 0;
}
```
Oh thế là nhập shellcode và chạy thôi. Lên google kéo cái shell x64 về chạy như thật mà méo để ý là chỉ có 5 byte :v
Thế là break ở call shellcode xem sao?
```
 RAX  0x0
 RBX  0x0
*RCX  0x7ffff7b04260 (__read_nocancel+7) ◂— cmp    rax, -0xfff
*RDX  0x601080 (shellcode) ◂— 0xa61 /* 'a\n' */
 RDI  0x0
*RSI  0x601080 (shellcode) ◂— 0xa61 /* 'a\n' */
```
Thế là chỉ cần 1 lệnh syscall là có thể read thêm thỏa thích vào shellcode rồi.
Mà run xong con shellcode google ngu quá nên thôi đánh đi code lại :v
Thế là từ đó ta có [solution.py](solution.py)