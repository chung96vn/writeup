Nhín source code thì lỗi quá rõ rồi.
`Formatstring`
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char format; // [rsp+10h] [rbp-90h]
  unsigned __int64 v5; // [rsp+98h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setbuf(_bss_start, 0LL);
  signal(14, (__sighandler_t)ALARMhandler);
  alarm(0u);
  __isoc99_scanf("%32s", &format);
  printf(&format, &format, argv);
  myspecialexitfunction();
  return 0;
}
```
Tuy nhiên sau khi thực hiện hàm `printf` chương trình sẽ `exit` băng `syscall_exit` vậy làm sao để có thể bỏ qua vấn đề này.
Tôi nghĩ ngay đến việc sử dụng signal time out.
```c
void ALARMhandler()
{
  puts("\nTIME OUT BABY!\n");
  myspecialexitfunction();
}
```
Hàm này có sử dụng lệnh `puts` đc dynamic linker nên có thể đè GOT của nó để có thể trigger call đến
```c
int myinvisiblebackdoor()
{
  return system("/bin/cat flag");
}
```
Mọi chuyện cũng không hề đơn giản khi chương trình chỉ cho read vào `32 byte` một con số khá nhỏ. Thật may vì hàm puts chưa được dùng tới trước đó nên GOT của nó sẽ chứa một giá trị gần với giá trị của `myinvisiblebackdoor()`

Từ đó chỉ việc đè 2 byte cuối của `puts GOT` vào để cho chương trình `time out` là có thể trigger đc `cat flag` rồi.

[solution.py](solution.py)