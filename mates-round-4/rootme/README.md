Bài này mình thấy thiên một chút về cờ ríp tô

```c
char *regroot()
{
  acc *v0; // rax

  root = (acc *)malloc(0x40uLL);
  v0 = root;
  *(_DWORD *)root->username = 'toor';
  v0->username[4] = 0;
  return strncpy(root->password, adminpassword, 0x20uLL);
}
```
Mình sử dụng lỗi `out bof bound` để `free` account root đi sau đó sử dụng lại

```c
unsigned __int64 del()
{
  int index; // eax
  __int16 buf; // [rsp+0h] [rbp-10h]
  char v3; // [rsp+2h] [rbp-Eh]
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("User's ID: ");
  buf = 0;
  v3 = 0;
  read(0, &buf, 2uLL);
  if ( userlist[atoi((const char *)&buf)] )
  {
    index = atoi((const char *)&buf);
    free(userlist[index]);
    userlist[atoi((const char *)&buf)] = 0LL;
  }
  else
  {
    puts("Wrong ID!");
  }
  return __readfsqword(0x28u) ^ v4;
}
```
Sử dụng lại sẽ không bị xóa bộ nhớ đệm nên `password` vẫn được lưu trong đó nên mình có thể ghi đè 1 byte đầu bằng cách brute force byte đó cho đúng với password root hoặc ghi đè nhiều hơn để brute force tìm password nếu rảnh.
Do quá rảnh nên mình đã `brute force` cả `password` cho nó ngầu :))

[solution.py](solution.py)