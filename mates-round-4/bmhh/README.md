Mở binary bằng IDA :v
```c
if ( GET_FLAG )
    LODWORD(v0) = system("cat flag.txt");
else
    LODWORD(v0) = puts("MASTERCTF{d4y_kh0ng_ph41_l4_fl4g_d4u}");
```
Muốn có flag thì phải biến GET_FLAG thành `!=0` có vẻ khó vì chẳng thấy nó được dùng ở đâu cả :v
Nhưng mà mình lại thấy một chỗ có thể tận dụng được ở trong chính Happy Ending :v
```c
int Happy()
{
  __int64 v0; // rax
  int v2; // [rsp+Ch] [rbp-14h]
  __int64 Male; // [rsp+10h] [rbp-10h]
  __int64 Partner; // [rsp+18h] [rbp-8h]

  v2 = ChonPlayer();
  if ( v2 == -1 )
  {
    LODWORD(v0) = puts("Nguoi choi khong ton tai!");
  }
  else if ( SEX_PLAYER[v2] == 1 )
  {
    Male = LIST_PLAYER[v2];
    v0 = *(_QWORD *)(Male + 320);
    if ( v0 )
    {
      Partner = *(_QWORD *)(Male + 0x140);
      printf("%s ban co dong y lay %s khong?\n1. Dong y\n2. Khong \n> ", *(_QWORD *)(Male + 0x140), Male);
      v0 = Choice();
      if ( v0 == 1 )
      {
        *(_BYTE *)(Male + 0x138) = 1;
        *(_BYTE *)(Partner + 0x238) = 1;
        puts("Chuc hai ban hanh phuc!\nDay la phan thuong danh cho hai ban");
        if ( GET_FLAG )
          LODWORD(v0) = system("cat flag.txt");
        else
          LODWORD(v0) = puts("MASTERCTF{d4y_kh0ng_ph41_l4_fl4g_d4u}");
      }
    }
  }
  else
  {
    LODWORD(v0) = puts("Hay nho! Cau hon la viec cua dan ong!");
  }
  return v0;
}
```
`*(_BYTE *)(Partner + 0x238) = 1;` và `Partner = *(_QWORD *)(Male + 0x140);` như vậy nếu control được `Partner` là sẽ giải quyết được bài toán.
Nhận thấy lúc Create Player thì chương trình không xóa bộ nhớ đệm nên việc vào ra `Male`với vùng nhớ `*(_QWORD *)(Male + 0x140);` đã tồn tại là hoàn toàn có thể?
Từ đó ta có [solution.py](solution.py)