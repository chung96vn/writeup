# one_shot
> Ban đầu cũng ko định viết nhưng sau nghĩ lại, thấy nên viết một cái gì đó cho ngày thi vừa rồi vì dù sao cũng cảm thấy hạnh phúc và vui vẻ khi được hòa mình vào với CTF. Cảm ơn MeePwn Team đã mang đến một giải hay và đầy cảm xúc.

Tên đề bài là one shot (Thông thường thì 1 shot loại bèo cũng đôi ba trăm nghìn rồi) mà bài này cuối cùng cũng còn đc `480`.

Description cho chúng ta những thứ sau:
`nc 178.128.87.12 31338` và [binary](one_shot)

Source code thì cũng khá đơn giản, chỉ bảo gồm như sau:

```C
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  alarm(0);
  HANDLE();
  return 0LL;
}
```
```C
_BOOL8 HANDLE()
{
  _BOOL8 result; // rax
  char buf[128]; // [rsp+20h] [rbp-80h]

  read(0, buf, 0x234uLL);
  close(0);
  close(1);
  close(2);
  result = Check(buf);
  if ( !(_DWORD)result )
    exit(1);
  return result;
}
```
```C
_BOOL8 __fastcall Check(char *a1)
{
  char *i; // rsi
  signed int v2; // eax
  signed int v4; // [rsp+0h] [rbp-24h]
  char v5[4]; // [rsp+4h] [rbp-20h]
  char v6[4]; // [rsp+8h] [rbp-1Ch]
  char *v7; // [rsp+Ch] [rbp-18h]

  v7 = a1;
  *(_DWORD *)v6 = 0x8A919FF0;
  v4 = 4;
  for ( i = v5; ; ++i )
  {
    v2 = v4--;
    if ( !v2 )
      break;
    *i = *a1++;
  }
  return v6[0] == v5[0] && v6[1] == v5[1] && v6[2] == v5[2] && v6[3] == v5[3];
}
```

Nhìn chung thì phải này chỉ có mỗi lỗi `buffer overflow` ở function `HANDLE()`.

Ngay sau khi đọc xong source code tôi nghĩ ngay đến 2 bài khá giống mà mình đã từng làm ở `pwnable.tw` đó là `deaslr` và `unexploitable` tuy nhiên để làm được 2 bài này thì cần phải ghi được vào `bss` mà ở bài này sau khi `read` sẽ ngắt hết `input` và `output` đối với `client`.

Hiển nhiên tôi nghĩ ngay đến việc phải thực hiện back connect về để đọc flag, tuy nhiên điều này hoàn toàn không dễ dàng.

Ban đầu tôi nghĩ đến việc tạo địa chỉ `syscall` bằng GOT table của một hàm nào đó có địa chỉ gần `syscall` tuy nhiên gặp đôi chút khó khăn trong việc tạo địa chỉ `syscall` vì không thể ghi được vào `bss`.

Sau một thời gian thử với nhiều cách khác nhau tôi chợt nhật ra mình đang quên một cái gì đó :)). Đó là hàm `Check()` được tác giả sử dụng nhưng không có ý nghĩa gì với flow chuẩn của chương trình. Phải chẳng đó là một chức năng có thể giúp giải đc bài này.

Tôi lập tức forcus vô hàm này và nhận thấy từ đây mình óc thể copy toàn bộ dữ liệu đã được nhập vô `stack` vòa `bss`.
```
.text:0000000000400673                 mov     [rbp+var_24], 4
.text:000000000040067A                 lea     rbx, [rbp+var_20]
.text:000000000040067E                 mov     rsi, rbx
```
Trên đây là đoạn lấy địa chỉ để copy dữ liệu vào. 

`mov     [rbp+var_24], 4` chính là gán số lượng byte được copy bằng `4`.
`lea     rbx, [rbp+var_20]` chính là lấy giá trị địa chỉ được ghi vào thanh ghi `rbx`.
Như vậy nếu thay đổi `rbp` theo ý mình thì tôi hoàn toàn có thể copy vào một địa chỉ bất kỳ.
Mặc khác sau khi chạy đến `ret` của function `Check()` thì giá trị của `rdi` đang trỏ tới `offset 4` vùng nhớ được nhập vô `stack`.

Như vậy tôi có thể copy dữ liệu vô `bss` => có thể thực hiện được theo hướng của 2 bài `unexploitable` và `deaslr`.

Việc còn lại chỉ là tìm kiếm các `rop chain` hợp lý để thực hiện ý đồ của mình.

Ở bài này tôi có làm theo 2 hướng và nó đều ko đúng ý tưởng ban đầu của tác giả.

Cách 1: Tạo địa chỉ `system` rồi thực thiện `system(command)`: file [solve_system.py](solve_system.py)

Cách 2: Tạo địa chỉ `syscall` rồi thực hiện `exec('/bin/bash', '-c', command): file [solve_syscall.py](solve_syscall.py)

Tuy nhiên vì một lý do magic nào đó tôi không thể thực hiện remote thành công với cách 1.

