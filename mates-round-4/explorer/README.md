Bài này thì code dài vcđ nhưng mà thấy hàm mẹ nào cũng giống nhau là thấy có biến ~ rồi.

Thấy mọi chỗ dùng đến hàm read thì đề là `read(0, buf, 8);` nên đã nghi nghi đâu đó không phải là `size 8` mà là `size` lớn hơn đó.

Tuy nhiên việc đọc bằng mắt còn số `99999` hàm là điều không thể nên mình nghĩ đến việc sử dụng `objdump` để tìm.

```bash
$ objdump -d -M intel explorer | grep 'mov edx,0x' > lol.txt
$ cat lol.txt | grep -v '0x8'
```

Thế là mình có được địa chỉ hàm bị lỗi.

```c
int castle42590()
{
  int result; // eax
  char buf[16]; // [rsp+0h] [rbp-10h]

  *(_QWORD *)buf = 0LL;
  read(0, buf, 8uLL);
  result = strcmp(buf, "nSGDGJV");
  if ( !result )
  {
    read(0, buf, 4259uLL);
    result = puts("GET IT?");
  }
  return result;
}
```

Mình gặp một vấn đề là debug nó cứ bị thoát qua cái đoạn nhập `read(0, buf, 4259uLL);` thế là méo debug nữa viết solution gửi lên server thế méo nào lại được :v

[solution.py](solution.py)