Bài này là một cái game nhỏ nuôi pet mà anh `Quang Nguyen(quangnh89)` làm ra.

Đây là struct mình dùng:
```c
struct __attribute__((aligned(8))) animal
{
  _QWORD FUNC;
  _WORD cups;
  char name[8];
  char color[6];
  _QWORD Active;
};
```

Bài này mình thấy 2 lỗi đó là:

```c
_BYTE *__fastcall Eat(animal *animal, __int16 cups)
{
  _BYTE *result; // rax

  result = &animal->cups;
  animal->cups += cups;
  return result;
};

Ở đây dửng dụng đến `WORD` làm tràn đến phần `TYPE` của pet nên có thể magic biến chó thành mèo và mèo thành cá và ngược lại :))

Lỗi thứ 2 là:
```c
char __fastcall Change_color(animal *animal, char *color)
{
  char result; // al

  result = (unsigned int)Get_type(animal) == 1;
  if ( result )
    result = change(animal, color);
  return result;
}
```
Lỗi này là hàm change ko kiểm tra đến size của color làm nó vượt quá `6` tràn sang vùng nhớ khác.

Từ đó mình có thể control vào trigger `system("/bin/sh")`

[solution.py](solution.py)