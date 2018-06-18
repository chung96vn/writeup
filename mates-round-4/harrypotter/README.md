Bài nay thì ban đầu mình nhìn rất giống bài `echo` và đã có ý tưởng làm theo hướng bài echo nhưng ko để ý đến `checksec` là `FULL RELRO` nên việc đè `puts GOT` là không thể?

Mình đã nghĩ đến việc ban tổ chức nhầm trong lúc `compiler` nên đã report và BTC xác nhận là đề không sai.

Mình đã bế tắc rất lâu cho đến lúc để ý là flag đã được copy vào `stack`

```c
unsigned __int64 Vipera_Evanesca()
{
  int v0; // ST0C_4
  signed int i; // [rsp+Ch] [rbp-814h]
  int j; // [rsp+Ch] [rbp-814h]
  char dest[2056]; // [rsp+10h] [rbp-810h]
  unsigned __int64 v5; // [rsp+818h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("System: Vipera Evanesca (https://youtu.be/ZAf3U0J8Se8?t=1m58s)");
  strncpy(dest, flag, 0x400uLL);
  for ( i = 0; i <= 1023 && dest[i] != '{'; ++i )
    ;
  v0 = i + 1;
  flag[v0] = '}';
  for ( j = v0 + 1; j <= 1023; ++j )
    flag[j] = 0;
  return __readfsqword(0x28u) ^ v5;
}
```

Từ đó mình có một hướng là `brute force stack` để lấy flag.

Mình thấy bài này nếu để theo hướng đè `GOT` sẽ hay hơn nhưng không hiểu sao người ra đề lại có ý tưởng theo hướng này và mình cũng không biết hướng giải của BTC có phải là `brute force` không nữa nhưng mình là mình thấy bài này `không hay` khi độ hên xui khá nhiều.

[solution.py](solution.py)