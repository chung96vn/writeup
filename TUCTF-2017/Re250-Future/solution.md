# Writeup Of AceBear Team

I have source code:
```C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void genMatrix(char mat[5][5], char str[]) {
	for (int i = 0; i < 25; i++) {
		int m = (i * 2) % 25;
		int f = (i * 7) % 25;
		mat[m/5][m%5] = str[f];
	}
}

void genAuthString(char mat[5][5], char auth[]) {
	auth[0] = mat[0][0] + mat[4][4];
	auth[1] = mat[2][1] + mat[0][2];
	auth[2] = mat[4][2] + mat[4][1];
	auth[3] = mat[1][3] + mat[3][1];
	auth[4] = mat[3][4] + mat[1][2];
	auth[5] = mat[1][0] + mat[2][3];
	auth[6] = mat[2][4] + mat[2][0];
	auth[7] = mat[3][3] + mat[3][2] + mat[0][3];
	auth[8] = mat[0][4] + mat[4][0] + mat[0][1];
	auth[9] = mat[3][3] + mat[2][0];
	auth[10] = mat[4][0] + mat[1][2];
	auth[11] = mat[0][4] + mat[4][1];
	auth[12] = mat[0][3] + mat[0][2];
	auth[13] = mat[3][0] + mat[2][0];
	auth[14] = mat[1][4] + mat[1][2];
	auth[15] = mat[4][3] + mat[2][3];
	auth[16] = mat[2][2] + mat[0][2];
	auth[17] = mat[1][1] + mat[4][1];
}

int main() {
	char flag[26];
	printf("What's the flag: ");
	scanf("%25s", flag);
	flag[25] = 0;

	if (strlen(flag) != 25) {
		puts("Try harder.");
		return 0;
	}


	// Setup matrix
	char mat[5][5];// Matrix for a jumbled string
	genMatrix(mat, flag);
	// Generate auth string
	char auth[19]; // The auth string they generate
	auth[18] = 0; // null byte
	genAuthString(mat, auth);	
	char pass[19] = "\x8b\xce\xb0\x89\x7b\xb0\xb0\xee\xbf\x92\x65\x9d\x9a\x99\x99\x94\xad\xe4\x00";
	
	// Check the input
	if (!strcmp(pass, auth)) {
		puts("Yup thats the flag!");
	} else {
		puts("Nope. Try again.");
	}
	
	return 0;
}
```
In `genAuthString` i can use z3 to find matrix because i know format of flag `TUCTF{.....}` and all characters is from 33 to 126.

I use debug to view matrix gen from flag.
Input flag: TUCTF{0123456789abcdefgh}
I have matrix: Ta1h8{f6Td4Ub2}90g7Fe5Cc3

Below is my script
```py
from z3 import *

x0 = Int('x0')
x1 = Int('x1')
x2 = Int('x2')
x3 = Int('x3')
x4 = Int('x4')
x5 = Int('x5')
x6 = Int('x6')
x7 = Int('x7')
x8 = Int('x8')
x9 = Int('x9')
x10 = Int('x10')
x11 = Int('x11')
x12 = Int('x12')
x13 = Int('x13')
x14 = Int('x14')
x15 = Int('x15')
x16 = Int('x16')
x17 = Int('x17')
x18 = Int('x18')
x19 = Int('x19')
x20 = Int('x20')
x21 = Int('x21')
x22 = Int('x22')
x23 = Int('x23')
x24 = Int('x24')

s = Solver()
s.add(x0 > 32, x0 < 127)
s.add(x1 > 32, x1 < 127)
s.add(x2 > 32, x2 < 127)
s.add(x3 > 32, x3 < 127)
s.add(x4 > 32, x4 < 127)
s.add(x5 > 32, x5 < 127)
s.add(x6 > 32, x6 < 127)
s.add(x7 > 32, x7 < 127)
s.add(x8 > 32, x8 < 127)
s.add(x9 > 32, x9 < 127)
s.add(x10 > 32, x10 < 127)
s.add(x11 > 32, x11 < 127)
s.add(x12 > 32, x12 < 127)
s.add(x13 > 32, x13 < 127)
s.add(x14 > 32, x14 < 127)
s.add(x15 > 32, x15 < 127)
s.add(x16 > 32, x16 < 127)
s.add(x17 > 32, x17 < 127)
s.add(x18 > 32, x18 < 127)
s.add(x19 > 32, x19 < 127)
s.add(x20 > 32, x20 < 127)
s.add(x21 > 32, x21 < 127)
s.add(x22 > 32, x22 < 127)
s.add(x23 > 32, x23 < 127)
s.add(x24 > 32, x24 < 127)

s.add(x0 == 0x54)
s.add(x5 == ord('{'))
s.add(x8 == ord('T'))
s.add(x11 == ord('U'))
s.add(x14 == ord('}'))
s.add(x19 == ord('F'))
s.add(x22 == ord('C'))

key = "\x8b\xce\xb0\x89\x7b\xb0\xb0\xee\xbf\x92\x65\x9d\x9a\x99\x99\x94\xad\xe4\x00"
auth = []
for x in key:
    auth.append(ord(x))

s.add(x0+ x24 == auth[0])
s.add(x11 + x2 == auth[1])
s.add(x22 + x21 == auth[2])
s.add(x8 + x16 == auth[3])
s.add(x19 + x7 == auth[4])
s.add(x5 + x13 == auth[5])
s.add(x14 + x10 == auth[6])
s.add(x18 + x17 + x3 == auth[7])
s.add(x4 + x20 + x1 == auth[8])
s.add(x18 + x10  == auth[9])
s.add(x20 + x7 == auth[10])
s.add(x4 + x21 == auth[11])
s.add(x3 + x2 == auth[12])
s.add(x15 + x10 == auth[13])
s.add(x9 + x7 == auth[14])
s.add(x23 + x13 == auth[15])
s.add(x12 + x2 == auth[16])
s.add(x6 + x21 == auth[17])

print s.check()
mod = s.model()

chars = [
        mod[x0],
        mod[x1],
        mod[x2],
        mod[x3],
        mod[x4],
        mod[x5],
        mod[x6],
        mod[x7],
        mod[x8],
        mod[x9],
        mod[x10],
        mod[x11],
        mod[x12],
        mod[x13],
        mod[x14],
        mod[x15],
        mod[x16],
        mod[x17],
        mod[x18],
        mod[x19],
        mod[x20],
        mod[x21],
        mod[x22],
        mod[x23],
        mod[x24],
    ]
    
flagz = ''.join(chr(int(str(x))) for x in chars)
mat = "Ta1h8{f6Td4Ub2}90g7Fe5Cc3"
print flagz
flag = "TUCTF{"
for x in "0123456789abcdefgh":
	flag += flagz[mat.find(x)]
flag += "}"
print flag
```
