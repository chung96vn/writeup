import hashlib

arr = [75, 98, 9, 145, 8, 105, 10, 80, 99, 135, 139, 201, 75, 98, 9, 145, 8, 105, 10, 80, 99, 135, 139, 201, 82, 217, 204, 186, 204, 120, 114, 96, 131, 115, 121, 229, 6, 221, 208, 100, 127, 150, 200, 153, 165, 82, 17, 39, 119, 237, 73, 150, 172, 236, 67, 194, 137, 213, 17, 218, 209, 203, 26, 133, 165, 199, 211, 15, 87, 252, 79, 250, 90, 10, 157, 130]
arr = arr[-64:]

def lfsr(R,mask):
    output = (R << 1) & 0xffffff
    i=(R&mask)&0xffffff
    lastbit=0
    while i!=0:
        lastbit^=(i&1)
        i=i>>1
    output^=lastbit
    return (output,lastbit)



mask = 0b10110110110011010111001101011010101011011

def brute_flag():
	for t in range(2**24):
		flag = t
		for i in range(64):
			tmp=0
			for j in range(8):
				(flag,lastbit)=lfsr(flag,mask)
				tmp=(tmp << 1)^lastbit
			if(arr[i] != tmp):
				break
			if(i==63):
				print t
				exit()

def brute_hash(flag):
	for i in range(2**17):
		tmp = bin(i)[2:] + flag
		raw = 'flag{'+ tmp +'}'
		if(hashlib.sha256(raw).hexdigest()=="b2dcba51efd4a7d6157c956884a15934cb3edd3d2c1026830afa8db4ec108b58"):
			print raw
			exit()
			
brute_flag():			
#flag = '111001101010111010111011'
brute_hash('111001101010111010111011')