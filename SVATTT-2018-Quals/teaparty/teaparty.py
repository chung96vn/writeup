import struct
import os

class Tictactoe:
    def __init__(self, key):
        self.delta = 0x9E3779B9
        self.mask = 0xffffffff
        self.rounds = 64
        self.block_size = 8 #char
        self.key = struct.unpack('4I', key)
        # print self.key

    def _encrypt(self, v):
        x, y = struct.unpack('2I', v)
        sum = 0
        for _ in range(self.rounds):
            x += (((y << 4) ^ (y >> 5)) + y) ^ (sum + self.key[sum & 3])
            
            x &= self.mask
            
            sum = (sum + self.delta) & self.mask
            
            y += (((x << 4) ^ (x >> 5)) + x) ^ (sum + self.key[(sum>>11) & 3])
            
            y &= self.mask
        
        return struct.pack('2I', x, y)

    def _decrypt(self, v):
        x, y = struct.unpack('2I', v)
        sum = (self.delta * self.rounds) & self.mask
        for _ in range(self.rounds):
            y -= (((x << 4) ^ (x >> 5)) + x) ^ (sum + self.key[(sum>>11) & 3])
            y &= self.mask
            sum = (sum - self.delta) & self.mask
            x -= (((y << 4) ^ (y >> 5)) + y) ^ (sum + self.key[sum & 3])
            x &= self.mask
        return struct.pack('2I', x, y) 

    def encrypt(self, plaintext):
        # padding
        pad = self.block_size - (len(plaintext) % 8)
        plaintext = plaintext + chr(pad) * pad
        # block encrypt ecb
        ciphertext = ''
        for i in range(0,len(plaintext),8):
            ciphertext += self._encrypt(plaintext[i:i+8])
        return ciphertext

    def decrypt(self, ciphertext):
        # block decrypt ecb
        plaintext = ''
        for i in range(0,len(ciphertext),8):
            plaintext += self._decrypt(ciphertext[i:i+8])
        # remove padding
        pad = ord(plaintext[-1])
        return plaintext[:-pad]

flag = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
challenge = 'Would you like xome tea?'
menu = '''1. Sign up
2. Log in
'''
request = 'Hi, my name is {name}, and my register code is {code}'

if __name__ == '__main__':
    cipher = Tictactoe(os.urandom(16))
    print challenge
    while 1:
        try:
            inp = raw_input(menu)
            if inp == '1':
                inp = raw_input('Your name: ')
                payload = request.format(name = inp, code = flag)
                print 'Here is your credential:', cipher.encrypt(payload).encode('hex')
            elif inp == '2':
                inp = raw_input('Who are you? ')
                credential = cipher.decrypt(inp.decode('hex'))
                index_1 = credential.index('Hi, my name is ')
                index_2 = credential.index(', and my register code is ')
                name = credential[index_1+15:index_2]
                if 'SVATTT2018' in name:
                    print 'Hi!, hacker :D'
                else:
                    print 'Hi,', name
            else:
                print 'Bye!'
                break
        except:
            print 'Bye!'
            break