import socket, string, time

target = '"2SiG5c9KCepoPA3iCyLHPRJ25uuo4AvD2/7yPHj2ReCofS9s47LU39JDRSU="'
ll = 2
charset = string.digits + 'abcdef'
nowstring = ''
#print s.recv(1024)

f = open('a','w')

for aa in '0123456789':
    s = socket.socket()
    s.connect(('47.91.210.116', 9999))
    s.recv(1024)
    s.recv(1024)

    s.send('0\n'+'\n'.join(['6170707'+aa + c for c in charset])+'\n')
    data = s.recv(4096)
    f.write(data)

    s.close()
