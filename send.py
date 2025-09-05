import binascii
f = open('DNSmessages.csv','r')
messages = f.read().split('\n')[1:]
f.close()
messages = [m.split(',') for m in messages]
for m in messages: print(m)
import socket
HOST = "127.0.0.1"
PORT = 5353
table =[]

for i,m in enumerate(messages) :
    queries = m[5]
    date,t = m[3].split()
    t = t.split('.')[0] # removing microseconds.
    header_hex = t.replace(':','').encode().hex()
    header = t + ":" + str(i)
    I = i.to_bytes(2,'big').hex()
    header_hex = header_hex + I
    m = header_hex + m[4].replace(':','')
    m = binascii.unhexlify(m)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(len(m).to_bytes(2, "big"))
        s.sendall(m)
        print(f"Sent {len(m)} bytes to {HOST}:{PORT}")
        length_bytes = s.recv(2)
        if length_bytes:
            length = int.from_bytes(length_bytes, "big")
            IP = s.recv(length)
            IP = IP.decode()
            print("Response:", IP)
            table.append([header,queries,IP])

for row in table:
    row[1] = ','.join(row[1].split())
    print(row)