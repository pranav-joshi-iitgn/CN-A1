
IP_Pool = [
"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
"192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10", 
"192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

import socket
HOST = "127.0.0.1"
PORT = 5353

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
    server_sock.bind((HOST, PORT))
    server_sock.listen()
    print(f"Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = server_sock.accept()
        with conn:
            print(f"Connection from {addr}")

            # Read 2-byte length prefix
            length_bytes = conn.recv(2)
            if not length_bytes:continue
            length = int.from_bytes(length_bytes, "big")

            # Read exactly that many bytes
            data = conn.recv(length)
            data = data.hex()
            print(f"Received DNS query ({length} bytes)")

            # extract header
            h = data[0:4]
            m = data[4:8]
            s = data[8:12]
            i = data[12:16]
            message = data[16:]
            h = chr(int(h[:2],16)) + chr(int(h[2:],16))
            m = chr(int(m[:2],16)) + chr(int(m[2:],16))
            s = chr(int(s[:2],16)) + chr(int(s[2:],16))
            i = int(i, 16)
            print(f"Header extracted :{h}:{m}:{s}:{i}")

            # create response
            h = int(h)
            i = i % 5
            if h >= 4 and h < 12 : ip_pool_start = 0 # morning
            elif h >= 12 and h < 20 : ip_pool_start = 5 # afternoon
            else : ip_pool_start = 10 # night
            i = i + ip_pool_start
            ip = IP_Pool[i]
            print('IP to return :',ip)

            # send response
            response = ip.encode()
            msg = len(response).to_bytes(2, "big") + response
            conn.sendall(msg)
            print('response sent')