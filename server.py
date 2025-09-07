IP_Pool = [
"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
"192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10", 
"192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

import socket
HOST = "127.0.0.1"
# You can use `HOST = '10.240.21.72'` if you are on the ground floor of main library.
PORT = 5353

with socket.socket(
    socket.AF_INET, # IPv4
    socket.SOCK_STREAM # TCP
) as resolver_socket:
    resolver_socket.bind((HOST, PORT)) # bind the socket to the 5353 port
    resolver_socket.listen() # listen for connection requests
    while True:
        print(f"Server listening on {HOST}:{PORT}")
        conn, addr = resolver_socket.accept() 
        client_IP,client_port = addr
        # successful connection `conn` from `addr`
        with conn:
            print(f"TCP connection established with {client_IP}:{client_port}")
            while True:
            
                # Read 2-byte length prefix
                length_bytes = conn.recv(2)
                if not length_bytes:break # FIN segment
                length = int.from_bytes(length_bytes, "big") # extract the length from first 2 bytes
    
                # Read exactly `length` many bytes
                data = conn.recv(length)
                data = data.hex() # convert to hex string to extract the header easily
                print(f"Received DNS query ({length} bytes)")
    
                # extract header
                h = data[0:4] # HH encoded in hex
                m = data[4:8] # MM
                s = data[8:12] # SS
                i = data[12:16] # ID
                message = data[16:]
                # converting hex values for timestamp back to strings
                h = chr(int(h[:2],16)) + chr(int(h[2:],16))
                m = chr(int(m[:2],16)) + chr(int(m[2:],16))
                s = chr(int(s[:2],16)) + chr(int(s[2:],16))
                i = int(i, 16) # convert hex encoded ID back to integer
                print(f"Header extracted :{h}:{m}:{s}:{i}")
    
                # create response
                h = int(h) # the hours value
                i = i % 5 # ID mod 5
                # Getting the value of ip_pool_start according to the rules
                if h >= 4 and h < 12 : ip_pool_start = 0 # morning
                elif h >= 12 and h < 20 : ip_pool_start = 5 # afternoon
                else : ip_pool_start = 10 # night
                i = i + ip_pool_start # The index in `IP_Pool` for the response
                ip = IP_Pool[i] # The IP address to return
                print('IP to return :',ip)
                # Note that the rather than using the Rule.json given, I'm coding it directly.
                # This is because the protocol is explicitely stated in the google doc.
                # It isn't said anywhere that my application should infer the rules from
                # a given Rules.json file.
    
                # send response
                response = ip.encode()
                msg = len(response).to_bytes(2, "big") + response
                conn.sendall(msg)
                print('response sent')
        print(f"Terminated connection from {client_IP}:{client_port}")