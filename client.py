help_message ="""
This is the client side code for task 1 for assignment 1.
Run this as `python3 client.py [OPTIONS] pcapfiles
OPTIONS :
0. `--help` : get this message.
1. `--de` : skip extraction from pcap file and use previously extracted messages
2. `--dwem` : skip writing the extracted messages as a CSV file. 
3. `--parse` : Parse the DNS message without relying on PyShark
4. `--st` : Use packet sniff time rather than the current system time.
5. `--tcp` : Do the communication with DNS resolution server over TCP rather than UDP (default)
6. `--batch` : Batch the extraced DNS messages to resolve togather, rather than immediately (default)
"""

import sys # for taking input from command line
import binascii # for convesion between data formats
import socket # for sending and receiving packets 
from datetime import datetime
import pyshark
# This module is a wrapper around libraries that WireShark is built on.
# This module will be used for extraction and parsing of queries

if '--help' in sys.argv:print(help_message)

# pcap files to extract DNS queries from are passed as arguments
filenames = [f for f in sys.argv[1:] if not f.startswith('--')] 
messages = [] # List of DNS messages; initially empty
HOST = "127.0.0.1"  # IP (v4) address of the server
# Note that since I am running the server process on my laptop that doesn't have a static IP address,
# I am using 127.0.0.1. Otherwise, it will be better to be using an IP address 
# that will allow other devices to connect to the server too. 
# For example, '10.240.21.72' if the server is placed on the ground floor of library.
PORT = 53535 # A port that isn't well known (0-1023) for running this network application
# This port is what the server process will be listening to.
table:list[list[str]] =[] # The final table/report; initially empty

def process_pkt(pkt):
    global messages
    src = pkt.ip.src # source IP address
    dst = pkt.ip.dst # destination IP address
    proto = pkt.transport_layer # transport layer protocol
    # For UDP/TCP packets, the application data is in the "udp.payload" or "tcp.payload"
    if proto == "UDP":payload = pkt.udp.payload
    elif proto == "TCP":payload = pkt.tcp.payload
    else:payload = ""
    if '--st' in sys.argv:
        # The time (with date) when the packet was sniffed/received
        t = pkt.sniff_time 
    else:t = str(datetime.now())
    # showing information about the extracted packet
    if payload:print(f"Packet : {t} : {proto} {src} → {dst} : {payload[:10]}...")
    else:print(f"Packet : {t} : {proto} {src} → {dst} : no payload")
    # Pyshark extracts information about all available layers in the packet.
    dns_layer = pkt.dns # Information about the DNS message
    if "--parse" not in sys.argv:
        if hasattr(dns_layer, "qry_name_all"):
            queries = dns_layer.qry_name_all
            # According to RFC 1035, there can be multiple questions
            # This I am handling that case too by having the table have multiple query values
            # for the same DNS message (with a unique header)
        elif hasattr(dns_layer, "qry_name"):
            queries = [dns_layer.qry_name]
            # But according to RFC 9619, a DNS resolutionrequest or response 
            # should ideally have only one query. So, my code is tailored around that.
        else:
            queries = []
            # In case the DNS message doesn't have any queries.
    else:
        # get the length (bytes 4,5 (0 index))
        B = payload.split(':')
        l = B[4] + B[5]
        l = int(l,16)
        b = 12 # byte number
        queries = []
        while l > 0 :
            name = []
            while True:
                part_len = int(B[b],16) # bytes for this part
                b += 1
                if part_len == 0 : break # null character
                part = (''.join(B[b:b + part_len]))
                part = binascii.unhexlify(part).decode()
                name.append(part)
                b += part_len
            query_type = int(B[b] + B[b+1],16)
            query_class = int(B[b+2] + B[b+3],16)
            b += 4
            name = '.'.join(name)
            queries.append(name)
            l -= 1
    message = [
            proto,src,dst, # These first 3 fields will not actually be used.
            # But I'm still keeping it since we have already extracted the information
            str(t), # This is the date and time
            payload, # The actual message
            ' '.join(queries) # The DNS queries, space separated
        ]
    messages.append(message) # message parsing done
    return message

def process_message(message:list[str],i:int) -> tuple[bytes,str,str]:
    """
    Processes the 6-tuple `message` which contains the features of the extracted DNS query.
    Returns the modified DNS query with custom header (as bytes), the header (asa string) 
    and the domain name for which the DNS query was made.
    """
    queries:str = message[5] # The hostnames for which resolution is needed, sent in this packet
    date,t = message[3].split() # The format for time is `date HH:MM:SS.microseconds`
    t = t.split('.')[0] # removing microseconds.
    timestamp = t.replace(':','') # Now this is in HHMMSS format
    timestamp_hex:str = timestamp.encode().hex() # each character is encoded in hex
    # The actual timestamp (in base 10) and the ID (in base 10)
    header = timestamp + (str(i) if i > 9 else "0"+str(i))
    # The `header` value won't be added to the packet. It's only for adding to the table.
    I = i.to_bytes(2,'big').hex() # The ID excoded in hex
    header_hex:str = timestamp_hex + I # The actual bytes to add to the packet
    # The payload extracted (as hexadecimals) has bytes separated by the ':' character.
    m = message[4].replace(':','') # Removing the ':' characters to get hex value
    m = header_hex + m # adding the header information to the payload
    m = binascii.unhexlify(m) # Converting from hexadecimal string to binary.
    return m,header,queries

def send_message_TCP(m:bytes,s):
    """
    Sends the application layer message `m` (the DNS query with custom header) 
    to the server using TCP socket `s`, and returns the resolved IP address from the server
    """
    l = len(m).to_bytes(2, "big") # According to RFC 1035 (section 4.2.2),
    s.sendall(l) # to send DNS messages over TCP, we should first send the length of the message
    s.sendall(m) # and then the actual message bytes. I'll do this for the custom DNS resolver too.
    print(f"Sent {len(m)} bytes to {HOST}:{PORT}")
    length_bytes = s.recv(2) # similar to how length was first sent from the client,
    # the same will happen when server sends a message to the client.
    # This allows both sides to know precisely when to close the TCP connection
    if length_bytes: # If this is not a FIN segment
        length = int.from_bytes(length_bytes, "big") # Extracting the length from the message
        IP = s.recv(length) # Receiving those many bytes. This will be the resolved IP address
        IP = IP.decode()  # Extracting the IP address from the message
        print("Response:", IP)
        return IP
    return None

def send_message(m:bytes):
    """
    Sends the application layer message `m` (the DNS query with custom header) 
    to the server using UDP and returns the resolved IP address
    """
    s = socket.socket(
            socket.AF_INET, # IPv4
            socket.SOCK_DGRAM # UDP
            )
    s.sendto(m,(HOST,PORT))
    print(f"Sent {len(m)} bytes to {HOST}:{PORT}")
    IP, addr = s.recvfrom(1024) # Receiving those many bytes. This will be the resolved IP address
    IP = IP.decode()  # Extracting the IP address from the message
    print("Response:", IP)
    s.close()
    return IP

if '--de' not in sys.argv: # de means "Don't extract". 
    if not filenames:
        print('You must give a pcap file name as the input argument '
        'or use the `--de` option to use previously extracted messages.')
        exit(1)
    send_immed = '--tcp' not in sys.argv and "--batch" not in sys.argv
    for file in filenames:
        # Open the capture and filter for port 53 traffic (DNS)
        cap = pyshark.FileCapture(file,display_filter="udp.port == 53 || tcp.port == 53")
        for i,pkt in enumerate(cap):
            try:message = process_pkt(pkt)
            except AttributeError:
                print("packet doesn't have IP addresses or ports.")
                continue
            if send_immed:
                m,header,queries = process_message(message,i)
                IP = send_message(m)
                table.append([ # For part c
                    header, # The header (HHMMSSID)
                    queries, # Comma separated host names
                    IP # The resolved IP address
                ])
    else:print("Extracted DNS queries from PCAP" + " and resolved"*send_immed)
else:
    print('using previously extracted DNS messages')
    f = open('DNSmessages.csv','r')
    messages = f.read().split('\n')[1:]
    f.close()
    messages = [m.split(',') for m in messages]

# Writing the messages in a CSV file (completed part a)
if '--dwem' not in sys.argv: # dwem means "don't write extracted messages"
    fields = 'transport_protocol,src_IP,dst_IP,time,message,queries'
    with open('DNSmessages.csv','w') as f:f.write(
        fields + '\n' + '\n'.join([','.join(m) for m in messages]))

# Adding header info and sending packets (part b)

# To send to the server, we need to create a socket.
if '--tcp' in sys.argv:
    with socket.socket(
        socket.AF_INET, # IPv4
        socket.SOCK_STREAM # TCP
        ) as s: # created socket
        s.connect((HOST, PORT)) # connecting to server
        for i,message in enumerate(messages): # i is the value of the ID field
            m,header,queries = process_message(message,i)
            IP = send_message_TCP(m,s)
            if IP is None:
                print('Server closed connection')
                break
            table.append([ # For part c
                header, # The header (HHMMSSID)
                queries, # Comma separated host names
                IP # The resolved IP address
            ])
    # The TCP connection will be closed on coming out the `with` block
elif '--de' in sys.argv or '--batch' in sys.argv:
    for i,message in enumerate(messages):
        m,header,queries = process_message(message,i)
        IP = send_message(m)
        table.append([ # For part c
            header, # The header (HHMMSSID)
            queries, # Comma separated host names
            IP # The resolved IP address
        ])

# Writing the report/table (part c)
fields = '"Custom header value (HHMMSSID)","Domain name","Resolved IP address"'
with open('Report.csv','w') as f:
    f.write('\n'.join([fields] + [','.join(row) for row in table]))
