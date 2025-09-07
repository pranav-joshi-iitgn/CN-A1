help_message ="""
This is the client side code for task 1 for assignment 1.
Run this as `python3 client.py [OPTIONS] pcapfiles
OPTIONS :
0. Use `--help` to get this message.
1. Use `--de` to skip extraction from pcap file and use previously extracted messages
2. Use `--dwem` to skip writing the extracted messages as a CSV file. 
"""

import sys # for taking input from command line
import binascii # for convesion between data formats
import socket # for sending and receiving packets 

import pyshark
# This module is a wrapper around libraries that WireShark is built on.
# This module will be used for extraction and parsing of queries

if '--help' in sys.argv:print(help_message)

# pcap files to extract DNS queries from are passed as arguments
filenames = [f for f in sys.argv[1:] if not f.startswith('--')] 
messages = [] # List of DNS messages; initially empty

if '--de' not in sys.argv: # de means "Don't extract". 
    if not filenames:
        print('You must give a pcap file name as the input argument '
        'or use the `--de` option to use previously extracted messages.')
        exit(1)
    for file in filenames:
        # Open the capture and filter for port 53 traffic (DNS)
        cap = pyshark.FileCapture(file,display_filter="udp.port == 53 || tcp.port == 53")
        for pkt in cap:
            try:
                src = pkt.ip.src # source IP address
                dst = pkt.ip.dst # destination IP address
                proto = pkt.transport_layer # transport layer protocol
                # For UDP/TCP packets, the application data is in the "udp.payload" or "tcp.payload"
                if proto == "UDP":payload = pkt.udp.payload
                elif proto == "TCP":payload = pkt.tcp.payload
                else:payload = ""
                t = pkt.sniff_time # The time (with date) when the packet was sniffed/received
                # showing information about the extracted packet
                if payload:print(f"{t} : {proto} {src} → {dst} : {payload[:10]}...")
                else:print(f"{t} : {proto} {src} → {dst} : no payload")
                # Pyshark extracts information about all available layers in the packet.
                dns_layer = pkt.dns # Information about the DNS message
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
                message = [
                        proto,src,dst, # These first 3 fields will not actually be used.
                        # But I'm still keeping it since we have already extracted the information
                        str(t), # This is the date and time
                        payload, # The actual message
                        ' '.join(queries) # The DNS queries, space separated
                    ]
                messages.append(message) # message parsing done

            except AttributeError:
                print("packet doesn't have IP addresses or ports.")
                continue
    print("Extracted!")
else: # use the previously extracted messages
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

HOST = "127.0.0.1"  # IP (v4) address of the server
PORT = 5353 # A port that isn't well known (0-1023) for running this network application
table:list[list[str]] =[] # The final table/report; initially empty

for i,message in enumerate(messages): # i is the value of the ID field
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
    # Now, to send this to the server, we need to create a socket.
    # To keep things simple, I'll use IPv4 (`AF_INET`) and TCP (`SOCK_STREAM`) for the socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: # created socket
        s.connect((HOST, PORT)) # connecting to server
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
            table.append([ # For part c
                header, # The header (HHMMSSID)
                queries, # Comma separated host names
                IP # The resolved IP address
            ])
    # The TCP connection will be closed on coming out the `with` block

# Writing the report/table (part c)
fields = '"Custom header value (HHMMSSID)","Domain name","Resolved IP address"'
with open('Report.csv','w') as f:
    f.write('\n'.join([fields] + [','.join(row) for row in table]))
