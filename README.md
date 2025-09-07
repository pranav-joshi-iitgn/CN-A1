# Task 1: Custom DNS Resolver

## File Structure
- `client.py`: Client-side script for packet parsing and message sending.
- `server.py`: Server-side script for DNS resolution logic.
- `DNSmessages.csv`: Stores extracted DNS queries. This is optional and can be avoided using `--dwem` option for `client.py` .
- `Report.csv`: Records query headers, domains, and resolved IPs.

## Usage

### Prerequisites

- Python 3.x
- `pyshark` library (`pip install pyshark`)
- PCAP file for DNS traffic (see assignment instructions for correct selection)

### Running the Server

```bash
python3 server.py
```

This will start the server on `127.0.0.1:5353`, giving this output:

```
Server listening on 127.0.0.1:5353
```

Ensure the server is running before starting the client.

### Running the Client

```
python3 client.py [OPTIONS] <pcapfile>
```
#### Options:

- `--help`: Show help message and usage instructions.
- `--de`: Skip extraction from PCAP and use previously extracted messages (in `DNSmessages.csv`).
- `--dwem`: Skip writing extracted messages in `DNSmessages.csv`.

The client parses DNS queries from the PCAP file, adds a header, sends them to the server, and writes the results to `Report.csv`.

For example, on client side we get this: 

```
$ python3 client.py 0.pcap
2025-09-04 18:04:16.109507 : UDP 10.240.26.55 → 8.8.8.8 : 00:00:01:0...
2025-09-04 18:04:16.109228 : UDP 10.240.26.55 → 8.8.8.8 : 00:00:01:0...
2025-09-04 18:04:16.109085 : UDP 10.240.26.55 → 8.8.8.8 : 00:00:01:0...
2025-09-04 18:04:16.108843 : UDP 10.240.26.55 → 8.8.8.8 : 00:00:01:0...
2025-09-04 18:04:16.109642 : UDP 10.240.26.55 → 8.8.8.8 : 00:00:01:0...
2025-09-04 18:04:16.109370 : UDP 10.240.26.55 → 8.8.8.8 : 00:00:01:0...
Extracted!
Sent 34 bytes to 127.0.0.1:5353
Response: 192.168.1.6
Sent 37 bytes to 127.0.0.1:5353
Response: 192.168.1.7
Sent 36 bytes to 127.0.0.1:5353
Response: 192.168.1.8
Sent 35 bytes to 127.0.0.1:5353
Response: 192.168.1.9
Sent 36 bytes to 127.0.0.1:5353
Response: 192.168.1.10
Sent 36 bytes to 127.0.0.1:5353
Response: 192.168.1.6
```

and on server side :

```
Connection from ('127.0.0.1', 33364)
Received DNS query (34 bytes)
Header extracted :18:04:16:0
IP to return : 192.168.1.6
response sent
Connection from ('127.0.0.1', 33380)
Received DNS query (37 bytes)
Header extracted :18:04:16:1
IP to return : 192.168.1.7
response sent
Connection from ('127.0.0.1', 33386)
Received DNS query (36 bytes)
Header extracted :18:04:16:2
IP to return : 192.168.1.8
response sent
Connection from ('127.0.0.1', 33390)
Received DNS query (35 bytes)
Header extracted :18:04:16:3
IP to return : 192.168.1.9
response sent
Connection from ('127.0.0.1', 33406)
Received DNS query (36 bytes)
Header extracted :18:04:16:4
IP to return : 192.168.1.10
response sent
Connection from ('127.0.0.1', 33412)
Received DNS query (36 bytes)
Header extracted :18:04:16:5
IP to return : 192.168.1.6
response sent
```

The output (in `Report.csv`) will be:

| Custom header value (HHMMSSID)   | Domain name   | Resolved IP address   |
| -------------------------------- | ------------- | --------------------- |
| 18041600                         | bing.com      | 192.168.1.6           |
| 18041601                         | example.com   | 192.168.1.7           |
| 18041602                         | amazon.com    | 192.168.1.8           |
| 18041603                         | yahoo.com     | 192.168.1.9           |
| 18041604                         | google.com    | 192.168.1.10          |
| 18041605                         | github.com    | 192.168.1.6           |

### Output Files

- `DNSmessages.csv`: Extracted DNS queries from the PCAP (for inspection).
- `Report.csv`: Table of each query, header, and resolved IP (for submission).