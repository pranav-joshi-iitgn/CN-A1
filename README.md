# Team members

| Name | Roll no. |
| ---- | -------- |
| Pranav Joshi | 22110197 |
| Neeshit | 22110172 |

# Task 1: Custom DNS Resolver

The PCAP file number should be $(197 + 172) \text{ mod } 10 = 9$. Thus, I should use `9.pcap` for the report.

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
$ python3 client.py 9.pcap
2025-09-04 18:04:16.129282 : UDP 10.240.26.55 → 8.8.8.8 : 00:00:01:0...
2025-09-04 18:04:16.129867 : UDP 10.240.26.55 → 8.8.8.8 : 00:00:01:0...
2025-09-04 18:04:16.129593 : UDP 10.240.26.55 → 8.8.8.8 : 00:00:01:0...
2025-09-04 18:04:16.129442 : UDP 10.240.26.55 → 8.8.8.8 : 00:00:01:0...
2025-09-04 18:04:16.129997 : UDP 10.240.26.55 → 8.8.8.8 : 00:00:01:0...
2025-09-04 18:04:16.129735 : UDP 10.240.26.55 → 8.8.8.8 : 00:00:01:0...
Extracted!
Sent 37 bytes to 127.0.0.1:5353
Response: 192.168.1.6
Sent 37 bytes to 127.0.0.1:5353
Response: 192.168.1.7
Sent 37 bytes to 127.0.0.1:5353
Response: 192.168.1.8
Sent 38 bytes to 127.0.0.1:5353
Response: 192.168.1.9
Sent 36 bytes to 127.0.0.1:5353
Response: 192.168.1.10
Sent 36 bytes to 127.0.0.1:5353
Response: 192.168.1.6
```

and on server side :

```
TCP connection established with 127.0.0.1:55674
Received DNS query (37 bytes)
Header extracted :18:04:16:0
IP to return : 192.168.1.6
response sent
Received DNS query (37 bytes)
Header extracted :18:04:16:1
IP to return : 192.168.1.7
response sent
Received DNS query (37 bytes)
Header extracted :18:04:16:2
IP to return : 192.168.1.8
response sent
Received DNS query (38 bytes)
Header extracted :18:04:16:3
IP to return : 192.168.1.9
response sent
Received DNS query (36 bytes)
Header extracted :18:04:16:4
IP to return : 192.168.1.10
response sent
Received DNS query (36 bytes)
Header extracted :18:04:16:5
IP to return : 192.168.1.6
response sent
Terminated connection from 127.0.0.1:55674
Server listening on 127.0.0.1:5353
```

The output (in `Report.csv`) will be:

| Custom header value (HHMMSSID)   | Domain name   | Resolved IP address   |
| -------------------------------- | ------------- | --------------------- |
| 18041600                         | twitter.com   | 192.168.1.6           |
| 18041601                         | example.com   | 192.168.1.7           |
| 18041602                         | netflix.com   | 192.168.1.8           |
| 18041603                         | linkedin.com  | 192.168.1.9           |
| 18041604                         | reddit.com    | 192.168.1.10          |
| 18041605                         | openai.com    | 192.168.1.6           |

### Output Files

- `DNSmessages.csv`: Extracted DNS queries from the PCAP (for inspection).
- `Report.csv`: Table of each query, header, and resolved IP (for submission).