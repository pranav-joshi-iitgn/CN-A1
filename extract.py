import pyshark

filenames = ['0.pcap','2.pcap']
messages = []

for file in filenames:
    # Open the capture and filter for port 53 traffic (DNS)
    cap = pyshark.FileCapture(file,display_filter="udp.port == 53 || tcp.port == 53")

    for pkt in cap:
        try:
            proto = pkt.transport_layer
            src = pkt.ip.src
            dst = pkt.ip.dst

            # For UDP/TCP packets, the application data is in the "udp.payload" or "tcp.payload"
            if proto == "UDP":
                payload = pkt.udp.payload
            elif proto == "TCP":
                payload = pkt.tcp.payload
            else:
                payload = ""
            t = pkt.sniff_time
            if payload:
                print(f"{proto}: {src} → {dst}, time = {t}, payload={payload[:10]}...")
            else:
                print(f"{proto}: {src} → {dst}, time = {t}, (no payload)")

            dns_layer = pkt.dns
            if hasattr(dns_layer, "qry_name_all"):
                queries = dns_layer.qry_name_all
            elif hasattr(dns_layer, "qry_name"):
                queries = [dns_layer.qry_name]
            else:
                queries = []
            message = [
                    proto,
                    src,
                    dst,
                    str(t),
                    payload,
                    ' '.join(queries)
                ]
            messages.append(message)

        except AttributeError:
            # Some packets may not have IP/ports
            continue

f = open('DNSmessages.csv','w')
f.write('transport_protocol,src_IP,dst_IP,time,message,queries\n' 
    + '\n'.join([','.join(m) for m in messages]))
f.close()
