#!/usr/bin/env python
"""
From wikipedia
DNS primarily uses User Datagram Protocol (UDP) on port number 53 to serve requests.[3]
DNS queries consist of a single UDP request from the client followed by a single UDP reply from the server.
The Transmission Control Protocol (TCP) is used when the response data size exceeds 512 bytes,
or for tasks such as zone transfers. Some resolver implementations use TCP for all queries.
"""
from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, UDP

if __name__ == '__main__':
    data={}

    reader = PcapReader('../files/dns-remoteshell.pcap')

    with open('sampleOutputDNS.txt', 'wb') as outFile:
        for p in reader :
            if (p.haslayer(TCP) and (p[TCP].sport == 53 or p[TCP].dport == 53))\
                or (p.haslayer(UDP) and (p[UDP].sport == 53 or p[UDP].dport == 53)):
                    # Possible DNS traffic
                    # if TCP then it should contain QTYPE IXFR
                    if not p.haslayer(DNS):
                        # Anomaly detected.
                        outFile.write('Something is not right with this packet: %s\n'%p.lastlayer())
                        outFile.flush()
                    else :
                        # Seems normal but need to check with additional methods described at
                        # http://www.sans.org/reading_room/whitepapers/dns/detecting-dns-tunneling_34152
                        pass

        reader.close()

