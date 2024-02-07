import socket
import struct

# Create a raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

# Bind the socket to the network interface
s.bind(("192.168.1.29", 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Receive packets
while True:
    packet = s.recvfrom(65565)

    # Print packet data
    print(packet)
