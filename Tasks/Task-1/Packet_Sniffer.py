import scapy.all as scapy

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        packet_len = len(packet)
        print(f"IP Packet: {source_ip} -> {destination_ip} Protocol: {protocol} Length: {packet_len}")
        print(packet.show())  # Show packet details

    if packet.haslayer(scapy.TCP):
        source_port = packet[scapy.TCP].sport
        destination_port = packet[scapy.TCP].dport
        print(f"TCP Packet: {source_port} -> {destination_port}")
        print(packet.show())  # Show packet details

    if packet.haslayer(scapy.UDP):
        source_port = packet[scapy.UDP].sport
        destination_port = packet[scapy.UDP].dport
        print(f"UDP Packet: {source_port} -> {destination_port}")
        print(packet.show())  # Show packet details

sniff_packets("Ethernet")
