from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
import socket
import threading

# Mapowanie numerów protokołów na nazwy
protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Flaga do zatrzymania wątków
stop_threads = False

#funckja wywoływana dla każdego pakietu
def packet_callback(packet):
    # Jeśli flaga jest ustawiona, zakończ funkcję
    if stop_threads:
        return

    #inicjalizacja zmiennych
    ip_version = None
    ip_src = None
    ip_dst = None
    protocol_num = None

    # Sprawdzenie wersji IP
    if packet.haslayer(IP):
        ip_version = "IPv4"
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol_num = packet[IP].proto
    elif packet.haslayer(IPv6):
        ip_version = "IPv6"
        ip_src = packet[IPv6].src
        ip_dst = packet[IPv6].dst
        protocol_num = packet[IPv6].nh

    if ip_version is None:
        return

    # Mapowanie numeru protokołu na nazwę
    protocol = protocol_map.get(protocol_num, "Unknown")
    src_port, dst_port = None, None

    # Sprawdzenie portów źródłowych i docelowych
    if protocol_num == 6 and packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        # jeśli port to 80 to protokół to HTTP, jeśli 443 to HTTPS
        if dst_port == 80:
            protocol = "HTTP"
        elif dst_port == 443:
            protocol = "HTTPS"
    
    # Jeśli protokół to UDP, pobierz porty źródłowy i docelowy
    elif protocol_num == 17 and packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # Pobierz nazwy hostów
    try:
        hostname_src = socket.gethostbyaddr(ip_src)[0]
    # Jeśli nie można znaleźć nazwy, użyj adresu IP
    except socket.herror:
        hostname_src = ip_src
    try:
        hostname_dst = socket.gethostbyaddr(ip_dst)[0]
    except socket.herror:
        hostname_dst = ip_dst

    print(f"{ip_version} | Source: {hostname_src} sport:{src_port} -> Destination: {hostname_dst} dport:{dst_port} | Protocol: {protocol}")

# Funkcja do przechwytywania pakietów IPv4
def sniff_ipv4():
    sniff(prn=packet_callback, filter="ip", count=10, stop_filter=lambda p: stop_threads)

# Funkcja do przechwytywania pakietów IPv6
def sniff_ipv6():
    sniff(prn=packet_callback, filter="ip6", count=10, stop_filter=lambda p: stop_threads)

# Uruchomienie wątków
threading.Thread(target=sniff_ipv4).start()
threading.Thread(target=sniff_ipv6).start()

