import socket
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP

def tcp_connect_scan(target_ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect((target_ip, port))
        sock.close()
        return True
    except:
        return False

def syn_scan(target_ip, port):
    src_port = scapy.RandShort()
    syn_packet = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="S")
    response = scapy.sr1(syn_packet, timeout=1, verbose=False)

    if response is not None and response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12: 
            rst_packet = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="R")
            scapy.send(rst_packet, verbose=False)  
            return True
    return False

def udp_scan(target_ip, port):
    udp_packet = IP(dst=target_ip)/UDP(dport=port)
    response = scapy.sr1(udp_packet, timeout=1, verbose=False)
    
    if response is None:
        return True  # might be open|filtered
    elif response.haslayer(UDP):
        return True  # UDP open
    elif response.haslayer(scapy.ICMP) and response.getlayer(scapy.ICMP).type == 3:
        if response.getlayer(scapy.ICMP).code == 3:
            return False  # Port unreachable
    return False

def service_detection(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target_ip, port))
        sock.sendall(b"GET / HTTP/1.1\r\n\r\n")
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()

        if "Server:" in response:
            return response.split("Server: ")[1].split("\r\n")[0]
        else:
            return "Unknown"
    except:
        return "Unknown"

def scan(target_ip, ports, scan_type="tcp_connect"):
    print(f"Scanning {target_ip} using {scan_type} scan")
    
    for port in ports:
        if scan_type == "tcp_connect":
            open_port = tcp_connect_scan(target_ip, port)
        elif scan_type == "syn":
            open_port = syn_scan(target_ip, port)
        elif scan_type == "udp":
            open_port = udp_scan(target_ip, port)
        else:
            print("Invalid scan type")
            return

        if open_port:
            service = service_detection(target_ip, port)
            print(f"Port {port} is open, service: {service}")
        else:
            print(f"Port {port} is closed")
            #pass

if __name__ == "__main__":
    target = "192.168.0.66" 
    port_range = range(20, 1025) 
    scan_mode = "syn"  # Options: "tcp_connect", "syn", "udp"

    scan(target, port_range, scan_mode)
