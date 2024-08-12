import socket
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import threading
from queue import Queue
import concurrent.futures
import argparse

def tcp_connect_scan(target_ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect((target_ip, port))
        return (port, True)
    except:
        return (port, False)
    finally:
        sock.close()


def syn_scan(target_ip, port):
    src_port = scapy.RandShort()
    syn_packet = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="S")
    response = scapy.sr1(syn_packet, timeout=1, verbose=False)

    if response is not None and response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK received
            rst_packet = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="R")
            scapy.send(rst_packet, verbose=False)  # Send RST to close connection
            return (port, True)
    return (port, False)


def udp_scan(target_ip, port):
    udp_packet = IP(dst=target_ip)/UDP(dport=port)
    response = scapy.sr1(udp_packet, timeout=1, verbose=False)
    
    if response is None:
        return (port, True)  # No response, might be open|filtered
    elif response.haslayer(UDP):
        return (port, True)  # UDP open
    elif response.haslayer(scapy.ICMP) and response.getlayer(scapy.ICMP).type == 3:
        if response.getlayer(scapy.ICMP).code == 3:
            return (port, False)  # Port unreachable
    return (port, False)


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


def scan_port(target_ip, port, scan_type):
    if scan_type == "tcp_connect":
        return tcp_connect_scan(target_ip, port)
    elif scan_type == "syn":
        return syn_scan(target_ip, port)
    elif scan_type == "udp":
        return udp_scan(target_ip, port)
    return (port, False)


def scan(target_ip, ports, scan_type="tcp_connect", num_threads=100):
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(scan_port, target_ip, port, scan_type): port for port in ports}
        
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service = service_detection(target_ip, port)
                print(f"Port {port} is open, service: {service}")
            else:
                print(f"Port {port} is closed")


def check_user_input():
    while True:
        buffer = input("")
        print("Scan is still in progress...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A simple port scanner.")
    parser.add_argument("target", help="Target IP address to scan.")
    parser.add_argument("--ps", type=int, default=1, help="Start port (default is 1).")
    parser.add_argument("--pe", type=int, default=65535, help="End port (default is 65535).")
    parser.add_argument("--scan-type", choices=["tcp_connect", "syn", "udp"], default="tcp_connect", help="Scan type (default is tcp_connect).")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads to use (default is 100).")

    args = parser.parse_args()

    port_range = range(args.ps, args.pe + 1)
    scan_mode = args.scan_type
    num_threads = args.threads
    target = args.target

    user_input_thread = threading.Thread(target=check_user_input, daemon=True)
    user_input_thread.start()

    scan(target, port_range, scan_mode, num_threads)
