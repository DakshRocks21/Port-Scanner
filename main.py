import socket
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import threading
from queue import Queue

def tcp_connect_scan(target_ip, port, result_queue):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect((target_ip, port))
        result_queue.put((port, True))
    except:
        result_queue.put((port, False))
    finally:
        sock.close()

def syn_scan(target_ip, port, result_queue):
    src_port = scapy.RandShort()
    syn_packet = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="S")
    response = scapy.sr1(syn_packet, timeout=1, verbose=False)

    if response is not None and response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK received
            rst_packet = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="R")
            scapy.send(rst_packet, verbose=False)  # Send RST to close connection
            result_queue.put((port, True))
            return
    result_queue.put((port, False))

def udp_scan(target_ip, port, result_queue):
    udp_packet = IP(dst=target_ip)/UDP(dport=port)
    response = scapy.sr1(udp_packet, timeout=1, verbose=False)
    
    if response is None:
        result_queue.put((port, True))  # No response, might be open|filtered
    elif response.haslayer(UDP):
        result_queue.put((port, True))  # UDP open
    elif response.haslayer(scapy.ICMP) and response.getlayer(scapy.ICMP).type == 3:
        if response.getlayer(scapy.ICMP).code == 3:
            result_queue.put((port, False))  # Port unreachable
    else:
        result_queue.put((port, False))

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

def worker(target_ip, ports_queue, result_queue, scan_type):
    while not ports_queue.empty():
        port = ports_queue.get()
        if scan_type == "tcp_connect":
            tcp_connect_scan(target_ip, port, result_queue)
        elif scan_type == "syn":
            syn_scan(target_ip, port, result_queue)
        elif scan_type == "udp":
            udp_scan(target_ip, port, result_queue)
        ports_queue.task_done()

def scan(target_ip, ports, scan_type="tcp_connect", num_threads=100):
    ports_queue = Queue()
    result_queue = Queue()
    
    for port in ports:
        ports_queue.put(port)
    
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(target_ip, ports_queue, result_queue, scan_type))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()

    while not result_queue.empty():
        port, is_open = result_queue.get()
        if is_open:
            service = service_detection(target_ip, port)
            print(f"Port {port} is open, service: {service}")
        else:
            print(f"Port {port} is closed")

if __name__ == "__main__":
    target = "192.168.0.66"
    port_range = range(100, 600)
    scan_mode = "syn"  # Options: "tcp_connect", "syn", "udp"
    num_threads = 100

    scan(target, port_range, scan_mode, num_threads)
