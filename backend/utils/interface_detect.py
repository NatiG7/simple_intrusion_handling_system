import ipaddress
from scapy.all import get_if_list, IFACES
def is_apipa(ip):
    try:
        return ipaddress.ip_address(ip).is_link_local
    except:
        return True

def select_interface():
    """Select the best active network interface"""
    available_interfaces = get_if_list()
    
    print("Available interfaces:")
    for name in available_interfaces:
        if name in IFACES:
            print(f"  {name}")
            print(f"    Description: {IFACES[name].description}")
            print(f"    IP: {IFACES[name].ip}\n")

    # 1. Prefer Wi-Fi or Ethernet
    for name in available_interfaces:
        if name in IFACES:
            iface = IFACES[name]
            desc = iface.description.lower()
            ip = iface.ip

            if ('wi-fi' in desc or 'wireless' in desc or 'wlan0' in desc or 'realtek' in desc or 'ethernet' in desc) \
               and ip and ip != '0.0.0.0' and not is_apipa(ip):
                print(f"Selected interface: {iface.description}")
                print(f"IP: {iface.ip}\n")
                return name

    # 2. Fallback: any non-WAN, non-loopback, non-APIPA interface
    for name in available_interfaces:
        if name in IFACES:
            iface = IFACES[name]
            desc = iface.description.lower()
            ip = iface.ip
            
            if 'loopback' in desc or 'wan miniport' in desc:
                continue
            if ip and ip != '0.0.0.0' and not is_apipa(ip):
                print(f"Selected interface: {iface.description}")
                print(f"IP: {iface.ip}\n")
                return name
    
    print("ERROR: No active network interface found!")
    return None