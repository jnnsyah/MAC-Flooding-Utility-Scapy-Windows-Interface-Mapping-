from scapy.all import *
import time
import re
import wmi
from scapy.arch.windows import get_windows_if_list

def get_interface_mapping():
    wmi_obj = wmi.WMI()
    scapy_ifaces = get_windows_if_list()
    mappings = []

    for iface in scapy_ifaces:
        guid = iface.get("guid")
        name = iface.get("name")
        description = iface.get("description")
        if not guid:
            continue

        for nic in wmi_obj.Win32_NetworkAdapter():
            if nic.GUID and nic.GUID.lower() == guid.lower():
                if nic.NetConnectionID:
                    mappings.append({
                        "friendly_name": nic.NetConnectionID,
                        "guid": guid,
                        "scapy_name": iface["name"]
                    })
                break
    return mappings

def select_interface():
    mappings = get_interface_mapping()
    if not mappings:
        print("[!] No matching interfaces found.")
        exit(1)

    print("\n🔍 Available Network Interfaces:")
    for i, iface in enumerate(mappings):
        print(f" {i}: {iface['friendly_name']} ({iface['scapy_name']})")

    while True:
        choice = input("Select an interface by number: ").strip()
        if not choice.isdigit():
            print("[!] Please enter a number.")
            continue
        idx = int(choice)
        if 0 <= idx < len(mappings):
            return mappings[idx]['scapy_name']
        else:
            print("[!] Invalid choice.")

def scan_nearby_macs(iface, timeout=5):
    print(f"\n[*] Scanning for nearby MAC addresses on interface {iface} (this may take {timeout} seconds)...")
    try:
        iface_ip = get_if_addr(iface)
        iface_netmask = get_if_netmask(iface)
    except Exception as e:
        print(f"[!] Could not get IP/netmask for {iface}: {e}")
        return set()

    try:
        import ipaddress
        network = ipaddress.IPv4Network(f"{iface_ip}/{iface_netmask}", strict=False)
    except Exception as e:
        print(f"[!] Error calculating network range: {e}")
        return set()

    macs_found = set()
    network24 = ipaddress.IPv4Network(f"{iface_ip}/24", strict=False)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(network24))
    ans, unans = srp(pkt, timeout=timeout, iface=iface, verbose=False)

    for snd, rcv in ans:
        mac = rcv.hwsrc.lower()
        macs_found.add(mac)

    print(f"[*] Found {len(macs_found)} unique MAC addresses nearby.")
    return macs_found

def input_mac(valid_macs):
    mac_pattern = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
    while True:
        mac = input("\nEnter the target MAC address (format XX:XX:XX:XX:XX:XX): ").strip().lower()
        if not mac_pattern.match(mac):
            print("[!] Invalid MAC address format.")
            retry = input("Try again? (y/n): ").strip().lower()
            if retry != 'y':
                print("[!] Exiting due to invalid MAC input.")
                exit(1)
            continue
        if mac not in valid_macs:
            print("[!] MAC address not found nearby.")
            print("Nearby MAC addresses detected:")
            for m in sorted(valid_macs):
                print(f" - {m}")
            retry = input("Try a different MAC? (y/n): ").strip().lower()
            if retry != 'y':
                print("[!] Exiting due to invalid MAC input.")
                exit(1)
            continue
        return mac

def input_int(prompt, min_val=None, max_val=None):
    while True:
        val = input(prompt).strip()
        if not val.isdigit():
            print("[!] Invalid input: please enter a valid integer.")
            retry = input("Try again? (y/n): ").strip().lower()
            if retry != 'y':
                print("[!] Exiting due to invalid input.")
                exit(1)
            continue
        iv = int(val)
        if (min_val is not None and iv < min_val) or (max_val is not None and iv > max_val):
            print(f"[!] Input must be between {min_val} and {max_val}.")
            retry = input("Try again? (y/n): ").strip().lower()
            if retry != 'y':
                print("[!] Exiting due to invalid input.")
                exit(1)
            continue
        return iv

def generate_payload(length):
    return b"A" * length

def main():
    iface = select_interface()
    valid_macs = scan_nearby_macs(iface)
    if not valid_macs:
        print("[!] Warning: No MAC addresses found nearby. You may not be able to validate the target MAC properly.")

    target_mac = input_mac(valid_macs) if valid_macs else input("\nEnter the target MAC address (any format will be accepted): ").strip().lower()

    print("\nSpecify payload size range (bytes):")
    start_size = input_int("Start size (e.g. 10): ", min_val=1)
    end_size = input_int("End size (e.g. 300): ", min_val=start_size)
    step_size = input_int("Step size (e.g. 10): ", min_val=1)

    print(f"\n[*] Starting to send frames on interface {iface} to target MAC {target_mac}...")

    for size in range(start_size, end_size + 1, step_size):
        payload = generate_payload(size)
        src_mac = RandMAC()
        ether = Ether(dst=target_mac, src=src_mac, type=0x1234)
        frame = ether / payload

        sendp(frame, iface=iface, verbose=False)
        print(f"[+] Sent payload size: {size} bytes")

        time.sleep(0.5)

    print("\n[*] Finished sending packets.")

if __name__ == "__main__":
    main()
