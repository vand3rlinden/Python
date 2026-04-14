import hashlib
import ipaddress
import pyfiglet
from colorama import Fore, Style

# Generate ASCII art
ascii_art = pyfiglet.figlet_format("SubnetBuddy")

# Display the ASCII art in green
print(Fore.GREEN + ascii_art + Style.RESET_ALL)

def ip_to_int(ip):
    octets = map(int, ip.split('.'))
    return sum(octet << (8 * (3 - index)) for index, octet in enumerate(octets))

def int_to_ip(integer):
    return '.'.join(str((integer >> (8 * i)) & 0xFF) for i in reversed(range(4)))

def calculate_subnet(ip, cidr):
    ip_int = ip_to_int(ip)
    mask_int = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
    network_int = ip_int & mask_int
    broadcast_int = network_int | (~mask_int & 0xFFFFFFFF)
    range_start_int = network_int + 1
    range_end_int = broadcast_int - 1

    mask = int_to_ip(mask_int)
    network = int_to_ip(network_int)
    broadcast = int_to_ip(broadcast_int)
    range_start = int_to_ip(range_start_int)
    range_end = int_to_ip(range_end_int)

    print(f"IP Address: {ip}")
    print(f"CIDR: /{cidr}")
    print(f"Subnet Mask: {mask}")
    print(f"Network Address: {network}")
    print(f"Broadcast Address: {broadcast}")
    print(f"Usable IP Range: {range_start} - {range_end}")

def ip_to_classful_cidr(ip: str) -> int:
    """Return the classful CIDR prefix for an IP address based on its class."""
    first_octet = int(ip.split('.')[0])
    if 1 <= first_octet <= 126:
        return 8   # Class A
    elif 128 <= first_octet <= 191:
        return 16  # Class B
    elif 192 <= first_octet <= 223:
        return 24  # Class C
    else:
        raise ValueError(f"Cannot determine classful network for {ip} (not a valid unicast address).")


def mask_to_cidr(mask: str) -> int:
    """Convert a dotted-decimal subnet mask to a CIDR prefix length."""
    mask_int = ip_to_int(mask)
    # Count leading 1-bits
    cidr = bin(mask_int).count('1')
    # Validate: a valid mask has no 0-bits followed by 1-bits
    if mask_int != (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF:
        raise ValueError(f"Invalid subnet mask: {mask}")
    return cidr


def main_menu():
    GREEN = '\033[32m'
    END = '\033[0m'

    while True:
        print(f"\n{GREEN}Subnet Calculator Menu{END}")
        print(f"{GREEN}1. IP + CIDR prefix  (e.g., 192.168.1.1/24){END}")
        print(f"{GREEN}2. IP + subnet mask  (e.g., 192.168.1.228/255.255.255.0){END}")
        print(f"{GREEN}3. IP only           (e.g., 192.168.1.228 — classful detection){END}")
        choice = input(f"{GREEN}Choose mode (1/2/3): {END}").strip()

        if choice == '1':
            subnet = input(f"{GREEN}Enter IP address with CIDR (e.g., 192.168.1.1/24): {END}")
            try:
                ip, cidr_str = subnet.split('/')
                cidr = int(cidr_str)
                if cidr < 0 or cidr > 32:
                    raise ValueError
                calculate_subnet(ip, cidr)
            except ValueError:
                print("Invalid input. Please enter a valid IP/CIDR like 192.168.1.1/24.")

        elif choice == '2':
            entry = input(f"{GREEN}Enter IP address with subnet mask (e.g., 192.168.1.228/255.255.255.0): {END}")
            try:
                ip, mask = entry.split('/')
                cidr = mask_to_cidr(mask.strip())
                calculate_subnet(ip.strip(), cidr)
            except ValueError as e:
                print(f"Invalid input: {e}. Please enter a valid IP/mask like 192.168.1.228/255.255.255.0.")

        elif choice == '3':
            ip = input(f"{GREEN}Enter IP address (e.g., 192.168.1.228): {END}").strip()
            try:
                cidr = ip_to_classful_cidr(ip)
                print(f"Detected class: Class {'A' if cidr == 8 else 'B' if cidr == 16 else 'C'} -> /{cidr}")
                calculate_subnet(ip, cidr)
            except ValueError as e:
                print(f"Invalid input: {e}")

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

        again = input(f"\n{GREEN}Do you want to calculate another subnet? (y/n): {END}").lower()
        if again != 'y':
            print("Exiting SubnetBuddy")
            break

if __name__ == "__main__":
    main_menu()