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

def main_menu():
    GREEN = '\033[32m'
    END = '\033[0m'

    while True:
        print(f"{GREEN}Subnet Calculator Menu{END}")
        subnet = input(f"{GREEN}Enter IP address with CIDR (e.g., 192.168.1.1/24): {END}")
        try:
            ip, cidr = subnet.split('/')
            cidr = int(cidr)
            if cidr < 0 or cidr > 32:
                raise ValueError
            calculate_subnet(ip, cidr)
        except ValueError:
            print("Invalid input. Please enter a valid IP address with CIDR.")
        
        again = input(f"{GREEN}Do you want to calculate another subnet? (y/n): {END}").lower()
        if again != 'y':
            print("Exiting SubnetBuddy")
            break

if __name__ == "__main__":
    main_menu()