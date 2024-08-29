import hashlib
import dns.resolver
import pyfiglet
from colorama import Fore, Style

# ANSI escape codes for colors
GREEN = "\033[92m"
RESET = "\033[0m"

# Generate ASCII art
ascii_art = pyfiglet.figlet_format("AuthNinja")

# Display the ASCII art in green
print(Fore.GREEN + ascii_art + Style.RESET_ALL)

# SPF Checker
def query_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            # Concatenate all strings within the TXT record (DNS TXT records are limited to 255 characters per string)
            spf_record = ''.join([txt_string.decode() for txt_string in rdata.strings])
            if spf_record.startswith("v=spf1"):
                print(f"{GREEN}SPF record for {domain}:{RESET}")
                print(f"{spf_record}")
                return
        print(f"{GREEN}No SPF record found for {domain}.{RESET}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"{GREEN}No DNS records found for {domain}.{RESET}")
    except Exception as e:
        print(f"{GREEN}An error occurred: {e}{RESET}")

# DKIM Checker
def query_dkim(domain, selector):
    try:
        dkim_domain = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for rdata in answers:
            # Concatenate all strings within the TXT record (DNS TXT records are limited to 255 characters per string)
            dkim_record = ''.join([txt_string.decode() for txt_string in rdata.strings])
            print(f"{GREEN}DKIM record for {dkim_domain}:{RESET}")
            print(f"{dkim_record}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"{GREEN}No DKIM record found for {dkim_domain}.{RESET}")
    except Exception as e:
        print(f"{GREEN}An error occurred: {e}{RESET}")

# DMARC Checker
def query_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            dmarc_record = rdata.to_text()
            print(f"{GREEN}DMARC record for {dmarc_domain}:{RESET}")
            print(f"{dmarc_record}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"{GREEN}No DMARC record found for {dmarc_domain}.{RESET}")
    except Exception as e:
        print(f"{GREEN}An error occurred: {e}{RESET}")

# Menu
def menu():
    while True:
        print(f"\n{GREEN}AuthNinja Query Menu:{RESET}")
        print(f"1. Query SPF Record")
        print(f"2. Query DKIM Record")
        print(f"3. Query DMARC Record")
        print(f"4. Exit")
        choice = input(f"{GREEN}Please choose an option (1-4): {RESET}")

        if choice == '1':
            domain = input(f"{GREEN}Enter the domain name: {RESET}")
            query_spf(domain)
        elif choice == '2':
            domain = input(f"{GREEN}Enter the domain name: {RESET}")
            selector = input(f"{GREEN}Enter the DKIM selector: {RESET}")
            query_dkim(domain, selector)
        elif choice == '3':
            domain = input(f"{GREEN}Enter the domain name: {RESET}")
            query_dmarc(domain)
        elif choice == '4':
            print(f"{GREEN}Exiting...{RESET}")
            break
        else:
            print(f"{GREEN}Invalid choice. Please select a valid option.{RESET}")

if __name__ == "__main__":
    menu()