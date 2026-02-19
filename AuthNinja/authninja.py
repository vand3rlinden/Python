import hashlib
import dns.resolver
import pyfiglet
from colorama import Fore, Style

# ANSI escape codes for colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
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
            spf_record = ''.join([txt_string.decode() for txt_string in rdata.strings])
            if spf_record.startswith("v=spf1"):
                print(f"{GREEN}SPF record for {domain}:{RESET}")
                print(f"{spf_record}")
                return
        print(f"{RED}No SPF record found for {domain}.{RESET}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"{RED}No DNS records found for {domain}.{RESET}")
    except Exception as e:
        print(f"{RED}An error occurred: {e}{RESET}")


# DKIM Checker
def query_dkim(domain, selector):
    try:
        dkim_domain = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for rdata in answers:
            dkim_record = ''.join([txt_string.decode() for txt_string in rdata.strings])
            print(f"{GREEN}DKIM record for {dkim_domain}:{RESET}")
            print(f"{dkim_record}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"{RED}No DKIM record found for {dkim_domain}.{RESET}")
    except Exception as e:
        print(f"{RED}An error occurred: {e}{RESET}")


# DMARC Checker
def query_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            dmarc_record = ''.join([txt_string.decode() for txt_string in rdata.strings])
            print(f"{GREEN}DMARC record for {dmarc_domain}:{RESET}")
            print(f"{dmarc_record}")
            if 'p=reject' in dmarc_record:
                print(f"{GREEN}Domain is DMARC compliant - protected against abuse.{RESET}")
            elif 'p=quarantine' in dmarc_record:
                print(f"{YELLOW}Domain is partially DMARC compliant.{RESET}")
            else:
                print(f"{RED}Domain is not DMARC compliant.{RESET}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"{RED}No DMARC record found for {domain}.{RESET}")
    except Exception as e:
        print(f"{RED}An error occurred: {e}{RESET}")


# MTA-STS Checker
def query_mta_sts(domain):
    try:
        mta_sts_domain = f"_mta-sts.{domain}"
        answers = dns.resolver.resolve(mta_sts_domain, 'TXT')
        for rdata in answers:
            mta_sts_record = ''.join([txt_string.decode() for txt_string in rdata.strings])
            print(f"{GREEN}MTA-STS record for {domain}:{RESET}")
            print(f"{mta_sts_record}")
            print(f"Policy URL: {GREEN}https://mta-sts.{domain}/.well-known/mta-sts.txt{RESET}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"{RED}No MTA-STS record found for {domain}.{RESET}")
    except Exception as e:
        print(f"{RED}An error occurred: {e}{RESET}")


# TLSRPT Checker (used by MTA-STS & DANE)
def query_tlsrpt(domain):
    try:
        tlsrpt_domain = f"_smtp._tls.{domain}"
        answers = dns.resolver.resolve(tlsrpt_domain, 'TXT')
        for rdata in answers:
            tlsrpt_record = ''.join([txt_string.decode() for txt_string in rdata.strings])
            print(f"{GREEN}TLSRPT record for {domain}:{RESET}")
            print(f"{tlsrpt_record}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"{RED}No TLSRPT record found for {domain}.{RESET}")
    except Exception as e:
        print(f"{RED}An error occurred: {e}{RESET}")


# SMTP DANE Checker
def query_smtp_dane(domain):
    try:
        # First resolve the MX record
        mx_answers = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_answers[0].exchange).rstrip('.')

        if not mx_record:
            print(f"{RED}No MX record found for {domain}.{RESET}")
            return

        # Look up the TLSA record for port 25
        tlsa_domain = f"_25._tcp.{mx_record}"
        try:
            tlsa_answers = dns.resolver.resolve(tlsa_domain, 'TLSA')
            print(f"{GREEN}SMTP DANE TLSA records for MX: {mx_record}{RESET}")
            for rdata in tlsa_answers:
                print(f"{rdata}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(f"{RED}No SMTP DANE TLSA records found for {domain}.{RESET}")

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"{RED}No MX record found for {domain}.{RESET}")
    except Exception as e:
        print(f"{RED}An error occurred: {e}{RESET}")


# Menu
def menu():
    while True:
        print(f"\n{GREEN}AuthNinja Query Menu:{RESET}")
        print(f"1. Query SPF Record")
        print(f"2. Query DKIM Record")
        print(f"3. Query DMARC Record")
        print(f"4. Query MTA-STS Record")
        print(f"5. Query SMTP DANE Record")
        print(f"6. Exit")

        choice = input(f"{GREEN}Please choose an option (1-6): {RESET}")

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
            domain = input(f"{GREEN}Enter the domain name: {RESET}")
            query_mta_sts(domain)
            query_tlsrpt(domain)
        elif choice == '5':
            domain = input(f"{GREEN}Enter the domain name: {RESET}")
            query_smtp_dane(domain)
            query_tlsrpt(domain)
        elif choice == '6':
            print(f"{GREEN}Exiting AuthNinja...{RESET}")
            break
        else:
            print(f"{RED}Invalid choice. Please select a valid option.{RESET}")


if __name__ == "__main__":
    menu()