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
                check_spf_dns_lookup_count(spf_record, domain)
                check_spf_record_length(rdata)
                return
        print(f"{RED}No SPF record found for {domain}.{RESET}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"{RED}No DNS records found for {domain}.{RESET}")
    except Exception as e:
        print(f"{RED}An error occurred: {e}{RESET}")


# SPF DNS Lookup Count Checker (max 10, including child lookups)
def count_spf_lookups(spf_record, visited=None):
    """Recursively count DNS lookups in an SPF record, following includes and redirects."""
    if visited is None:
        visited = set()

    lookup_count = 0
    # Mechanisms that require a DNS lookup
    dns_mechanisms = ('include:', 'a:', 'a ', 'a\t', 'mx:', 'mx ', 'mx\t',
                      'ptr:', 'ptr ', 'ptr\t', 'exists:', 'redirect=')

    terms = spf_record.split()
    for term in terms:
        term_lower = term.lower().lstrip('+-?~')

        # Handle 'a' and 'mx' with no argument (lookup on current domain)
        if term_lower in ('a', 'mx', 'ptr'):
            lookup_count += 1

        elif term_lower.startswith('include:'):
            lookup_count += 1
            child_domain = term_lower[len('include:'):]
            if child_domain not in visited:
                visited.add(child_domain)
                child_record = _fetch_spf_record(child_domain)
                if child_record:
                    lookup_count += count_spf_lookups(child_record, visited)

        elif term_lower.startswith('redirect='):
            lookup_count += 1
            redirect_domain = term_lower[len('redirect='):]
            if redirect_domain not in visited:
                visited.add(redirect_domain)
                child_record = _fetch_spf_record(redirect_domain)
                if child_record:
                    lookup_count += count_spf_lookups(child_record, visited)

        elif term_lower.startswith('a:') or term_lower.startswith('mx:') or \
             term_lower.startswith('ptr:') or term_lower.startswith('exists:'):
            lookup_count += 1

    return lookup_count


def _fetch_spf_record(domain):
    """Helper to fetch an SPF TXT record for a domain. Returns the record string or None."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            record = ''.join([s.decode() for s in rdata.strings])
            if record.startswith('v=spf1'):
                return record
    except Exception:
        pass
    return None


def check_spf_dns_lookup_count(spf_record, domain):
    """Check the total DNS lookup count (including child lookups) against the RFC limit of 10."""
    print(f"\n{GREEN}--- SPF DNS Lookup Count Check ---{RESET}")
    try:
        total_lookups = count_spf_lookups(spf_record, visited={domain})
        if total_lookups > 10:
            print(f"{RED}DNS lookup count: {total_lookups} — EXCEEDS the limit of 10! "
                  f"This will cause SPF PermError and emails may fail authentication.{RESET}")
        elif total_lookups >= 8:
            print(f"{YELLOW}DNS lookup count: {total_lookups} — WARNING: Close to the limit of 10. "
                  f"Consider optimising your SPF record.{RESET}")
        else:
            print(f"{GREEN}DNS lookup count: {total_lookups} — OK (limit is 10).{RESET}")
    except Exception as e:
        print(f"{RED}Could not complete DNS lookup count check: {e}{RESET}")


# SPF Record String Length Checker (max 255 chars per string)
def check_spf_record_length(rdata):
    """Check each string in the SPF TXT record against the 255-character per-string RFC limit."""
    print(f"\n{GREEN}--- SPF Record String Length Check ---{RESET}")
    all_ok = True
    for i, txt_string in enumerate(rdata.strings):
        string_decoded = txt_string.decode()
        length = len(string_decoded)
        if length > 255:
            print(f"{RED}String {i + 1}: {length} characters — EXCEEDS the 255-character limit!{RESET}")
            print(f"  → \"{string_decoded[:60]}...\"")
            all_ok = False
        else:
            print(f"{GREEN}String {i + 1}: {length} characters — OK (limit is 255).{RESET}")
    if all_ok:
        print(f"{GREEN}All SPF record strings are within the 255-character limit.{RESET}")


# DKIM Checker
def query_dkim(domain, selector):
    try:
        dkim_domain = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for rdata in answers:
            dkim_record = ''.join([txt_string.decode() for txt_string in rdata.strings])
            print(f"{GREEN}DKIM record for {dkim_domain}:{RESET}")
            print(f"{dkim_record}")
            check_dkim_key_length(dkim_record)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"{RED}No DKIM record found for {dkim_domain}.{RESET}")
    except Exception as e:
        print(f"{RED}An error occurred: {e}{RESET}")


# DKIM Public Key Length Checker
def check_dkim_key_length(dkim_record):
    """Extract and check the bit length of the DKIM public key."""
    import base64

    print(f"\n{GREEN}--- DKIM Public Key Length Check ---{RESET}")
    try:
        # Extract the base64-encoded public key from the p= tag
        p_value = None
        for tag in dkim_record.split(';'):
            tag = tag.strip()
            if tag.startswith('p='):
                p_value = tag[2:].strip()
                break

        if not p_value:
            print(f"{RED}No public key (p=) found in DKIM record.{RESET}")
            return

        if p_value == '':
            print(f"{RED}DKIM record has been revoked (p= is empty).{RESET}")
            return

        key_der = base64.b64decode(p_value)
        key_bits = _get_rsa_key_bits(key_der)

        if key_bits is None:
            print(f"{YELLOW}Could not determine key length (key may not be RSA or uses an unsupported format).{RESET}")
            return

        if key_bits < 1024:
            print(f"{RED}Key length: {key_bits} bits — CRITICALLY WEAK. "
                  f"Keys under 1024 bits are insecure and likely to be rejected.{RESET}")
        elif key_bits < 2048:
            print(f"{YELLOW}Key length: {key_bits} bits — WEAK WARNING. "
                  f"1024-bit keys are deprecated; upgrade to 2048 bits or higher.{RESET}")
        elif key_bits >= 4096:
            print(f"{GREEN}Key length: {key_bits} bits — STRONG (4096-bit key).{RESET}")
        else:
            print(f"{GREEN}Key length: {key_bits} bits — OK (recommended minimum is 2048 bits).{RESET}")

    except Exception as e:
        print(f"{RED}Could not check DKIM key length: {e}{RESET}")


def _get_rsa_key_bits(der_bytes):
    """Parse a DER-encoded SubjectPublicKeyInfo structure and return the RSA modulus bit length."""

    def parse_der_length(data, offset):
        first = data[offset]
        offset += 1
        if first & 0x80 == 0:
            return first, offset
        num_bytes = first & 0x7f
        length = int.from_bytes(data[offset:offset + num_bytes], 'big')
        return length, offset + num_bytes

    def skip_sequence_header(data, offset):
        assert data[offset] == 0x30, "Expected SEQUENCE tag"
        offset += 1
        _, offset = parse_der_length(data, offset)
        return offset

    def skip_algorithm_identifier(data, offset):
        assert data[offset] == 0x30, "Expected AlgorithmIdentifier SEQUENCE"
        offset += 1
        length, offset = parse_der_length(data, offset)
        return offset + length

    def parse_bit_string_content(data, offset):
        assert data[offset] == 0x03, "Expected BIT STRING tag"
        offset += 1
        length, offset = parse_der_length(data, offset)
        # First byte is the count of unused bits in the final byte
        return data[offset + 1: offset + length]

    try:
        offset = 0
        offset = skip_sequence_header(der_bytes, offset)       # SubjectPublicKeyInfo SEQUENCE
        offset = skip_algorithm_identifier(der_bytes, offset)  # AlgorithmIdentifier
        rsa_key_bytes = parse_bit_string_content(der_bytes, offset)  # BIT STRING → RSAPublicKey

        # RSAPublicKey is itself a DER SEQUENCE { INTEGER modulus, INTEGER publicExponent }
        offset = 0
        offset = skip_sequence_header(rsa_key_bytes, offset)

        assert rsa_key_bytes[offset] == 0x02, "Expected INTEGER tag for modulus"
        offset += 1
        modulus_length, offset = parse_der_length(rsa_key_bytes, offset)

        modulus_bytes = rsa_key_bytes[offset: offset + modulus_length]
        if modulus_bytes[0] == 0x00:   # strip DER sign byte
            modulus_bytes = modulus_bytes[1:]

        return len(modulus_bytes) * 8

    except Exception:
        return None


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