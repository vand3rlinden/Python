import hashlib
import requests
import pyfiglet
from colorama import Fore, Style

# Add your API keys here
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"
SCAMALYTICS_API_KEY = "your_scamalytics_api_key"
SCAMALYTICS_USERNAME = "your_scamalytics_username"

# ANSI escape codes for colors
GREEN = "\033[92m"
RESET = "\033[0m"

# Generate ASCII art
ascii_art = pyfiglet.figlet_format("ThreatHunterX")

# Display the ASCII art in green
print(Fore.GREEN + ascii_art + Style.RESET_ALL)

# Menu
def print_menu():
    print(f"\n{GREEN}Menu:{RESET}")
    print("1. Scan URL with VirusTotal")
    print("2. Scan File Hash with VirusTotal")
    print("3. Scan IP Address with AbuseIPDB")
    print("4. Scan IP Address with Scamalytics")
    print("5. Exit")

# VirusTotal
def format_virustotal_result(result):
    print(f"{GREEN}VirusTotal Scan Results{RESET}")
    scan_date = result.get('scan_date', 'N/A')
    positives = result.get('positives', 0)
    total = result.get('total', 0)
    permalink = result.get('permalink', 'N/A')

    print(f"{GREEN}Scan Date:{RESET} {scan_date}")
    print(f"{GREEN}Positives:{RESET} {positives} out of {total} security vendors flagged this entry as malicious")
    print(f"{GREEN}Permalink to Full Report:{RESET} {permalink}")

    if 'scans' in result:
        print(f"{GREEN}Detailed Scan Results:{RESET}")
        for vendor, scan_info in result['scans'].items():
            print(f"  {GREEN}{vendor}:{RESET} Detected: {scan_info.get('detected', False)}, "
                  f"Result: {scan_info.get('result', 'Clean')}")

def scan_url_virustotal(url):
    print(f"{GREEN}Scanning URL with VirusTotal{RESET}")
    api_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}

    response = requests.get(api_url, params=params)
    if response.status_code == 200:
        result = response.json()
        format_virustotal_result(result)
    else:
        print(f"Error: {response.status_code} - {response.text}")

def scan_file_hash_virustotal(file_hash):
    print(f"{GREEN}Scanning File Hash with VirusTotal{RESET}")
    api_url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}

    response = requests.get(api_url, params=params)
    if response.status_code == 200:
        result = response.json()
        format_virustotal_result(result)
    else:
        print(f"Error: {response.status_code} - {response.text}")

# AbuseIPDB
def scan_ip_abuseipdb(ip_address):
    print(f"{GREEN}Scanning IP Address with AbuseIPDB{RESET}")
    api_url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip_address, 'maxAgeInDays': 90}

    response = requests.get(api_url, headers=headers, params=params)
    if response.status_code == 200:
        result = response.json()['data']
        print(f"{GREEN}AbuseIPDB Scan Results{RESET}")
        print(f"{GREEN}IP Address:{RESET} {result.get('ipAddress')}")
        print(f"{GREEN}Is Public:{RESET} {result.get('isPublic')}")
        print(f"{GREEN}IP Version:{RESET} {result.get('ipVersion')}")
        print(f"{GREEN}Country Code:{RESET} {result.get('countryCode')}")
        print(f"{GREEN}ISP:{RESET} {result.get('isp')}")
        print(f"{GREEN}Domain:{RESET} {result.get('domain')}")
        print(f"{GREEN}Hostnames:{RESET} {', '.join(result.get('hostnames', []))}")
        print(f"{GREEN}Total Reports:{RESET} {result.get('totalReports')}")
        print(f"{GREEN}Last Reported:{RESET} {result.get('lastReportedAt')}")
        print(f"{GREEN}Abuse Confidence Score:{RESET} {result.get('abuseConfidenceScore')}")
        print(f"{GREEN}Usage Type:{RESET} {result.get('usageType')}")
    else:
        print(f"Error: {response.status_code} - {response.text}")

# Scamalytics
def scan_ip_scamalytics(ip_address):
    print(f"{GREEN}Scanning IP Address with Scamalytics{RESET}")
    api_url = f"https://api12.scamalytics.com/{SCAMALYTICS_USERNAME}/?key={SCAMALYTICS_API_KEY}&ip={ip_address}"

    response = requests.get(api_url)
    if response.status_code == 200:
        result = response.json()
        print(f"{GREEN}Scamalytics Scan Results {RESET}")
        print(f"{GREEN}IP Address:{RESET} {result.get('ip')}")
        print(f"{GREEN}Risk Score:{RESET} {result.get('score')}")
        print(f"{GREEN}Risk Level:{RESET} {result.get('risk')}")
        print(f"{GREEN}URL:{RESET} {result.get('url')}")
        print(f"Operator:")
        print(f"{GREEN}ASN:{RESET} {result.get('as_number')}")
        print(f"{GREEN}ISP:{RESET} {result.get('ISP Name')}")
        print(f"{GREEN}ISP Fraud Score:{RESET} {result.get('ISP Fraud Score')}")
        print(f"{GREEN}Organization Name:{RESET} {result.get('Organization Name')}")
        print(f"{GREEN}Connection Type:{RESET} {result.get('connection_type')}")
        print(f"Location:")
        print(f"{GREEN}Country Name:{RESET} {result.get('ip_country_name')}")
        print(f"{GREEN}Country Code:{RESET} {result.get('ip_country_code')}")
        print(f"{GREEN}State / Province:{RESET} {result.get('ip_state_name')}")
        print(f"{GREEN}City:{RESET} {result.get('ip_city')}")
        print(f"{GREEN}Postal Code:{RESET} {result.get('ip_postcode')}")
        print(f"{GREEN}Geo Location:{RESET} {result.get('ip_geolocation')}")
        print(f"Proxies:")
        print(f"{GREEN}Proxy Type:{RESET} {result.get('proxy_type')}")
    else:
        print(f"Error: {response.status_code} - {response.text}")

# Input menu
def main():
    while True:
        print_menu()
        choice = input(f"{GREEN}Enter your choice: {RESET}")

        if choice == "1":
            url = input(f"{GREEN}Enter URL to scan: {RESET}")
            scan_url_virustotal(url)
        elif choice == "2":
            file_hash = input(f"{GREEN}Enter File Hash to scan: {RESET}")
            scan_file_hash_virustotal(file_hash)
        elif choice == "3":
            ip_address = input(f"{GREEN}Enter IP address to scan with AbuseIPDB: {RESET}")
            scan_ip_abuseipdb(ip_address)
        elif choice == "4":
            ip_address = input(f"{GREEN}Enter IP address to scan with Scamalytics: {RESET}")
            scan_ip_scamalytics(ip_address)
        elif choice == "5":
            print(f"{GREEN}Exiting...{RESET}")
            break
        else:
            print(f"{GREEN}Invalid choice. Please try again.{RESET}")

if __name__ == "__main__":
    main()