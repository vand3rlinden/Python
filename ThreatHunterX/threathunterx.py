import hashlib
import requests
import pyfiglet
from colorama import Fore, Style

# Add your API keys here
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"

# ANSI escape codes for colors
GREEN = "\033[92m"
RESET = "\033[0m"

# Generate ASCII art
ascii_art = pyfiglet.figlet_format("ThreatHunterX")

# Display the ASCII art in green
print(Fore.GREEN + ascii_art + Style.RESET_ALL)

def print_menu():
    print(f"\n{GREEN}Menu:{RESET}")
    print("1. Scan URL with VirusTotal")
    print("2. Scan File Hash with VirusTotal")
    print("3. Scan IP Address with AbuseIPDB")
    print("4. Exit")

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
    print(f"{GREEN}Scanning URL: {url}{RESET}")
    api_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}

    response = requests.get(api_url, params=params)
    if response.status_code == 200:
        result = response.json()
        format_virustotal_result(result)
    else:
        print(f"Error: {response.status_code} - {response.text}")

def scan_file_hash_virustotal(file_hash):
    print(f"{GREEN}Scanning File Hash: {file_hash}{RESET}")
    api_url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}

    response = requests.get(api_url, params=params)
    if response.status_code == 200:
        result = response.json()
        format_virustotal_result(result)
    else:
        print(f"Error: {response.status_code} - {response.text}")

def scan_ip_abuseipdb(ip_address):
    print(f"{GREEN}Scanning IP Address: {ip_address}{RESET}")
    api_url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip_address, 'maxAgeInDays': 90}

    response = requests.get(api_url, headers=headers, params=params)
    if response.status_code == 200:
        result = response.json()['data']
        print(f"{GREEN}AbuseIPDB Scan Results for IP: {ip_address}{RESET}")
        print(f"{GREEN}IP Address:{RESET} {result.get('ipAddress')}")
        print(f"{GREEN}Is Public:{RESET} {result.get('isPublic')}")
        print(f"{GREEN}IP Version:{RESET} {result.get('ipVersion')}")
        print(f"{GREEN}Country Code:{RESET} {result.get('countryCode')}")
        print(f"{GREEN}ISP:{RESET} {result.get('isp')}")
        print(f"{GREEN}Domain:{RESET} {result.get('domain')}")
        print(f"{GREEN}Hostnames:{RESET} {', '.join(result.get('hostnames', []))}")
        print(f"{GREEN}Total Reports:{RESET} {result.get('totalReports')}")
        print(f"{GREEN}Most Recent Report:{RESET} {result.get('mostRecentReport', {}).get('reportedAt')}")
        print(f"{GREEN}Abuse Confidence Score:{RESET} {result.get('abuseConfidenceScore')}")
        print(f"{GREEN}Usage Type:{RESET} {result.get('usageType')}")
    else:
        print(f"Error: {response.status_code} - {response.text}")

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
            ip_address = input(f"{GREEN}Enter IP address to scan: {RESET}")
            scan_ip_abuseipdb(ip_address)
        elif choice == "4":
            print(f"{GREEN}Exiting...{RESET}")
            break
        else:
            print(f"{GREEN}Invalid choice. Please try again.{RESET}")

if __name__ == "__main__":
    main()
