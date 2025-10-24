import sys
import urllib.parse
import pyfiglet

# ANSI escape codes
GREEN = "\033[92m"
RESET = "\033[0m"

def decode_safelink(safelink_url):
    parsed = urllib.parse.urlparse(safelink_url)
    query_params = urllib.parse.parse_qs(parsed.query)

    encoded_url = query_params.get('url', [None])[0]
    if not encoded_url:
        print("No 'url' parameter found in the Safelink.")
        return

    decoded_url = urllib.parse.unquote(encoded_url)
    print(f"{GREEN}Decoded URL:{RESET}")
    print(decoded_url)

def main_menu():
    banner = pyfiglet.figlet_format("MDO SafeLinks Decoder")
    print(GREEN + banner + RESET)
    print(f"{GREEN}Welcome to the MDO SafeLinks Decoder - by VAND3RLINDEN!{RESET}")
    print("Choose an option:")
    print("1. Decode a Safelink URL")
    print("2. Exit - No links to decode")

    choice = input("Enter your choice (1/2): ").strip()

    if choice == "1":
        url = input("Paste the Safelink URL: ").strip()
        decode_safelink(url)
    elif choice == "2":
        print("Goodbye (:")
        sys.exit(0)
    else:
        print("Invalid choice. Try again.")
        main_menu()

if __name__ == "__main__":
    main_menu()
