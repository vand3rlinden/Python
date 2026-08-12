import sys
import base64
import pyfiglet

# ANSI escape codes
GREEN = "\033[92m"
RESET = "\033[0m"

def encode_base64(text):
    encoded = base64.b64encode(text.encode()).decode()
    print(f"{GREEN}Encoded Base64:{RESET}")
    print(encoded)

def decode_base64(text):
    try:
        decoded = base64.b64decode(text.encode()).decode()
        print(f"{GREEN}Decoded Text:{RESET}")
        print(decoded)
    except Exception as e:
        print(f"Failed to decode Base64: {e}")

def main_menu():
    banner = pyfiglet.figlet_format("Base64 Toolkit")
    print(GREEN + banner + RESET)
    print(f"{GREEN}Welcome to the Base64 Toolkit - by VAND3RLINDEN!{RESET}")
    print("Choose an option:")
    print("1. Decode Base64 to text")
    print("2. Encode text to Base64")
    print("3. Exit")

    choice = input("Enter your choice (1/2/3): ").strip()

    if choice == "1":
        text = input("Paste the Base64 string to decode: ").strip()
        decode_base64(text)
    elif choice == "2":
        text = input("Enter the text to encode: ").strip()
        encode_base64(text)
    elif choice == "3":
        print("Goodbye (:")
        sys.exit(0)
    else:
        print("Invalid choice. Try again.")
        main_menu()

if __name__ == "__main__":
    main_menu()