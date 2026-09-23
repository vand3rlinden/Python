import sys
import urllib.parse
import pyfiglet

try:
    import termios
    import tty
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False

# ANSI escape codes
GREEN = "\033[92m"
RESET = "\033[0m"

def read_long_line(prompt=""):
    """Read a line of input without the terminal's canonical-mode line
    length cap (MAX_CANON, 1024 bytes on macOS), which truncates/mangles
    long pasted URLs when read via input()."""
    if not HAS_TERMIOS or not sys.stdin.isatty():
        return input(prompt)

    sys.stdout.write(prompt)
    sys.stdout.flush()

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    buf = []
    try:
        tty.setcbreak(fd)
        # Disable bracketed paste so the terminal doesn't wrap pasted
        # content in \x1b[200~ / \x1b[201~ markers that would otherwise
        # end up embedded in the captured string.
        sys.stdout.write("\x1b[?2004l")
        sys.stdout.flush()
        while True:
            ch = sys.stdin.read(1)
            if ch in ("\n", "\r"):
                sys.stdout.write("\n")
                break
            elif ch == "\x7f":  # backspace
                if buf:
                    buf.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
            elif ch == "\x03":  # Ctrl-C
                raise KeyboardInterrupt
            elif ch == "":  # EOF
                break
            else:
                buf.append(ch)
                sys.stdout.write(ch)
                sys.stdout.flush()
    finally:
        sys.stdout.write("\x1b[?2004h")
        sys.stdout.flush()
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    return "".join(buf).strip()

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
    print("2. Exit - No Safelink URL to decode")

    choice = input("Enter your choice (1/2): ").strip()

    if choice == "1":
        url = read_long_line("Paste the Safelink URL: ")
        decode_safelink(url)
    elif choice == "2":
        print("Goodbye (:")
        sys.exit(0)
    else:
        print("Invalid choice. Try again.")
        main_menu()

if __name__ == "__main__":
    main_menu()
