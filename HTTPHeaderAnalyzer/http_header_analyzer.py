import requests
import pyfiglet
from colorama import Fore, Style

# ANSI escape codes for colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

# Generate ASCII art
ascii_art = pyfiglet.figlet_format("HeaderAnalyzer")

# Display the ASCII art in green
print(Fore.GREEN + ascii_art + Style.RESET_ALL)


def fetch_headers(url):
    """Fetch HTTP response headers from the given URL. Returns headers dict or None."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        print(f"\n{GREEN}Fetched headers from: {response.url} (HTTP {response.status_code}){RESET}")
        return {k.lower(): v for k, v in response.headers.items()}
    except requests.exceptions.SSLError:
        print(f"{RED}SSL error connecting to {url}. Try with http:// if the site lacks HTTPS.{RESET}")
    except requests.exceptions.ConnectionError:
        print(f"{RED}Could not connect to {url}. Check the URL and your network connection.{RESET}")
    except requests.exceptions.Timeout:
        print(f"{RED}Request to {url} timed out.{RESET}")
    except Exception as e:
        print(f"{RED}An error occurred: {e}{RESET}")
    return None


# Strict-Transport-Security
def analyze_hsts(headers):
    print(f"\n{GREEN}--- Strict-Transport-Security ---{RESET}")
    value = headers.get("strict-transport-security")
    if not value:
        print(f"{RED}MISSING: Strict-Transport-Security header not found.{RESET}")
        print(f"{YELLOW}Tip: Add this header to enforce HTTPS. Recommended value:{RESET}")
        print(f"{YELLOW}  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload{RESET}")
        return

    print(f"{GREEN}Present:{RESET} {value}")
    directives = [d.strip().lower() for d in value.split(";")]

    max_age = None
    for directive in directives:
        if directive.startswith("max-age="):
            try:
                max_age = int(directive.split("=", 1)[1])
            except ValueError:
                print(f"{RED}max-age value is not a valid integer.{RESET}")
    if max_age is None:
        print(f"{RED}max-age directive is missing — browsers will ignore this header.{RESET}")
    elif max_age < 31536000:
        print(f"{YELLOW}max-age is {max_age} seconds — recommended minimum is 31536000 (1 year).{RESET}")
    else:
        print(f"{GREEN}max-age: {max_age} seconds — OK.{RESET}")

    if "includesubdomains" in directives:
        print(f"{GREEN}includeSubDomains: present — subdomains are also protected.{RESET}")
    else:
        print(f"{YELLOW}includeSubDomains: missing — subdomains may be reachable over HTTP.{RESET}")

    if "preload" in directives:
        print(f"{GREEN}preload: present — eligible for HSTS preload list.{RESET}")
    else:
        print(f"{YELLOW}preload: missing — consider adding to qualify for browser preload lists.{RESET}")


# Content-Security-Policy
def analyze_csp(headers):
    print(f"\n{GREEN}--- Content-Security-Policy ---{RESET}")
    value = headers.get("content-security-policy")
    if not value:
        print(f"{RED}MISSING: Content-Security-Policy header not found.{RESET}")
        print(f"{YELLOW}Tip: A CSP restricts what resources browsers can load, mitigating XSS attacks.{RESET}")
        print(f"{YELLOW}  Example: Content-Security-Policy: default-src 'self'; script-src 'self'{RESET}")
        return

    print(f"{GREEN}Present:{RESET} {value}")
    directives = [d.strip().lower() for d in value.split(";")]
    directive_names = [d.split()[0] for d in directives if d]

    if "default-src" not in directive_names:
        print(f"{YELLOW}default-src: missing — consider adding as a catch-all fallback directive.{RESET}")
    else:
        print(f"{GREEN}default-src: present.{RESET}")

    if any("'unsafe-inline'" in d for d in directives):
        print(f"{RED}'unsafe-inline' detected — allows inline scripts/styles, weakening XSS protection.{RESET}")

    if any("'unsafe-eval'" in d for d in directives):
        print(f"{RED}'unsafe-eval' detected — allows eval(), a common XSS vector.{RESET}")

    if not any("'unsafe-inline'" in d or "'unsafe-eval'" in d for d in directives):
        print(f"{GREEN}No unsafe directives detected.{RESET}")


# Referrer-Policy
def analyze_referrer_policy(headers):
    print(f"\n{GREEN}--- Referrer-Policy ---{RESET}")
    value = headers.get("referrer-policy")
    if not value:
        print(f"{RED}MISSING: Referrer-Policy header not found.{RESET}")
        print(f"{YELLOW}Tip: Without this header, browsers default to sending the full referrer URL, "
              f"which may leak sensitive path information.{RESET}")
        print(f"{YELLOW}  Recommended: Referrer-Policy: strict-origin-when-cross-origin{RESET}")
        return

    print(f"{GREEN}Present:{RESET} {value}")
    strict_values = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "same-origin",
    }
    loose_values = {"unsafe-url", "origin-when-cross-origin"}
    policy = value.strip().lower()

    if policy in strict_values:
        print(f"{GREEN}Policy '{value}' — good, limits referrer data exposure.{RESET}")
    elif policy in loose_values:
        print(f"{YELLOW}Policy '{value}' — may expose full URLs to third parties. "
              f"Consider 'strict-origin-when-cross-origin'.{RESET}")
    else:
        print(f"{YELLOW}Policy '{value}' — unrecognised or browser-default behaviour may apply.{RESET}")


# X-Frame-Options
def analyze_x_frame_options(headers):
    print(f"\n{GREEN}--- X-Frame-Options ---{RESET}")
    value = headers.get("x-frame-options")
    if not value:
        print(f"{RED}MISSING: X-Frame-Options header not found.{RESET}")
        print(f"{YELLOW}Tip: Without this header, the page can be embedded in iframes, "
              f"enabling clickjacking attacks.{RESET}")
        print(f"{YELLOW}  Recommended: X-Frame-Options: DENY  (or use CSP frame-ancestors instead){RESET}")
        return

    print(f"{GREEN}Present:{RESET} {value}")
    upper = value.strip().upper()
    if upper == "DENY":
        print(f"{GREEN}DENY — page cannot be embedded in any frame.{RESET}")
    elif upper == "SAMEORIGIN":
        print(f"{GREEN}SAMEORIGIN — page can only be framed by the same origin.{RESET}")
    elif upper.startswith("ALLOW-FROM"):
        print(f"{YELLOW}ALLOW-FROM is deprecated and ignored by most modern browsers. "
              f"Use CSP 'frame-ancestors' instead.{RESET}")
    else:
        print(f"{YELLOW}Unrecognised value '{value}' — browsers may ignore this header.{RESET}")


# X-Content-Type-Options
def analyze_x_content_type_options(headers):
    print(f"\n{GREEN}--- X-Content-Type-Options ---{RESET}")
    value = headers.get("x-content-type-options")
    if not value:
        print(f"{RED}MISSING: X-Content-Type-Options header not found.{RESET}")
        print(f"{YELLOW}Tip: Without 'nosniff', browsers may MIME-sniff responses, "
              f"allowing content-type confusion attacks.{RESET}")
        print(f"{YELLOW}  Recommended: X-Content-Type-Options: nosniff{RESET}")
        return

    print(f"{GREEN}Present:{RESET} {value}")
    if value.strip().lower() == "nosniff":
        print(f"{GREEN}nosniff — browsers will honour the declared Content-Type.{RESET}")
    else:
        print(f"{YELLOW}Unrecognised value '{value}'. The only valid value is 'nosniff'.{RESET}")


# Permissions-Policy
def analyze_permissions_policy(headers):
    print(f"\n{GREEN}--- Permissions-Policy ---{RESET}")
    value = headers.get("permissions-policy")
    if not value:
        print(f"{RED}MISSING: Permissions-Policy header not found.{RESET}")
        print(f"{YELLOW}Tip: Without this header, the browser applies default access to powerful APIs "
              f"(camera, microphone, geolocation). Explicitly disabling unused features reduces attack surface.{RESET}")
        print(f"{YELLOW}  Example: Permissions-Policy: geolocation=(), microphone=(), camera=(){RESET}")
        return

    print(f"{GREEN}Present:{RESET} {value}")
    features = [f.strip() for f in value.split(",") if f.strip()]
    disabled = [f for f in features if f.endswith("=()")]
    enabled = [f for f in features if not f.endswith("=()")]

    if disabled:
        print(f"{GREEN}Disabled features ({len(disabled)}): {', '.join(disabled)}{RESET}")
    if enabled:
        print(f"{YELLOW}Permitted features ({len(enabled)}): {', '.join(enabled)} — review if all are needed.{RESET}")
    if not disabled and not enabled:
        print(f"{YELLOW}Policy is present but appears empty.{RESET}")


def analyze_all_headers(url):
    headers = fetch_headers(url)
    if headers is None:
        return
    analyze_hsts(headers)
    analyze_csp(headers)
    analyze_referrer_policy(headers)
    analyze_x_frame_options(headers)
    analyze_x_content_type_options(headers)
    analyze_permissions_policy(headers)


# Menu
def menu():
    while True:
        print(f"\n{GREEN}HTTP Header Analyzer Menu:{RESET}")
        print(f"1. Analyse all headers")
        print(f"2. Analyse Strict-Transport-Security")
        print(f"3. Analyse Content-Security-Policy")
        print(f"4. Analyse Referrer-Policy")
        print(f"5. Analyse X-Frame-Options")
        print(f"6. Analyse X-Content-Type-Options")
        print(f"7. Analyse Permissions-Policy")
        print(f"8. Exit")

        choice = input(f"{GREEN}Please choose an option (1-8): {RESET}")

        if choice == '1':
            url = input(f"{GREEN}Enter the URL: {RESET}")
            analyze_all_headers(url)
        elif choice == '2':
            url = input(f"{GREEN}Enter the URL: {RESET}")
            headers = fetch_headers(url)
            if headers:
                analyze_hsts(headers)
        elif choice == '3':
            url = input(f"{GREEN}Enter the URL: {RESET}")
            headers = fetch_headers(url)
            if headers:
                analyze_csp(headers)
        elif choice == '4':
            url = input(f"{GREEN}Enter the URL: {RESET}")
            headers = fetch_headers(url)
            if headers:
                analyze_referrer_policy(headers)
        elif choice == '5':
            url = input(f"{GREEN}Enter the URL: {RESET}")
            headers = fetch_headers(url)
            if headers:
                analyze_x_frame_options(headers)
        elif choice == '6':
            url = input(f"{GREEN}Enter the URL: {RESET}")
            headers = fetch_headers(url)
            if headers:
                analyze_x_content_type_options(headers)
        elif choice == '7':
            url = input(f"{GREEN}Enter the URL: {RESET}")
            headers = fetch_headers(url)
            if headers:
                analyze_permissions_policy(headers)
        elif choice == '8':
            print(f"{GREEN}Exiting HeaderScan...{RESET}")
            break
        else:
            print(f"{RED}Invalid choice. Please select a valid option.{RESET}")


if __name__ == "__main__":
    menu()
