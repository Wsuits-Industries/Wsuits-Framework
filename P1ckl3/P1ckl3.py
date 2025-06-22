import requests
import argparse
import os
from datetime import datetime
from colorama import Fore, Style, init

# Init colorama
init(autoreset=True)

#banner fuction
def banner():
    print(Fore.BLUE + r"""

██╗░░██╗░█████╗░░█████╗░██╗░░██╗  ████████╗██╗░░██╗███████╗  ░██╗░░░░░░░██╗███████╗██████╗░
██║░░██║██╔══██╗██╔══██╗██║░██╔╝  ╚══██╔══╝██║░░██║██╔════╝  ░██║░░██╗░░██║██╔════╝██╔══██╗
███████║███████║██║░░╚═╝█████═╝░  ░░░██║░░░███████║█████╗░░  ░╚██╗████╗██╔╝█████╗░░██████╦╝
██╔══██║██╔══██║██║░░██╗██╔═██╗░  ░░░██║░░░██╔══██║██╔══╝░░  ░░████╔═████║░██╔══╝░░██╔══██╗
██║░░██║██║░░██║╚█████╔╝██║░╚██╗  ░░░██║░░░██║░░██║███████╗  ░░╚██╔╝░╚██╔╝░███████╗██████╦╝
╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝  ░░░╚═╝░░░╚═╝░░╚═╝╚══════╝  ░░░╚═╝░░░╚═╝░░╚══════╝╚═════╝░
          
          
█████████████████████████████████████████████████████████████████████████████████████████
█░░░░░░░░░░░░░░█░░░░░░░░███░░░░░░░░░░░░░░█░░░░░░██░░░░░░░░█░░░░░░█████████░░░░░░░░░░░░░░█
█░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀▄▀░░███░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀░░██░░▄▀▄▀░░█░░▄▀░░█████████░░▄▀▄▀▄▀▄▀▄▀░░█
█░░▄▀░░░░░░▄▀░░█░░░░▄▀░░███░░▄▀░░░░░░░░░░█░░▄▀░░██░░▄▀░░░░█░░▄▀░░█████████░░░░░░░░░░▄▀░░█
█░░▄▀░░██░░▄▀░░███░░▄▀░░███░░▄▀░░█████████░░▄▀░░██░░▄▀░░███░░▄▀░░█████████████████░░▄▀░░█
█░░▄▀░░░░░░▄▀░░███░░▄▀░░███░░▄▀░░█████████░░▄▀░░░░░░▄▀░░███░░▄▀░░█████████░░░░░░░░░░▄▀░░█
█░░▄▀▄▀▄▀▄▀▄▀░░███░░▄▀░░███░░▄▀░░█████████░░▄▀▄▀▄▀▄▀▄▀░░███░░▄▀░░█████████░░▄▀▄▀▄▀▄▀▄▀░░█
█░░▄▀░░░░░░░░░░███░░▄▀░░███░░▄▀░░█████████░░▄▀░░░░░░▄▀░░███░░▄▀░░█████████░░░░░░░░░░▄▀░░█
█░░▄▀░░███████████░░▄▀░░███░░▄▀░░█████████░░▄▀░░██░░▄▀░░███░░▄▀░░█████████████████░░▄▀░░█
█░░▄▀░░█████████░░░░▄▀░░░░█░░▄▀░░░░░░░░░░█░░▄▀░░██░░▄▀░░░░█░░▄▀░░░░░░░░░░█░░░░░░░░░░▄▀░░█
█░░▄▀░░█████████░░▄▀▄▀▄▀░░█░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀░░██░░▄▀▄▀░░█░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀▄▀▄▀▄▀▄▀░░█
█░░░░░░█████████░░░░░░░░░░█░░░░░░░░░░░░░░█░░░░░░██░░░░░░░░█░░░░░░░░░░░░░░█░░░░░░░░░░░░░░█
█████████████████████████████████████████████████████████████████████████████████████████

                                🔥 WSUITS PORT SCANNER 🔥
                                 >>> Africans Hacking <<< 
          
""")

def parse_args():
    parser = argparse.ArgumentParser(description="Wsuits Industries Directory Fuzzer - Happy Hacking")
    parser.add_argument("--url", required=True, help="Base target URL to fuzz (e.g., https://target.com/)")
    parser.add_argument("--wordlist", default="common.txt", help="Path to wordlist (default: common.txt)")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout for requests (default: 3s)")
    return parser.parse_args()

def read_wordlist(path):
    if not os.path.exists(path):
        print(Fore.RED + f"[!] Wordlist not found: {path}")
        exit(1)
    with open(path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def brute_force(base_url, wordlist, timeout):
    print(Fore.CYAN + f"[i] Starting fuzz on: {base_url}")
    start_time = datetime.now()
    known_404_length = None

    for i, path in enumerate(wordlist, 1):
        url = base_url.rstrip('/') + '/' + path
        try:
            response = requests.get(url, headers={"User-Agent": get_fake_agent()}, timeout=timeout, allow_redirects=False)
            content_length = len(response.text)

            # Detect first 404 content length to compare
            if response.status_code == 404 and not known_404_length:
                known_404_length = content_length

            # Print result if not 404 or content length differs from custom 404
            if response.status_code in [200, 301, 302, 403] or (known_404_length and content_length != known_404_length):
                print(Fore.GREEN + f"[+] Found: {url} [{response.status_code}]")
            else:
                print(Fore.YELLOW + f"[-] Not found: {url}")
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[!] Error on {url}: {str(e)}")

    duration = datetime.now() - start_time
    print(Fore.BLUE + f"\n[✓] Fuzzing completed in {duration.total_seconds():.2f} seconds.")

def get_fake_agent():
    return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"

if __name__ == "__main__":
    banner()
    args = parse_args()
    wordlist = read_wordlist(args.wordlist)
    brute_force(args.url, wordlist, args.timeout)
