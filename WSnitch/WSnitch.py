import socket
import argparse
import time
from scapy.all import *
from datetime import datetime

# Argument for CLI
parser = argparse.ArgumentParser(description="Wsuits Industries Port Scanner - Happy Hacking")
parser.add_argument("--ip", help="(^_^) Target IP")
parser.add_argument("--start", type=int, default=1, help="(^_0) Start port (default: 1)")
parser.add_argument("--end", type=int, default=65535, help="(^_^) End port (default: 65535)")
parser.add_argument("--out", type=str, help="Output File (^_0) Store scan info for later Use")
parser.add_argument("--domain", type=str, help="Domain Name of Target")
parser.add_argument("--craft", action="store_true", help="Enter interactive custom packet crafting mode")

args = parser.parse_args()


# Wsuits Banner
def banner():
    print(r"""

                             

░██╗░░░░░░░██╗░██████╗███╗░░██╗██╗████████╗░█████╗░██╗░░██╗
░██║░░██╗░░██║██╔════╝████╗░██║██║╚══██╔══╝██╔══██╗██║░░██║
░╚██╗████╗██╔╝╚█████╗░██╔██╗██║██║░░░██║░░░██║░░╚═╝███████║
░░████╔═████║░░╚═══██╗██║╚████║██║░░░██║░░░██║░░██╗██╔══██║
░░╚██╔╝░╚██╔╝░██████╔╝██║░╚███║██║░░░██║░░░╚█████╔╝██║░░██║
░░░╚═╝░░░╚═╝░░╚═════╝░╚═╝░░╚══╝╚═╝░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝

                🔥 WSUITS PORT SCANNER 🔥
                 >>> Africans Hacking <<< 
""")


# Custom Packet Crafter
def craftpkt():
    banner()
    print("[+] Entering Custom Packet Craft Mode 🛠️")

    dst_ip = input("[>] Target IP Address: ").strip()
    try:
        socket.inet_aton(dst_ip)
    except socket.error:
        print("[!] Invalid IP address.")
        return

    proto = input("[>] Protocol (tcp/udp/icmp): ").strip().lower()
    pkt = IP(dst=dst_ip)

    if proto == "tcp":
        try:
            dport = int(input("[>] TCP Destination Port: "))
            if not (1 <= dport <= 65535):
                raise ValueError
            flags = input("[>] TCP Flags (e.g., S, A, R, F, PA): ").upper()
            pkt /= TCP(dport=dport, flags=flags)
        except ValueError:
            print("[!] Invalid TCP port or flag.")
            return

    elif proto == "udp":
        try:
            dport = int(input("[>] UDP Destination Port: "))
            if not (1 <= dport <= 65535):
                raise ValueError
            pkt /= UDP(dport=dport)
        except ValueError:
            print("[!] Invalid UDP port.")
            return

    elif proto == "icmp":
        pkt /= ICMP()

    else:
        print("[!] Unsupported protocol.")
        return

    # Optional payload
    payload = input("[>] Add Payload? (y/n): ").strip().lower()
    if payload == "y":
        data = input("[>] Enter Payload String: ")
        pkt /= Raw(load=data.encode())

    # Show packet
    print("\n[+] Crafted Packet:")
    pkt.show()

    # Send packet?
    send_choice = input("[>] Send packet now? (y/n): ").strip().lower()
    if send_choice == "y":
        send(pkt, verbose=1)
        print("[+] Packet sent.")
    else:
        print("[!] Packet not sent.")


# Resolve domain to IP
def resolve(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] Resolved ▄︻̷̿┻̿═━一 {domain} to  ▄︻̷̿┻̿═━一 {ip}")
        return ip
    except socket.gaierror as e:
        print(f"[!] Could not resolve domain {domain}: {e}")
        exit(1)


# Port Scanner
def scan(ip, start_port, end_port):
    banner()
    print(f"[+] Starting scan on  ▄︻̷̿┻̿═━一 {ip} from port ▄︻̷̿┻̿═━一 {start_port} to ▄︻̷̿┻̿═━一 {end_port}\n")

    results = []
    start_time = time.time()
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                msg = f"[+] Port {port} is OPEN!!"
            else:
                msg = f"[-] Port {port} is Filtered / Closed"
            print(msg)
            results.append(msg)
            sock.close()
        except KeyboardInterrupt:
            print("\n[!] Scan aborted by user.")
            break
        except Exception as e:
            print(f"[!] Error scanning port {port}: {e}")

    duration = time.time() - start_time
    duration_formatted = f"{duration:.2f} seconds"

    # Save results
    if args.out:
        try:
            with open(args.out, "a") as f:
                f.write("="*50 + "\n")
                f.write("WSUITS INDUSTRIES - PORT SCAN REPORT\n")
                f.write("="*50 + "\n")
                f.write(f"Target IP: {ip}\n")
                f.write(f"Scan Time: {scan_time}\n")
                f.write(f"Scan Duration: {duration_formatted}\n")
                f.write(f"Port Range: {start_port}-{end_port}\n\n")
                for line in results:
                    f.write(line + "\n")
                f.write("\n\n")
            print(f"\n[+] Scan results saved to: {args.out}")
        except Exception as e:
            print(f"[!] Failed to write to file: {e}")

    print(f"\n[+] Scan completed in {duration_formatted}")


# Main Program Entry Point
if __name__ == "__main__":
    if args.craft:
        craftpkt()
        exit(0)

    if args.domain:
        ip_to_scan = resolve(args.domain)
    elif args.ip:
        ip_to_scan = args.ip
    else:
        print("[!] ▄︻̷̿┻̿═━一 You must specify either --ip or --domain unless using --craft")
        exit(1)

    scan(ip_to_scan, args.start, args.end)
