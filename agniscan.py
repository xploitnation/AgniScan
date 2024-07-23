import argparse
import socket
from datetime import datetime
from tqdm import tqdm
import warnings
import pyfiglet
 
warnings.simplefilter('ignore', category=Warning)

# ANSI color codes
GREEN = '\033[92m'  # Green color for successful
RED = '\033[91m'    # Red color for failed
RESET = '\033[0m'   # Reset to default color

SERVICE_PORT_MAPPING = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
}

EXPLOITS = {
    "FTP": [
        ("FTP Brute Force", "https://www.exploit-db.com/exploits/4243"),
        ("FTP Anonymous Login", "https://www.exploit-db.com/exploits/4244"),
    ],
    "SSH": [
        ("SSH Brute Force", "https://www.exploit-db.com/exploits/4245"),
        ("SSH Password Cracker", "https://www.exploit-db.com/exploits/4246"),
    ],
    "HTTP": [
        ("HTTP Server Side Request Forgery (SSRF)", "https://www.exploit-db.com/exploits/4247"),
        ("HTTP XML External Entity (XXE) Attack", "https://www.exploit-db.com/exploits/4248"),
    ],
    "HTTPS": [
        ("HTTPS SSL/TLS Certificate Validation Bypass", "https://www.exploit-db.com/exploits/4249"),
        ("HTTPS Heartbleed", "https://www.exploit-db.com/exploits/4250"),
    ],
    "DNS": [
        ("DNS Zone Transfer", "https://www.exploit-db.com/exploits/4251"),
        ("DNS Cache Poisoning", "https://www.exploit-db.com/exploits/4252"),
    ],
}

def resolve_target(target):
    """Resolve the target hostname to an IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        print(f"Error resolving target {target}: {exc}")
        return None

def scan_port(target, port, protocol):
    """Scan a single port on the target for the specified protocol."""
    try:
        if protocol == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target, port))
            sock.close()
        elif protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b'', (target, port))
            data, addr = sock.recvfrom(1024)
            sock.close()
        else:
            raise ValueError(f"Unsupported protocol '{protocol}'")

        return port, protocol

    except socket.timeout:
        return None
    except ConnectionRefusedError:
        return None
    except OSError as exc:
        return None
    except Exception as exc:
        return None

def test_service(target, port, protocol):
    """Determine the service running on a given port and protocol."""
    if protocol == "tcp":
        return SERVICE_PORT_MAPPING.get(port, "Unknown")
    elif protocol == "udp":
        return "DNS" if port == 53 else "Unknown"

def suggest_exploits(service):
    """Suggest exploits based on the detected service."""
    output = []
    if service in EXPLOITS:
        output.append("Suggested exploits:")
        for name, url in EXPLOITS[service]:
            output.append(f"- {name}: {url}")
    else:
        output.append("No suggested exploits for this service.")
    return "\n".join(output)

def print_banner():
    """Print the Agniscan banner with credits."""
    banner = pyfiglet.figlet_format("Agniscan")
    print(f"{GREEN}{banner}{RESET}")
    print(f"Developed by xploitnation")
    print(f"GitHub: https://github.com/xploitnation")
    print(f"X Handle: 0xSwayamm")
    print(f"\nAgniscan is an advanced port scanner that helps you identify open ports and potential vulnerabilities.\n")

def main(target, ports_range, protocol, verbose=False):
    """Main function to run the port scanner."""
    print_banner()
    
    target_ip = resolve_target(target)

    if not target_ip:
        return

    print(f"Agniscan - Scanning Target: {target} ({target_ip})")
    print(f"Scanning started at: {datetime.now()}\n")

    results = []
    for port in tqdm(range(*ports_range), desc="Scanning", unit="ports"):
        result = scan_port(target_ip, port, protocol)
        if result and result[0]:
            results.append(result)

    if results:
        open_ports_info = []
        open_ports_info.append(f"\n{GREEN}Open ports:{RESET}\n")
        
        # Format open ports in a table-like structure
        max_port_length = max(len(str(port)) for port, _ in results)
        max_protocol_length = max(len(protocol) for _, protocol in results)
        
        header = f"{'Port'.ljust(max_port_length)}  {'Protocol'.ljust(max_protocol_length)}  {'Service'}"
        separator = "-" * len(header)
        open_ports_info.append(header)
        open_ports_info.append(separator)
        
        exploits_info = []

        for port, protocol in results:
            service = test_service(target_ip, port, protocol)
            if service and service != "Unknown":
                open_ports_info.append(f"{str(port).ljust(max_port_length)}  {protocol.ljust(max_protocol_length)}  {service}")
                exploits_info.append(f"\n{GREEN}Port {port}/{protocol}: {service}{RESET}\n")
                exploits_info.append(suggest_exploits(service))

        print("\n".join(open_ports_info))
        print("\n".join(exploits_info))
    else:
        print("No open ports found.")

    print("-" * 50)

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="Agniscan - Advanced Port Scanner")
        parser.add_argument("target", help="Target IP address or hostname")
        parser.add_argument("-p", "--ports", type=int, nargs=2, metavar=("START", "END"), default=(1, 100), help="Ports range (default: 1-100)")
        parser.add_argument("-P", "--protocol", choices=["tcp", "udp"], default="tcp", help="Protocol to scan (default: tcp)")
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

        args = parser.parse_args()

        if args.verbose:
            print("Verbose mode enabled.")

        main(args.target, args.ports, args.protocol, args.verbose)
    except KeyboardInterrupt:
        print(f"\n{RED}Scan interrupted by user. Exiting...{RESET}")