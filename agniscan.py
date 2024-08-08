import argparse #line:1:import argparse
import socket #line:2:import socket
from datetime import datetime #line:3:from datetime import datetime
from tqdm import tqdm #line:4:from tqdm import tqdm
import warnings #line:5:import warnings
import pyfiglet #line:6:import pyfiglet
warnings .simplefilter ('ignore',category =Warning )#line:8:warnings.simplefilter('ignore', category=Warning)
GREEN ='\033[92m'#line:11:GREEN = '\033[92m'  # Green color for successful
RED ='\033[91m'#line:12:RED = '\033[91m'    # Red color for failed
RESET ='\033[0m'#line:13:RESET = '\033[0m'   # Reset to default color
SERVICE_PORT_MAPPING ={21 :"FTP",22 :"SSH",80 :"HTTP",443 :"HTTPS",53 :"DNS",}#line:21:}
EXPLOITS ={"FTP":[("FTP Brute Force","https://www.exploit-db.com/exploits/4243"),("FTP Anonymous Login","https://www.exploit-db.com/exploits/4244"),],"SSH":[("SSH Brute Force","https://www.exploit-db.com/exploits/4245"),("SSH Password Cracker","https://www.exploit-db.com/exploits/4246"),],"HTTP":[("HTTP Server Side Request Forgery (SSRF)","https://www.exploit-db.com/exploits/4247"),("HTTP XML External Entity (XXE) Attack","https://www.exploit-db.com/exploits/4248"),],"HTTPS":[("HTTPS SSL/TLS Certificate Validation Bypass","https://www.exploit-db.com/exploits/4249"),("HTTPS Heartbleed","https://www.exploit-db.com/exploits/4250"),],"DNS":[("DNS Zone Transfer","https://www.exploit-db.com/exploits/4251"),("DNS Cache Poisoning","https://www.exploit-db.com/exploits/4252"),],}#line:44:}
def resolve_target (OOOOOOO00O0O00O0O ):#line:46:def resolve_target(target):
    ""#line:47:"""Resolve the target hostname to an IP address."""
    try :#line:48:try:
        return socket .gethostbyname (OOOOOOO00O0O00O0O )#line:49:return socket.gethostbyname(target)
    except socket .gaierror as OO0OOOOO0OO0OOOO0 :#line:50:except socket.gaierror as exc:
        print (f"Error resolving target {OOOOOOO00O0O00O0O}: {OO0OOOOO0OO0OOOO0}")#line:51:print(f"Error resolving target {target}: {exc}")
        return None #line:52:return None
def scan_port (OOO0000O00000000O ,O00O0OO0O000O000O ,O00OOO00OO00O0OO0 ):#line:54:def scan_port(target, port, protocol):
    ""#line:55:"""Scan a single port on the target for the specified protocol."""
    try :#line:56:try:
        if O00OOO00OO00O0OO0 =="tcp":#line:57:if protocol == "tcp":
            O000O0OO0OO0O0O0O =socket .socket (socket .AF_INET ,socket .SOCK_STREAM )#line:58:sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            O000O0OO0OO0O0O0O .settimeout (1 )#line:59:sock.settimeout(1)
            O000O0OO0OO0O0O0O .connect ((OOO0000O00000000O ,O00O0OO0O000O000O ))#line:60:sock.connect((target, port))
            O000O0OO0OO0O0O0O .close ()#line:61:sock.close()
        elif O00OOO00OO00O0OO0 =="udp":#line:62:elif protocol == "udp":
            O000O0OO0OO0O0O0O =socket .socket (socket .AF_INET ,socket .SOCK_DGRAM )#line:63:sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            O000O0OO0OO0O0O0O .settimeout (1 )#line:64:sock.settimeout(1)
            O000O0OO0OO0O0O0O .sendto (b'',(OOO0000O00000000O ,O00O0OO0O000O000O ))#line:65:sock.sendto(b'', (target, port))
            OO0OOOOO0O0OOOOO0 ,O0O00OOOO0O0O0000 =O000O0OO0OO0O0O0O .recvfrom (1024 )#line:66:data, addr = sock.recvfrom(1024)
            O000O0OO0OO0O0O0O .close ()#line:67:sock.close()
        else :#line:68:else:
            raise ValueError (f"Unsupported protocol '{O00OOO00OO00O0OO0}'")#line:69:raise ValueError(f"Unsupported protocol '{protocol}'")
        return O00O0OO0O000O000O ,O00OOO00OO00O0OO0 #line:71:return port, protocol
    except socket .timeout :#line:73:except socket.timeout:
        return None #line:74:return None
    except ConnectionRefusedError :#line:75:except ConnectionRefusedError:
        return None #line:76:return None
    except OSError as OOOO00OOOOOO0O00O :#line:77:except OSError as exc:
        return None #line:78:return None
    except Exception as OOOO00OOOOOO0O00O :#line:79:except Exception as exc:
        return None #line:80:return None
def test_service (O0O00O00O00O00OOO ,O0O00OOO0O00OOO0O ,OO0O00O00OO00000O ):#line:82:def test_service(target, port, protocol):
    ""#line:83:"""Determine the service running on a given port and protocol."""
    if OO0O00O00OO00000O =="tcp":#line:84:if protocol == "tcp":
        return SERVICE_PORT_MAPPING .get (O0O00OOO0O00OOO0O ,"Unknown")#line:85:return SERVICE_PORT_MAPPING.get(port, "Unknown")
    elif OO0O00O00OO00000O =="udp":#line:86:elif protocol == "udp":
        return "DNS"if O0O00OOO0O00OOO0O ==53 else "Unknown"#line:87:return "DNS" if port == 53 else "Unknown"
def suggest_exploits (OO0000O00O00O00O0 ):#line:89:def suggest_exploits(service):
    ""#line:90:"""Suggest exploits based on the detected service."""
    O0O00OOO0O0O0OOO0 =[]#line:91:output = []
    if OO0000O00O00O00O0 in EXPLOITS :#line:92:if service in EXPLOITS:
        O0O00OOO0O0O0OOO0 .append ("Suggested exploits:")#line:93:output.append("Suggested exploits:")
        for O00O000OO00OOOO0O ,OOOO0OO000OO0OO00 in EXPLOITS [OO0000O00O00O00O0 ]:#line:94:for name, url in EXPLOITS[service]:
            O0O00OOO0O0O0OOO0 .append (f"- {O00O000OO00OOOO0O}: {OOOO0OO000OO0OO00}")#line:95:output.append(f"- {name}: {url}")
    else :#line:96:else:
        O0O00OOO0O0O0OOO0 .append ("No suggested exploits for this service.")#line:97:output.append("No suggested exploits for this service.")
    return "\n".join (O0O00OOO0O0O0OOO0 )#line:98:return "\n".join(output)
def print_banner ():#line:100:def print_banner():
    ""#line:101:"""Print the Agniscan banner with credits."""
    OOOOO0O00O0O00O00 =pyfiglet .figlet_format ("Agniscan")#line:102:banner = pyfiglet.figlet_format("Agniscan")
    print (f"{GREEN}{OOOOO0O00O0O00O00}{RESET}")#line:103:print(f"{GREEN}{banner}{RESET}")
    print (f"Developed by xploitnation")#line:104:print(f"Developed by xploitnation")
    print (f"GitHub: https://github.com/xploitnation")#line:105:print(f"GitHub: https://github.com/xploitnation")
    print (f"X Handle: 0xSwayamm")#line:106:print(f"X Handle: 0xSwayamm")
    print (f"\nAgniscan is an advanced port scanner that helps you identify open ports and potential vulnerabilities.\n")#line:107:print(f"\nAgniscan is an advanced port scanner that helps you identify open ports and potential vulnerabilities.\n")
def main (O0000000OO000O000 ,O000OO00O000O0000 ,O0OOO0O00000000O0 ,OOOOO0000O0O0O0O0 =False ):#line:109:def main(target, ports_range, protocol, verbose=False):
    ""#line:110:"""Main function to run the port scanner."""
    print_banner ()#line:111:print_banner()
    O0O00O0O0OOO00O0O =resolve_target (O0000000OO000O000 )#line:113:target_ip = resolve_target(target)
    if not O0O00O0O0OOO00O0O :#line:115:if not target_ip:
        return #line:116:return
    print (f"Agniscan - Scanning Target: {O0000000OO000O000} ({O0O00O0O0OOO00O0O})")#line:118:print(f"Agniscan - Scanning Target: {target} ({target_ip})")
    print (f"Scanning started at: {datetime.now()}\n")#line:119:print(f"Scanning started at: {datetime.now()}\n")
    O0O0OOOOOOO000OO0 =[]#line:121:results = []
    for OO00O00000OO0OO0O in tqdm (range (*O000OO00O000O0000 ),desc ="Scanning",unit ="ports"):#line:122:for port in tqdm(range(*ports_range), desc="Scanning", unit="ports"):
        OOO0O0O000O000O00 =scan_port (O0O00O0O0OOO00O0O ,OO00O00000OO0OO0O ,O0OOO0O00000000O0 )#line:123:result = scan_port(target_ip, port, protocol)
        if OOO0O0O000O000O00 and OOO0O0O000O000O00 [0 ]:#line:124:if result and result[0]:
            O0O0OOOOOOO000OO0 .append (OOO0O0O000O000O00 )#line:125:results.append(result)
    if O0O0OOOOOOO000OO0 :#line:127:if results:
        O00OO0O00O000O000 =[]#line:128:open_ports_info = []
        O00OO0O00O000O000 .append (f"\n{GREEN}Open ports:{RESET}\n")#line:129:open_ports_info.append(f"\n{GREEN}Open ports:{RESET}\n")
        OOO00O00OO0OOOOOO =max (len (str (O0OO00OOOO0OOO00O ))for O0OO00OOOO0OOO00O ,_OO00OOO0OO0000000 in O0O0OOOOOOO000OO0 )#line:132:max_port_length = max(len(str(port)) for port, _ in results)
        O0O0O0O0OOO000O0O =max (len (O0OOO0O000000OO0O )for _O00O00OOOO000OO0O ,O0OOO0O000000OO0O in O0O0OOOOOOO000OO0 )#line:133:max_protocol_length = max(len(protocol) for _, protocol in results)
        O00OOO0OOO0O0OO00 =f"{'Port'.ljust(OOO00O00OO0OOOOOO)}  {'Protocol'.ljust(O0O0O0O0OOO000O0O)}  {'Service'}"#line:135:header = f"{'Port'.ljust(max_port_length)}  {'Protocol'.ljust(max_protocol_length)}  {'Service'}"
        OO0OOO00O0O0OOOOO ="-"*len (O00OOO0OOO0O0OO00 )#line:136:separator = "-" * len(header)
        O00OO0O00O000O000 .append (O00OOO0OOO0O0OO00 )#line:137:open_ports_info.append(header)
        O00OO0O00O000O000 .append (OO0OOO00O0O0OOOOO )#line:138:open_ports_info.append(separator)
        O0O0O0000O000000O =[]#line:140:exploits_info = []
        for OO00O00000OO0OO0O ,O0OOO0O00000000O0 in O0O0OOOOOOO000OO0 :#line:142:for port, protocol in results:
            OO00OO0000OOO000O =test_service (O0O00O0O0OOO00O0O ,OO00O00000OO0OO0O ,O0OOO0O00000000O0 )#line:143:service = test_service(target_ip, port, protocol)
            if OO00OO0000OOO000O and OO00OO0000OOO000O !="Unknown":#line:144:if service and service != "Unknown":
                O00OO0O00O000O000 .append (f"{str(OO00O00000OO0OO0O).ljust(OOO00O00OO0OOOOOO)}  {O0OOO0O00000000O0.ljust(O0O0O0O0OOO000O0O)}  {OO00OO0000OOO000O}")#line:145:open_ports_info.append(f"{str(port).ljust(max_port_length)}  {protocol.ljust(max_protocol_length)}  {service}")
                O0O0O0000O000000O .append (f"\n{GREEN}Port {OO00O00000OO0OO0O}/{O0OOO0O00000000O0}: {OO00OO0000OOO000O}{RESET}\n")#line:146:exploits_info.append(f"\n{GREEN}Port {port}/{protocol}: {service}{RESET}\n")
                O0O0O0000O000000O .append (suggest_exploits (OO00OO0000OOO000O ))#line:147:exploits_info.append(suggest_exploits(service))
        print ("\n".join (O00OO0O00O000O000 ))#line:149:print("\n".join(open_ports_info))
        print ("\n".join (O0O0O0000O000000O ))#line:150:print("\n".join(exploits_info))
    else :#line:151:else:
        print ("No open ports found.")#line:152:print("No open ports found.")
    print ("-"*50 )#line:154:print("-" * 50)
if __name__ =="__main__":#line:156:if __name__ == "__main__":
    try :#line:157:try:
        parser =argparse .ArgumentParser (description ="Agniscan - Advanced Port Scanner")#line:158:parser = argparse.ArgumentParser(description="Agniscan - Advanced Port Scanner")
        parser .add_argument ("target",help ="Target IP address or hostname")#line:159:parser.add_argument("target", help="Target IP address or hostname")
        parser .add_argument ("-p","--ports",type =int ,nargs =2 ,metavar =("START","END"),default =(1 ,100 ),help ="Ports range (default: 1-100)")#line:160:parser.add_argument("-p", "--ports", type=int, nargs=2, metavar=("START", "END"), default=(1, 100), help="Ports range (default: 1-100)")
        parser .add_argument ("-P","--protocol",choices =["tcp","udp"],default ="tcp",help ="Protocol to scan (default: tcp)")#line:161:parser.add_argument("-P", "--protocol", choices=["tcp", "udp"], default="tcp", help="Protocol to scan (default: tcp)")
        parser .add_argument ("-v","--verbose",action ="store_true",help ="Enable verbose output")#line:162:parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
        args =parser .parse_args ()#line:164:args = parser.parse_args()
        if args .verbose :#line:166:if args.verbose:
            print ("Verbose mode enabled.")#line:167:print("Verbose mode enabled.")
        main (args .target ,args .ports ,args .protocol ,args .verbose )#line:169:main(args.target, args.ports, args.protocol, args.verbose)
    except KeyboardInterrupt :#line:170:except KeyboardInterrupt:
        print (f"\n{RED}Scan interrupted by user. Exiting...{RESET}")
