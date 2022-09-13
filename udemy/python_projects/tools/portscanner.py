import socket
import termcolor

def scan_port(ipaddress="192.168.1.24", port=25):
    '''
    '''
    try:
        soc = socket.socket()
        soc.connect((ipaddress, port))
        print(termcolor.colored(f"[+] {str(ipaddress)} Port opened : {str(port)}", 'green'))
        soc.close()
    except:
        print(termcolor.colored(f"[+] {str(ipaddress)} Port closed : {str(port)}", 'red'))

def scan(targets, port):
    '''
    '''
    for port in range(1,ports):
        scan_port(targets, port)

while True:
    try:
        targets = str(input("[*] Enter target to scan: "))
        if targets=="":
            targets=ipaddress="192.168.1.24"
    except ValueError:
        print("please enter ip list, cidr notation not accepted")
        continue
    else:
        break
while True:
    try:
        ports = int(input("[*] Enter port count to scan: "))
    except ValueError:
        print("please enter ports count to scan (from port 1 to port X")
        continue
    else:
        break

if ',' in targets:
    print("[*] Scanning multiple targets.")
    for ip in targets.split(','):
        scan(ip.strip(' '), ports)
else:
    scan(targets, ports)
