

import nmap

scanner = nmap.PortScanner()

print("welcome, this is a nmap automation tool")
print(".......................................")
ip_addr = input("please enter the IP address you want to scan: ")
print("The IP address you entered is:",ip_addr)
type(ip_addr)

response = input("""\nplease enter the type of scan you want to run
                1)SYN ACK scan
                2)UDP scan
                3)Comprehensive scan \n """)
print("you have selected option: ",response)

if response == '1':
    print("nmap version: ",scanner.nmap_version())
    scanner.scan(ip_addr,'1-1000','-v -sS')
    print(scanner.scaninfo())
    print("IP status: ",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("open ports: ",scanner[ip_addr]['tcp'].keys())

elif response == '2':
    print("nmap version: ",scanner.nmap_version())
    scanner.scan(ip_addr,'1-1000','-v -sU')
    print(scanner.scaninfo())
    print("IP status: ",scanner[ip_addr].state())
    print(scanner[ip_addr].allprotocols())
    print("open ports: ",scanner[ip_addr]['udp'].keys())

elif response == '3':
    print("nmap version: ",scanner.nmap_version())
    scanner.scan(ip_addr,'1-1000','-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP status: ",scanner[ip_addr].state())
    print(scanner[ip_addr].allprotocols())
    print("open ports: ",scanner[ip_addr]['tcp'].keys())

else:
    print("please enter a valid option")
