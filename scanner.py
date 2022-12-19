#!/usr/bin/python3

import nmap

Scanner = nmap.PortScanner()

print("welcome, this is a nmap automation scanning tool")
print("<..............................................>")

ip_addr = input("please enter the ip address you want to scan: ")
print("the ip you entered is:", ip_addr)
type(ip_addr)

resp = input("""\nplease enter the type of scan you want to run
                 1)SYN ACK acan
                 2)UDP scan
                 3)comprehensive scan\n""")
print("you have selected option:", resp)

if resp == '1':
    print("nmap version: ", Scanner.nmap_version())
    Scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(Scanner.scaninfo())
    print("ip status:", Scanner[ip_addr].state())
    print(Scanner[ip_addr].all_protocols())
    print("open ports: ", Scanner[ip_addr]['tcp'].keys())

elif resp == '2':
    print("nmap version: ", Scanner.nmap_version())
    Scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(Scanner.scaninfo())
    print("ip status:", Scanner[ip_addr].state())
    print(Scanner[ip_addr].all_protocols())
    print("open ports: ", Scanner[ip_addr]['udp'].keys())

elif resp == '3':
    print("nmap version: ", Scanner.nmap_version())
    Scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(Scanner.scaninfo())
    print("ip status:", Scanner[ip_addr].state())
    print(Scanner[ip_addr].all_protocols())
    print("open ports: ", Scanner[ip_addr]['tcp'].keys())
    
else: 
    print("please enter a valid option")


