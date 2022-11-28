#!/usr/bin/python3

import nmap

Scanner = nmap.PortScanner

print("welcome, this is a nmap automation tool")
print(".......................................")
ip_addr = input("please enter the IP address you want to scan: ")
print("The IP address you entered is:",ip_addr)
type(ip_addr)

scan = input("""\nplease enter the type of scan you want to run
                1)SYN ACK scan
                2)UDP scan
                3)Comprehensive scan \n """)

if scan == '1':
    Scanner.scan(ip_addr,"1-1024","-v -sS")
    print(Scanner.scaninfo())
    print("IP status: ",Scanner[ip_addr].state())
    print(Scanner[ip_addr].allprotocols())
    print("open ports: ",Scanner[ip_addr]['tcp'].keys())

elif scan == '2':
    print("nmap version: ",Scanner.nmap_version())
    Scanner.scan(ip_addr,'1-1000','-v -sU')
    print(Scanner.scaninfo())
    print("IP status: ",Scanner[ip_addr].state())
    print(Scanner[ip_addr].allprotocols())
    print("open ports: ",Scanner[ip_addr]['udp'].keys())

elif scan == '3':
    print("nmap version: ",Scanner.nmap_version())
    Scanner.scan(ip_addr,'1-1000','-v -sS -sV -sC -A -O')
    print(Scanner.scaninfo())
    print("IP status: ",Scanner[ip_addr].state())
    print(Scanner[ip_addr].allprotocols())
    print("open ports: ",Scanner[ip_addr]['tcp'].keys())

else:
    print("please enter a valid option")
