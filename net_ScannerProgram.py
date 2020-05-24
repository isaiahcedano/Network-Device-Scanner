#!/usr/bin/env python

import nmap
import optparse
parser = optparse.OptionParser()
parser.add_option("-i", "--ip-address", dest="IpAddress", help="This is the ip address of which \n"
                                                               "you want to scan, '192.168.1.1/24' for the whole net")
args = parser.parse_args()[0]

scanner = nmap.PortScanner()

def scanNet(ip):
    if not ip:
        print("[-] Please specify an IP Address, --help for more info")
        quit()
    else:
        print("[+] Scanning...")
        print("[!] This can take a while, please be patient\n")
        scanner.scan(ip, arguments="-T4 -F")
        return scanner.all_hosts()

clients_Ip = scanNet(args.IpAddress) # Clients_Ip is basically scanner.all_hosts() list

print("[+] Scan Results : \n")
print("IP Addresses\t\tMac Addresses\t\t\tVendor\n--------------------------------------------------------------------------")

for item in clients_Ip: # for each item inside the scanner.all_hosts() list
    if "mac" in scanner[item]['addresses']:
        mac = scanner[item]['addresses']['mac']
        vendor = scanner[item]["vendor"][mac]
        print(item + "\t\t" + mac + "\t\t" + vendor)
    else:
        print("[-] There is no MAC or Vendor found for this Host -->> " + item)
