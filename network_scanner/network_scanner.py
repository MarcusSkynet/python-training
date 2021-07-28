#!/bin/python3

# Import of necessary functions
import scapy.all as scapy
import argparse


# Gets program arguments, range of IP addresses and target interface
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP / IP range')
    #parser.add_argument('-i', '--interface', dest='interface', help='Scanned interface')
    options = parser.parse_args()
    return options


# Scan the network function
def scan(ip):
    # Create arp request directed to broadcast MAC asking for IPs
    arp_request = scapy.ARP(pdst=ip)
    print(scapy.ls(scapy.ARP))
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')

    # Send packet and receive response
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Parse the response
    clients_list = []
    for client in answered_list:
        client_dict = {'ip': client[1].psrc, 'mac': client[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


# Print results function
def print_result(results_list):
    print('    IP \t\t\tAt MAC address\n-----------------------------------------')
    for element in results_list:
        print(element['ip'] + '\t\t' + element['mac'])


# Perform scan and print results
options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
