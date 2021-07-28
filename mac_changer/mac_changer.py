#!/bin/python3

# Imports necessary functions
import subprocess
import optparse
import re

# Gets program arguments, new mac address and target interface
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--interface', dest='interface', help='Interface to change its MAC address')
    parser.add_option('-m', '--mac', dest='new_mac', help='New MAC address')
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error('[-] Please specify an interface, use --help for more info.')
    elif not options.new_mac:
        parser.error('[-] Please specify a new MAC address, use --help for more info.')
    return options

# Function to change mac address of desired interface
def change_mac(interface, new_mac):
    print('[+] Changing the MAC address of ' + interface + ' to ' + new_mac)
    subprocess.call(['ifconfig', interface, 'down'])
    subprocess.call(['ifconfig', interface, 'hw', 'ether', new_mac])
    subprocess.call(['ifconfig', interface, 'up'])

# Reads current MAC address
def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(['ifconfig', interface])
    mac_address_search_result = re.search(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', str(ifconfig_result))
    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print('[-] Could not read the MAC address.')

# Changes the MAC address
options = get_arguments()

current_mac = get_current_mac(options.interface)
print('Current MAC address is ' + str(current_mac))

change_mac(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
    print('[+] MAC address was successfully changed to ' + current_mac)
else:
    print('[-] MAC address has not been changed.')