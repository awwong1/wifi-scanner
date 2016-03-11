#!/usr/bin/python
import os
import sys

from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff

ap_list = []


def check_root():
    if not os.geteuid() == 0:
        print __file__ + " requires root permissions."
        exit(1)


def usage():
    if len(sys.argv) < 3:
        print
        print "Usage:"
        print "\twifi-scanner.py -i <interface>"
        print
        exit(1)


def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.addr2 not in ap_list:
                ap_list.append(pkt.addr2)
                print "AP MAC: %s with SSID: %s " % (pkt.addr2, pkt.info)


if __name__ == "__main__":
    usage()
    check_root()
    parameters = {sys.argv[1]: sys.argv[2]}
    newiface = str(parameters["-i"])
    sniff(iface=newiface, prn=packet_handler)
