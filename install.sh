#!/bin/bash
sudo pip install scapy --break-system-packages
sudo curl -s https://raw.githubusercontent.com/josemlwdf/PCAP_Parser/refs/heads/main/pcap_parser.py -o /usr/sbin/pcap_parser
sudo chmod +x /usr/sbin/pcap_parser
