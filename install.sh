#!/bin/bash
sudo pip install scapy --break-system-packages
cd /opt; sudo wget https://raw.githubusercontent.com/josemlwdf/PCAP_Parser/refs/heads/main/pcap_parser.py
chmod +x /opt/pcap_parser.py
sudo ln -s /opt/pcap_parser.py /usr/sbin/pcap_parser
