#!/usr/bin/env python3

from scapy.all import *
import string
import argparse
import os
import time

def extract_streams(pcap_file, dest_ip=None):
    tcp_streams = defaultdict(list)

    print(f"[!] Reading pcap file: {pcap_file}. This can take a while.")

    # Read the pcap file
    packets = rdpcap(pcap_file)

    protocols = [TCP, UDP, ICMP]

    str_protocols = {TCP : 'TCP', UDP : 'UDP', ICMP : 'ICMP'}

    # Extract TCP streams
    for packet in packets:
        for proto in protocols:
            if proto in packet:
                try:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    if dest_ip and dst_ip != dest_ip:
                        continue  # Skip packet if destination IP doesn't match

                    src_port = packet[proto].sport
                    dst_port = packet[proto].dport

                    # Creating a unique stream identifier
                    stream_id = f"{str_protocols[proto]}: {src_ip}:{src_port}-{dst_ip}:{dst_port}\n"
                    
                    # Extracting packet data
                    packet_data = bytes(packet[proto].payload)

                    # Extracting timestamp
                    timestamp = int(packet.time)

                    # Convert the timestamp to a UTC struct_time
                    utc_time_struct = time.gmtime(timestamp)

                    # Formatting the UTC time struct_time into the required format
                    formatted_utc_time = time.strftime("%d/%m/%Y %H:%M:%S", utc_time_struct)

                    if len(packet_data) < 5:
                        continue
                    
                    packet_data = bytes(formatted_utc_time + ": ", encoding='utf-8') + packet_data

                    # Appending packet data to the respective stream
                    tcp_streams[stream_id].append(packet_data)
                except Exception as e:
                    #print(e)
                    continue
                continue
    return tcp_streams


def get_printable_characters(input_string):
    clean_data = ""

    for char in input_string:
        if char in string.printable:
            clean_data += char
    return clean_data


def reset_file(file_name):
    with open(file_name, 'w') as file:
        file.write("")
        file.close()


def print_tcp_streams(tcp_streams, output_file=None, grep=False, raw=False):
    print("[!] Printing data.\n" + "=" * 40)

    for stream_id, packets in tcp_streams.items():
        data = f"Stream-{stream_id}\n"

        final_pkt_data = ""

        for idx, packet_data in enumerate(packets, start=1):            
            try:
                str_data = bytes.decode(packet_data, encoding='utf-8')

                final_pkt_data = get_printable_characters(str_data) + "\n"
            except:
                if not raw:
                    continue
                final_pkt_data += packet_data.hex()

        if len(final_pkt_data) < 5:
            continue
        
        if not raw:
            final_pkt_data = final_pkt_data.replace("\n\n", "\n")

        data += final_pkt_data
        
        if grep:
            if '\r\n' in data:
                data = data.replace("\r\n" , " @ ")
            if '\n' in data:
                data = data.replace("\n" , " @ ")
            data += "\n"

        if output_file:
            with open(output_file, 'a') as file:
                file.write(data)
                file.close()

        print("=" * 40)
        print(data)


def main():
    parser = argparse.ArgumentParser(description='Extract TCP streams from a pcap file.')
    parser.add_argument('pcap_file', help='Path to the input pcap file')
    parser.add_argument('--dest-ip', help='Destination IP address to filter packets')
    parser.add_argument('--output-file', help='Output file to save the results')
    parser.add_argument('--grep', action='store_const', const=True, default=False, help='Outputs the data in a greppable format')
    parser.add_argument('--raw', action='store_const', const=True, default=False, help='Outputs the data in raw format (including bad chars)')

    args = parser.parse_args()

    pcap_file = args.pcap_file
    dest_ip = args.dest_ip
    output_file = args.output_file
    grep = args.grep
    raw = args.raw

    if output_file:
        reset_file(output_file)

    # Extract TCP streams from pcap file, optionally filtered by destination IP
    tcp_streams = extract_streams(pcap_file, dest_ip=dest_ip)

    # Print or save each element of the list based on the output file option
    print_tcp_streams(tcp_streams, output_file=output_file, grep=grep, raw=raw)


if __name__ == "__main__":
    main()
