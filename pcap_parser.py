#!/usr/bin/env python3

from scapy.all import *
import string
import argparse
import os
from collections import defaultdict
import time
import re

# Constants
TIME_FORMAT = "%d/%m/%Y %H:%M:%S"
PROTOCOLS = {"tcp": TCP, "udp": UDP, "icmp": ICMP, "all": None}
MIN_PAYLOAD_SIZE = 5
GENERIC_SEPARATOR = "\n\n" + "=" * 40 + "\n\n"
TCP_SEPARATOR = "\n" + "=" * 40 + "\n"


def extract_streams(pcap_file, dest_ip=None, src_ip=None, src_port=None, dst_port=None):
    tcp_streams = defaultdict(list)
    udp_packets = []
    icmp_packets = []
    unknown_protocol_packets = []

    print(f"[!] Reading pcap file: {pcap_file}. This can take a while.")
    packets = rdpcap(pcap_file)

    for packet in packets:
        try:
            if IP not in packet:
                continue

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if dest_ip and dst_ip != dest_ip:
                continue
            if src_ip and src_ip != packet[IP].src:
                continue
            if src_port and TCP in packet and packet[TCP].sport != src_port:
                continue
            if dst_port and TCP in packet and packet[TCP].dport != dst_port:
                continue
            if src_port and UDP in packet and packet[UDP].sport != src_port:
                continue
            if dst_port and UDP in packet and packet[UDP].dport != dst_port:
                continue

            timestamp = int(packet.time)
            formatted_utc_time = time.strftime(TIME_FORMAT, time.gmtime(timestamp))

            # TCP
            if TCP in packet:
                payload = bytes(packet[TCP].payload)
                if len(payload) >= MIN_PAYLOAD_SIZE:
                    stream_id = tuple(sorted([
                        (src_ip, packet[TCP].sport),
                        (dst_ip, packet[TCP].dport)
                    ]))

                    tcp_streams[stream_id].append({
                        "time": formatted_utc_time,
                        "timestamp": packet.time,
                        "src_ip": src_ip,
                        "src_port": packet[TCP].sport,
                        "dst_ip": dst_ip,
                        "dst_port": packet[TCP].dport,
                        "payload": payload
                    })

            # UDP
            elif UDP in packet:
                payload = bytes(packet[UDP].payload)
                if len(payload) >= MIN_PAYLOAD_SIZE:
                    udp_packets.append({
                        "time": formatted_utc_time,
                        "src_ip": src_ip,
                        "src_port": packet[UDP].sport,
                        "dst_ip": dst_ip,
                        "dst_port": packet[UDP].dport,
                        "payload": payload
                    })

            # ICMP
            elif ICMP in packet:
                payload = bytes(packet[ICMP].payload)
                if len(payload) >= MIN_PAYLOAD_SIZE:
                    icmp_packets.append({
                        "time": formatted_utc_time,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "payload": payload
                    })

            # Unknown
            else:
                unknown_protocol_packets.append({
                    "time": formatted_utc_time,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "payload": b"UNKNOWN PROTOCOL"
                })

        except Exception:
            continue
    
    for stream_id in tcp_streams:
        tcp_streams[stream_id].sort(key=lambda p: p["timestamp"])

    return {
        "TCP": tcp_streams,
        "UDP": udp_packets,
        "ICMP": icmp_packets,
        "UNKNOWN": unknown_protocol_packets
    }


def get_printable_characters(input_string):
    return ''.join([char for char in input_string if char in string.printable])


def reset_file(file_name):
    with open(file_name, 'w') as file:
        file.write("")


def print_tcp_streams(title, tcp_streams, output_file=None, grep=None, raw=False):
    if not tcp_streams:
        return

    for stream_id, packets in tcp_streams.items():
        ip_port_1, ip_port_2 = stream_id

        stream_str = f"{ip_port_1[0]}:{ip_port_1[1]} <-> {ip_port_2[0]}:{ip_port_2[1]}"

        data_lines = []

        for packet in packets:
            time_str = packet.get("time", "")
            src_ip = packet.get("src_ip", "")
            dst_ip = packet.get("dst_ip", "")
            src_port = packet.get("src_port", "")
            dst_port = packet.get("dst_port", "")
            payload = packet.get("payload", b"")

            try:
                decoded = payload.decode('utf-8').strip()
                clean = get_printable_characters(decoded)
            except:
                if not raw:
                    continue
                clean = payload.hex()
            
            if (not len(clean) >= MIN_PAYLOAD_SIZE):
                continue
            
            if (clean[:4] == "HTTP"):
                clean = "\n" + clean
                
            data_lines.append(clean)

        if not data_lines:
            continue
        
        header = f"{time_str} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} |\n\n"

        data = f"{title} Stream: {stream_str}\n{header}" + "\n".join(data_lines).strip()

        if grep and grep.lower() not in data.lower():
            continue

        if output_file:
            with open(output_file, 'a') as f:
                f.write(data)

        print(TCP_SEPARATOR)
        print(data)


def print_flat_packets(title, packets, output_file=None, grep=None, raw=False):
    if not packets:
        return

    print(f"[!] Printing {title} packets\n" + "=" * 40)
    data_lines = []

    for packet in packets:
        time_str = packet.get("time", "")
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        src_port = packet.get("src_port", "")
        dst_port = packet.get("dst_port", "")
        payload = packet.get("payload", b"")

        try:
            decoded = payload.decode('utf-8').strip()
            clean = get_printable_characters(decoded)
        except:
            if not raw:
                continue
            clean = payload.hex()
        
        if (not len(clean) >= MIN_PAYLOAD_SIZE):
                continue

        if src_port and dst_port:
            line = f"{title} Packet: {time_str} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} |\n\n{clean}"
        else:
            line = f"{title} Packet: {time_str} | {src_ip} -> {dst_ip} |\n\n{clean}"

        data_lines.append(line)

    if not data_lines:
        return

    data = f"{GENERIC_SEPARATOR}".join(data_lines).strip() + "\n"

    if grep and grep.lower() not in data.lower():
        return

    if output_file:
        with open(output_file, 'a') as file:
            file.write(data)

    print(data)


def main():
    parser = argparse.ArgumentParser(description='Extract protocol streams from a pcap file.')
    parser.add_argument('pcap_file', help='Path to the input pcap file')
    parser.add_argument('--dest-ip', help='Destination IP address to filter packets')
    parser.add_argument('--src-ip', help='Source IP address to filter packets')
    parser.add_argument('--src-port', type=int, help='Source port to filter packets')
    parser.add_argument('--dst-port', type=int, help='Destination port to filter packets')
    parser.add_argument('--output-file', help='Output file to save the results')
    parser.add_argument('--grep', type=str, help='Only display packets containing this grep term (case-insensitive)')
    parser.add_argument('--raw', action='store_true', help='Outputs the data in raw format (including bad chars)')
    parser.add_argument('--proto', choices=['tcp', 'udp', 'icmp', 'all'], default='all',
                        help='Protocol to extract (default: all)')

    args = parser.parse_args()

    if args.output_file:
        reset_file(args.output_file)
    
    try:
        with open(args.pcap_file, "rb"):
            pass
    except Exception as e:
        print(f"[!] Error opening file: {e}\n")
        parser.print_usage()
        return

    streams = extract_streams(
        args.pcap_file,
        dest_ip=args.dest_ip,
        src_ip=args.src_ip,
        src_port=args.src_port,
        dst_port=args.dst_port
    )

    proto = args.proto.upper()

    if proto == "TCP" or proto == "ALL":
        print_tcp_streams("TCP", streams["TCP"], output_file=args.output_file, grep=args.grep, raw=args.raw)
    if proto == "UDP" or proto == "ALL":
        print_flat_packets("UDP", streams["UDP"], output_file=args.output_file, grep=args.grep, raw=args.raw)
    if proto == "ICMP" or proto == "ALL":
        print_flat_packets("ICMP", streams["ICMP"], output_file=args.output_file, grep=args.grep, raw=args.raw)
    if proto == "ALL":
        print_flat_packets("UNKNOWN", streams["UNKNOWN"], output_file=args.output_file, grep=args.grep, raw=args.raw)



if __name__ == "__main__":
    main()
