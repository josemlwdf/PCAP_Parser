#!/usr/bin/env python3

from scapy.all import *
import string
import argparse
import os
from collections import defaultdict
import time
import re
import difflib

# Constants
TIME_FORMAT = "%d/%m/%Y %H:%M:%S"
PROTOCOLS = {"tcp": TCP, "udp": UDP, "icmp": ICMP, "all": None}
MIN_PAYLOAD_SIZE = 5
GENERIC_SEPARATOR = "\n\n" + "=" * 40 + "\n\n"
TCP_SEPARATOR = "\n" + "=" * 40 + "\n"
CIPHERED_PORTS = {22, 443, 465, 636, 993, 995, 3389} # TCP ports for SSH, HTTPS, SMTPS, LDAPS, IMAPS, POP3S, RDP


class Colors:
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'

def colorize_pii(data):
    pii_patterns = [
        (r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", "email"),
        (r"(password|pass|pwd|secret|token|api_key|auth_key|access_key|cookie|session)", "potential credentials"),
        (r"(credit|card|cc_num|card_no)", "potential credit card"),
        (r"(ssn|social_security_number)", "potential SSN"),
        (r"(cvv)", "potential CVV"),
        (r"(user|username|login|user_id|usr)", "potential username"),
        (r"(cred)", "potential credential"),
        (r"([a-zA-Z0-9+/]{15,})", "potential high-entropy string"),
    ]
    for pattern, _ in pii_patterns:
        data = re.sub(pattern, lambda m: f"{Colors.RED}{m.group(0)}{Colors.RESET}", data, flags=re.IGNORECASE)
    return data

def reconstruct_dns(payload):
    try:
        dns_packet = DNS(payload)
        # Check if it's a DNS query (opcode 0) and has a question name
        if dns_packet.qr == 0 and dns_packet.qd and dns_packet.qd.qname:
            return dns_packet.qd.qname.decode('utf-8', 'ignore').rstrip('.')
    except Exception as e:
        return None
    return None

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

def reconstruct_non_printable_payload(payload_bytes, src_port, dst_port):
    """
    Reconstructs a payload by extracting only printable characters,
    and indicates if non-printable chars were present.
    Returns the reconstructed string if applicable, otherwise None.
    """
    if src_port in CIPHERED_PORTS or dst_port in CIPHERED_PORTS:
        return None

    decoded_payload = payload_bytes.decode('utf-8', 'ignore')
    printable_payload = get_printable_characters(decoded_payload)

    # Check if non-printable characters were present
    # A simple heuristic: if the length changes after stripping, or if the original decode had issues
    # and there's still printable data.
    if len(printable_payload) < len(decoded_payload) or (len(payload_bytes) > 0 and not decoded_payload and len(printable_payload) > 0):
        if len(printable_payload) >= MIN_PAYLOAD_SIZE: # Only reconstruct if there's enough printable data
            return f"[RECONSTRUCTED NON-PRINTABLE PAYLOAD]:\n{printable_payload}"
    return None


def reset_file(file_name):
    with open(file_name, 'w') as file:
        file.write("")

def print_tcp_streams(title, tcp_streams, output_file=None, grep=None, raw=False, color=Colors.RESET):
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

        data = "\n".join(data_lines).strip()

        if grep and grep.lower() not in data.lower():
            continue

        data = colorize_pii(data)

        if output_file:
            with open(output_file, 'a') as f:
                f.write(data)

        print(TCP_SEPARATOR)
        print(f"{color}{title} Stream: {stream_str}{Colors.RESET}\n{header}{data}")

def print_flat_packets(title, packets, output_file=None, grep=None, raw=False, color=Colors.RESET):
    if not packets:
        return

    print(GENERIC_SEPARATOR)

    print(f"[!] Printing {title} packets\n" + "=" * 40)

    displayed_dns_queries = set()
    processed_payloads = [] # To store payloads that have already been processed/printed
    all_packets_to_print = []

    for packet_info in packets:
        time_str = packet_info.get("time", "")
        src_ip = packet_info.get("src_ip", "")
        dst_ip = packet_info.get("dst_ip", "")
        src_port = packet_info.get("src_port", "")
        dst_port = packet_info.get("dst_port", "")
        payload = packet_info.get("payload", b"")

        packet_string = ""
        clean_payload = "" # Initialize clean_payload
        skip_packet = False

        if dst_port == 53 or src_port == 53:
            dns_query = reconstruct_dns(payload)
            if dns_query:
                if dns_query not in displayed_dns_queries:
                    packet_string = f"{time_str} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | DNS Query: {dns_query}"
                    displayed_dns_queries.add(dns_query)
                    clean_payload = dns_query # For similarity check
                else:
                    skip_packet = True
            else:
                # DNS packet but couldn't reconstruct query, treat as regular UDP payload
                reconstructed_payload = reconstruct_non_printable_payload(payload, src_port, dst_port)
                if reconstructed_payload:
                    clean_payload = reconstructed_payload
                else:
                    try:
                        clean_payload = get_printable_characters(payload.decode('utf-8').strip())
                    except:
                        if not raw:
                            skip_packet = True
                        else:
                            clean_payload = payload.hex()

                if not skip_packet and not len(clean_payload) >= MIN_PAYLOAD_SIZE:
                    skip_packet = True

                if not skip_packet:
                    if src_port and dst_port:
                        packet_string = f"{time_str} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} |\n\n{clean_payload}"
                    else:
                        packet_string = f"{time_str} | {src_ip} -> {dst_ip} |\n\n{clean_payload}"
        else:
            # Not a DNS packet, treat as regular UDP payload
            reconstructed_payload = reconstruct_non_printable_payload(payload, src_port, dst_port)
            if reconstructed_payload:
                clean_payload = reconstructed_payload
            else:
                try:
                    clean_payload = get_printable_characters(payload.decode('utf-8').strip())
                except:
                    if not raw:
                        skip_packet = True
                    else:
                        clean_payload = payload.hex()

            if not skip_packet and not len(clean_payload) >= MIN_PAYLOAD_SIZE:
                skip_packet = True

            if not skip_packet:
                if src_port and dst_port:
                    packet_string = f"{time_str} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} |\n\n{clean_payload}"
                else:
                    packet_string = f"{time_str} | {src_ip} -> {dst_ip} |\n\n{clean_payload}"

        if skip_packet:
            continue

        # Apply PII highlighting to the content
        highlighted_line = colorize_pii(packet_string)

        # Apply grep filter
        if grep and grep.lower() not in highlighted_line.lower():
            continue

        # Check for similarity before adding to all_packets_to_print
        is_similar = False
        for existing_payload in processed_payloads:
            # Use SequenceMatcher to calculate similarity
            similarity_ratio = difflib.SequenceMatcher(None, clean_payload, existing_payload).ratio()
            if similarity_ratio >= 0.80: # 80% similarity threshold
                is_similar = True
                break

        if not is_similar:
            all_packets_to_print.append(highlighted_line)
            processed_payloads.append(clean_payload) # Store the clean payload for future comparisons

    # Now print all collected lines with separators
    for i, line in enumerate(all_packets_to_print):
        if i > 0:
            print(GENERIC_SEPARATOR) # Print separator before each line except the first
        else:
            print("\n\n")
        print(f"{color}{title} Packet: {Colors.RESET}{line}")

        # Write to file if output_file is specified
        if output_file:
            with open(output_file, 'a') as f:
                f.write(line + "\n") # Write the line to file, then a newline


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
    parser.add_argument('--proto', choices=['tcp', 'udp', 'icmp'], default='all',
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
        print_tcp_streams("TCP", streams["TCP"], output_file=args.output_file, grep=args.grep, raw=args.raw, color=Colors.BLUE)
    if proto == "UDP" or proto == "ALL":
        print_flat_packets("UDP", streams["UDP"], output_file=args.output_file, grep=args.grep, raw=args.raw, color=Colors.YELLOW)
    if proto == "ICMP" or proto == "ALL":
        print_flat_packets("ICMP", streams["ICMP"], output_file=args.output_file, grep=args.grep, raw=args.raw, color=Colors.GREEN)
    if proto == "ALL":
        print_flat_packets("UNKNOWN", streams["UNKNOWN"], output_file=args.output_file, grep=args.grep, raw=args.raw)



if __name__ == "__main__":
    main()
