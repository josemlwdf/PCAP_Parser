# PCAP_Parser

This Python script, `pcap_parser.py`, extracts and analyzes TCP, UDP, and ICMP packet streams from a `.pcap` (packet capture) file. It uses **Scapy** to process network traffic and supports advanced filtering, grepping, and stream reconstruction (including full **bidirectional TCP conversations**).

---

## 🧰 Prerequisites

- Python 3.x
- Scapy (`pip install scapy`)

---

## 📦 Install

    curl https://raw.githubusercontent.com/josemlwdf/PCAP_Parser/refs/heads/main/install.sh | bash

## 🚀 Usage

    python3 pcap_parser.py <pcap_file> [options]

🔧 Command-Line Options

| Option        | Description                                                              |
|---------------|--------------------------------------------------------------------------|
| `pcap_file`   | Path to the input pcap file (required)                                   |
| `--proto`     | Protocol to extract: `tcp`, `udp`, `icmp`, or `all` (default: `all`)     |
| `--dest-ip`   | Filter by destination IP                                                 |
| `--src-ip`    | Filter by source IP                                                      |
| `--src-port`  | Filter by source port                                                    |
| `--dst-port`  | Filter by destination port                                               |
| `--output-file`| Save the results to a file                                               |
| `--grep <term>`| Only show packets containing a specific string (case-insensitive)        |
| `--raw`       | Show raw data (hex or undecodable content)                               |

📌 Examples

Extract all TCP conversations with printable payloads

    pcap_parser capture.pcap --proto tcp

Filter by source IP and grep for HTTP

    pcap_parser capture.pcap --src-ip 192.168.1.5 --grep "HTTP"

Save UDP traffic to a file

    pcap_parser capture.pcap --proto udp --output-file udp_output.txt

Show raw data for all protocols

    pcap_parser capture.pcap --raw

## 🧠 Features

✅ Full bidirectional TCP stream reconstruction

Each TCP stream captures both client → server and server → client packets in one flow.

Stream content is chronologically sorted by timestamp.

✅ Handles TCP, UDP, ICMP (and unknown protocols)

✅ Greppable Output

✅ **PII Highlighting**: Automatically highlights potential Personally Identifiable Information (e.g., emails, passwords, credit card numbers) in the output.

✅ **DNS Query Reconstruction**: Intelligently reconstructs and displays DNS queries.

✅ **Intelligent Packet Deduplication**: For UDP, ICMP, and unknown protocols, highly similar packets are deduplicated to reduce noise.

✅ **Colorized Output**: Enhances readability with color-coded output for different protocols and highlighted PII.

✅ **Raw Data Output**: Option to display raw (hex or undecodable) payload content.

✅ **Ciphered Port Handling**: Avoids attempting to reconstruct payloads for common ciphered ports (e.g., SSH, HTTPS) to prevent garbled output.


🖼️ Output Examples
<p align="left"> <img src="https://github.com/user-attachments/assets/2791f9b8-8ec4-4677-afeb-c27c6fa1b6e6"> </p>

*Note: The actual output will be colorized and may include PII highlighting, which is not fully represented in the static image.*

## ⚙️ Internals

Scapy reads packets and extracts protocols of interest.

TCP packets are grouped by stream key: ((IP_A, portA), (IP_B, portB)), sorted for bidirectional pairing.

Packets are sorted chronologically and optionally filtered via CLI flags.

DNS queries are reconstructed from UDP payloads. 

Potential PII is identified and highlighted using regular expressions. 

For UDP, ICMP, and unknown protocols, a similarity check is performed to deduplicate highly similar packet payloads.


## 🤝 Contributing

Contributions and feedback are welcome! Feel free to open issues or submit pull requests.
