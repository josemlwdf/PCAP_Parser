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
Option	Description
        
        ```
        pcap_file	Path to the input pcap file (required)
        --proto	Protocol to extract: tcp, udp, icmp, or all (default: all)
        --dest-ip	Filter by destination IP
        --src-ip	Filter by source IP
        --src-port	Filter by source port
        --dst-port	Filter by destination port
        --output-file	Save the results to a file
        --grep <term>	Only show packets containing a specific string (case-insensitive)
        --raw	Show raw data (hex or undecodable content)
        ```

📌 Examples
Extract all TCP conversations with printable payloads

    pcap_parser capture.pcap --proto tcp

Filter by source IP and grep for HTTP

    pcap_parser capture.pcap --src-ip 192.168.1.5 --grep "HTTP"

Save UDP traffic to a file

    pcap_parser capture.pcap --proto udp --output-file udp_output.txt

## 🧠 Features

✅ Full bidirectional TCP stream reconstruction

        ```
        Each TCP stream captures both client → server and server → client packets in one flow.
        
        Stream content is chronologically sorted by timestamp.
        ```

✅ Handles TCP, UDP, ICMP (and unknown protocols)
✅ Greppable Output


🖼️ Output Examples
<p align="left"> <img src="https://github.com/user-attachments/assets/2791f9b8-8ec4-4677-afeb-c27c6fa1b6e6"> </p>

## ⚙️ Internals
        ```
        Scapy reads packets and extracts protocols of interest.
        
        TCP packets are grouped by stream key: ((IP_A, portA), (IP_B, portB)), sorted for bidirectional pairing.
        
        Packets are sorted chronologically and optionally filtered via CLI flags.
        ````

## 🤝 Contributing

Contributions and feedback are welcome! Feel free to open issues or submit pull requests.
📄 License

This project is licensed under the MIT License — see the LICENSE file for details.
