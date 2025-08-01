# 🛡️ Network Data Analysis & Vulnerability Suite

A Python-based suite for analyzing `.pcap` network capture files and performing Nmap-based network scanning — all from a simple CLI.

---

## 🚀 Features

- 🔍 **Nmap Scanning**  
  Scan IPs or ranges to identify open ports, services, and OS information.

- 📁 **PCAP File Analysis**  
  Analyze `.pcap` files using PyShark to extract and interpret network packet data.

- 🎨 **Colorized CLI Output**  
  Clear, readable terminal output with `colorama`.

- 📊 **Formatted Tables**  
  Display scan and analysis results neatly using `tabulate`.

---

## Requirements

Install all dependencies with:
```bash
pip install -r requirements.txt
```
## Usage
```bash
python main.py
```
You will see a menu like:
```bash
 _   _      _   _            _      _____       _ _     _
| \ | | ___| |_| |_ ___ _ __(_) ___| ____|_ __ (_) | __| | ___ _ __  
|  \| |/ _ \ __| __/ _ \ '__| |/ __|  _| | '_ \| | |/ _` |/ _ \ '_ \ 
| |\  |  __/ |_| ||  __/ |  | | (__| |___| | | | | | (_| |  __/ | | |
|_| \_|\___|\__|\__\___|_|  |_|\___|_____|_| |_|_|_|\__,_|\___|_| |_|

1. Run Nmap Scan & CVE Lookup
2. Capture Packets with TShark
3. Search CVEs by Keyword
4. Generate Combined Nmap + Wireshark Report
5. Exit
```
## 📄 Sample Report
```bash
Generated reports include:
Open ports and services
Known CVEs linked to detected services
Packet summary from the target
Combined analysis in a structured format
```
