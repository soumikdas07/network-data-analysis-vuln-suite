from scapy.all import rdpcap, IP, TCP, UDP

def analyze_pcap(file_path):
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        return f"❌ Failed to read PCAP: {e}"

    summary = []
    ip_counter = {}
    protocol_counter = {}

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = None

            if TCP in pkt:
                proto = "TCP"
            elif UDP in pkt:
                proto = "UDP"
            else:
                proto = "OTHER"

            ip_pair = f"{src} ➜ {dst}"
            ip_counter[ip_pair] = ip_counter.get(ip_pair, 0) + 1
            protocol_counter[proto] = protocol_counter.get(proto, 0) + 1

    if not ip_counter:
        return "No IP traffic found in the PCAP file."

    summary.append("📦 IP Communication Summary:")
    for pair, count in ip_counter.items():
        summary.append(f"   - {pair}: {count} packets")

    summary.append("\n📡 Protocol Breakdown:")
    for proto, count in protocol_counter.items():
        summary.append(f"   - {proto}: {count} packets")

    return "\n".join(summary)
