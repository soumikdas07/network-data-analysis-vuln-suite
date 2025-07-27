def capture_packets(interface="Wi-Fi", count=10):
    import subprocess
    import os
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)  # Ensure the folder exists

    output_file = f"{output_dir}/capture_{timestamp}.pcapng"
    print(f"[DEBUG] Will save capture to: {output_file}")
    
    try:
        print(f"[+] Capturing {count} packets on interface '{interface}'...")
        command = ["tshark", "-i", interface, "-c", str(count), "-w", output_file]
        subprocess.run(command, check=True)
        print(f"[+] Packets saved to: {output_file}")
    except Exception as e:
        print(f"[!] Error capturing packets: {e}")
