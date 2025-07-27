# Add this line at the top
import re
import subprocess


def run_nmap_scan(target):
    print(f"\n[+] Running Nmap scan on {target}...\n")
    output_file = f"output/nmap_{target.replace('.', '_')}.txt"

    command = f"nmap -sV {target} -oN {output_file}"
    subprocess.run(command, shell=True)

    print(f"\n[+] Nmap scan completed. Output saved to {output_file}\n")

    # Extract service names using regex
    services = []
    with open(output_file, "r") as f:
        for line in f:
            match = re.search(r'\d+/tcp.*open\s+(\S+)', line)
            if match:
                services.append(match.group(1).lower())
    
    return services
