from nmap_module import run_nmap_scan
from tshark_module import capture_packets
from cve_module import search_cve_by_keyword
from report_generator import generate_combined_report, generate_html_report, convert_html_to_pdf

import os
import time

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    print(r"""
 _   _      _   _            _      _____       _ _     _            
| \ | | ___| |_| |_ ___ _ __(_) ___| ____|_ __ (_) | __| | ___ _ __  
|  \| |/ _ \ __| __/ _ \ '__| |/ __|  _| | '_ \| | |/ _` |/ _ \ '_ \ 
| |\  |  __/ |_| ||  __/ |  | | (__| |___| | | | | | (_| |  __/ | | |
|_| \_|\___|\__|\__\___|_|  |_|\___|_____|_| |_|_|_|\__,_|\___|_| |_|
    """)

def main():
    while True:
        clear_screen()
        banner()

        print("\n1. Run Nmap Scan & CVE Lookup")
        print("2. Capture Packets with TShark")
        print("3. Search CVEs by Keyword")
        print("4. Generate Combined Nmap + Wireshark Report")
        print("5. Exit")

        choice = input("\nChoose an option (1-5): ")

        if choice == "1":
            target = input("Enter IP address or domain to scan with Nmap: ")
            services = run_nmap_scan(target)
            if services:
                print(f"\n[+] Detected services: {', '.join(services)}")
                all_cves = []
                for service in services:
                    print(f"\n[+] Searching CVEs for {service}...")
                    cves = search_cve_by_keyword(service)
                    if cves:
                        all_cves.extend(cves)
                print(f"\n[✓] CVE search complete. {len(all_cves)} total vulnerabilities found.")
            else:
                print("[!] No services detected from Nmap output.")
            input("\nPress Enter to return to the menu...")

        elif choice == "2":
            iface = input("Enter your network interface name (e.g., Wi-Fi or Ethernet): ")
            capture_packets(interface=iface)
            input("\nPress Enter to return to the menu...")

        elif choice == "3":
            keyword = input("Enter a software or service keyword (e.g., openssh, apache): ")
            search_cve_by_keyword(keyword)
            input("\nPress Enter to return to the menu...")

        elif choice == "4":
            nmap_file = input("Enter path to Nmap scan file (e.g., output/nmap_scan.txt): ")
            pcap_file = input("Enter path to PCAP file (e.g., output/capture.pcapng): ")
            try:
                # Step 1: Unpack summaries from combined report
                nmap_summary, pcap_summary = generate_combined_report(nmap_file, pcap_file)

                # Step 2: Generate HTML report
                html_path = generate_html_report(nmap_summary, pcap_summary)
                print(f"[+] HTML report saved to: {html_path}")

                # Step 3: Convert HTML to PDF
                pdf_path = convert_html_to_pdf(html_path)
                if pdf_path:
                    print(f"[✔] PDF report successfully generated: {pdf_path}")
                else:
                    print("[✘] Failed to generate PDF report.")

            except Exception as e:
                print(f"[!] Error generating report: {e}")

            input("\n[✓] Report generation complete. Press Enter to return to the menu...")

        elif choice == "5":
            print("Exiting. Stay secure!")
            break

        else:
            print("Invalid choice. Try again.")
            time.sleep(1)

if __name__ == "__main__":
    main()

