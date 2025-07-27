import requests

def search_cve_by_keyword(keyword):
    print(f"\n[+] Searching for known vulnerabilities related to '{keyword}'...\n")
    try:
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 5,
            "startIndex": 0
        }
        headers = {
            "User-Agent": "VulnIntel-Suite"
        }

        response = requests.get(base_url, params=params, headers=headers)
        if response.status_code == 200:
            data = response.json()
            cves = data.get("vulnerabilities", [])
            if not cves:
                print("[!] No CVEs found for the given keyword.")
                return

            for i, item in enumerate(cves, 1):
                cve_id = item["cve"]["id"]
                description = item["cve"]["descriptions"][0]["value"]
                print(f"{i}. CVE ID: {cve_id}")
                print(f"   Description: {description}\n")
        else:
            print(f"[!] Failed to retrieve CVE data. Status Code: {response.status_code}")
    except Exception as e:
        print(f"[!] Error: {str(e)}")
