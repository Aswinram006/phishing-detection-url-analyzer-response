import requests
import whois
from datetime import datetime
from urllib.parse import urlparse

VT_API_KEY = "5efaa28db3c2aa83e646022663fe6d7f9b758351fbc96cc67391b2eb5a070030"
VT_URL = "https://www.virustotal.com/api/v3/urls"


# ---------------------------
# Extract domain
# ---------------------------
def extract_domain(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlparse(url)
    return parsed.netloc


# ---------------------------
# Domain Age Checker
# ---------------------------
def get_domain_age(domain):
    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return "Unknown"

        age_days = (datetime.now() - creation_date).days
        return age_days

    except:
        return "Unknown"


# ---------------------------
# VirusTotal URL Scanner
# ---------------------------

import time

def scan_with_virustotal(url):
    try:
        headers = {"x-apikey": VT_API_KEY}
        data = {"url": url}

        # Step 1: Submit URL
        response = requests.post(VT_URL, headers=headers, data=data).json()
        analysis_id = response["data"]["id"]

        # Step 2: Poll until scan completes
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        while True:
            report = requests.get(report_url, headers=headers).json()
            status = report["data"]["attributes"]["status"]

            if status == "completed":
                break  # 🟢 Scan finished

            print("⏳ VirusTotal scanning... waiting 2 sec")
            time.sleep(2)

        # Step 3: Return stats
        stats = report["data"]["attributes"]["stats"]
        return stats

    except Exception as e:
        return {"error": str(e)}

# ---------------------------
# Analyze URL
# ---------------------------
def analyze_url(url):
    print(f"\n🔍 Analyzing URL: {url}")

    domain = extract_domain(url)
    domain_age = get_domain_age(domain)

    print(f"📌 Domain: {domain}")
    print(f"📅 Domain Age: {domain_age} days")

    # VirusTotal Check
    print("\n🛡 Running VirusTotal Scan...")
    vt_result = scan_with_virustotal(url)

    if "error" in vt_result:
        print("❌ VirusTotal Error:", vt_result["error"])
        return

    harmless = vt_result["harmless"]
    malicious = vt_result["malicious"]
    suspicious = vt_result["suspicious"]
    undetected = vt_result["undetected"]

    print("\n📊 VirusTotal Analysis:")
    print(f"✔ Harmless: {harmless}")
    print(f"❌ Malicious: {malicious}")
    print(f"⚠️ Suspicious: {suspicious}")
    print(f"❓ Undetected: {undetected}")

    # Final Verdict
    print("\n📢 Final Verdict:")
    if malicious > 0 or suspicious > 0:
        print("🚨 DANGEROUS — Malicious URL Detected!")
    elif domain_age != "Unknown" and domain_age < 180:
        print("⚠️ Young Domain — Potential Risk")
    else:
        print("✅ Safe URL (Based on VirusTotal)")


# ---------------------------
# RUN
# ---------------------------
url = input("Enter URL to analyze: ").strip()
analyze_url(url)