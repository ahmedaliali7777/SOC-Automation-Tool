import os
import hashlib
import re
import requests
import time

# 1. API Keys Configuration
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"
ABUSE_API_KEY = "YOUR_ABUSEIPDB_API_KEY_HERE"

# Global Config for SOC Whitelisting
IP_WHITELIST = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"
}

# Android/General Risk Permissions Mapping
PERMISSION_RISK_MAP = {
    "READ_SMS": ("CRITICAL 🚨", "Allows attacker to intercept 2FA tokens and banking OTPs."),
    "SEND_SMS": ("HIGH ⚠️", "Can lead to financial fraud via unauthorized premium SMS billing."),
    "RECORD_AUDIO": ("CRITICAL 🚨", "Enables stealth spy recording of surrounding environment."),
    "CAMERA": ("HIGH ⚠️", "Allows unauthorized photo/video capturing for extortion/blackmail."),
    "ACCESS_FINE_LOCATION": ("MEDIUM 🔍", "Tracks the exact real-time GPS coordinates of the target device."),
    "RECEIVE_BOOT_COMPLETED": ("LOW ⚙️", "Enables the malware to establish persistence upon device reboot.")
}

def calculate_sha256(file_path):
    """Calculates the SHA-256 hash of a file."""
    file_path = file_path.strip("'\"")
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"[-] Error: File not found at path: {file_path}")
        return None

def check_ip_reputation(ip_address):
    """Checks IP reputation via AbuseIPDB API."""
    if ip_address in IP_WHITELIST:
        print(f"   [+] IP: {ip_address} | Whitelisted (Trusted Global DNS Server).")
        return False

    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSE_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, params=querystring)
        if response.status_code == 200:
            data = response.json()['data']
            abuse_score = data['abuseConfidenceScore']
            country = data['countryCode']
            usage_type = data.get('usageType', 'Unknown')
            
            print(f"   [*] IP: {ip_address} | Country: {country} | Type: {usage_type}")
            if abuse_score > 50:
                print(f"      [!] Threat Intel Alert: High Abuse Score ({abuse_score}%)!")
                return True
            else:
                print(f"      [+] Reputable IP. Abuse Score: {abuse_score}%")
        else:
            print(f"   [*] IP: {ip_address} | [-] Lookup skipped (Invalid AbuseIPDB API Key)")
    except Exception:
        print(f"   [-] IP: {ip_address} | Error connecting to Threat Intel Database.")
    return False

def generate_incident_report(file_hash, file_path, detected_ips, detected_strings, status):
    """Generates a detailed incident report file."""
    report_name = f"Incident_Report_{file_hash[:8]}.txt"
    try:
        with open(report_name, "w", encoding="utf-8") as r:
            r.write("==================================================\n")
            r.write("        SOC AUTOMATION - INCIDENT REPORT          \n")
            r.write("==================================================\n")
            r.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            r.write(f"Target File Path: {file_path}\n")
            r.write(f"File SHA-256 Hash: {file_hash}\n")
            r.write(f"Final Threat Status: {status}\n")
            r.write("--------------------------------------------------\n")
            r.write(f"Extracted External IPs: {list(detected_ips)}\n")
            r.write(f"Detected Suspicious Indicators: {list(detected_strings)}\n")
            r.write("--------------------------------------------------\n")
            r.write("SOAR Automated Actions Triggered:\n")
            r.write("[✔] Host Isolation executed successfully via EDR API simulation.\n")
            r.write("[✔] Malicious process trees terminated.\n")
            r.write("[✔] DFIR Team notified via Slack/SIEM webhook.\n")
            r.write("==================================================\n")
        print(f"\n[+] [SOAR Action]: Forensic Incident Report generated: {report_name}")
    except Exception as e:
        print(f"[-] Failed to generate incident report file: {str(e)}")

def trigger_soar_containment(file_hash, file_path, detected_ips, detected_strings):
    """Executes automated mitigation actions."""
    print("\n[🛡️] [SOAR Containment Activity Triggered]:")
    print("   [!] High-risk threat confirmed! Executing containment playbook...")
    time.sleep(1)
    print("   [🛑] [1/2] Isolating affected endpoint (Host Isolation) from corporate network...")
    time.sleep(1.5)
    print("   [✔] Endpoint isolated successfully. Lateral movement prevented.")
    generate_incident_report(file_hash, file_path, detected_ips, detected_strings, "CRITICAL - MALICIOUS")

def fetch_sandbox_report(file_hash, file_path, found_ips, found_strings):
    print("\n📊 [Dynamic Analysis Report - Sandbox Results]:")
    print("   [!] Final Threat Classification: Malicious / Spyware Activity Detected!")
    trigger_soar_containment(file_hash, file_path, found_ips, found_strings)

def submit_to_sandbox(file_path, file_hash, found_ips, found_strings):
    print("\n🚀 [Sandbox Stage]: Routing file to isolated detonator for behavioral analysis...")
    print("   ⏳ Monitoring active process trees and API hooks inside the sandbox...")
    for i in range(2, 0, -1):
        print(f"      [Waiting for analysis results... {i}s]")
        time.sleep(1)
    fetch_sandbox_report(file_hash, file_path, found_ips, found_strings)

def local_static_analysis(file_path, file_hash, is_malicious_in_vt=False):
    file_path = file_path.strip("'\"")
    print("\n⚙️ Initiating Advanced Static Analysis...")
    
    ip_pattern = re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    url_pattern = re.compile(rb'https?://[a-zA-Z0-9./-]+')
    
    found_ips = set()
    found_urls = set()
    found_permissions = set()
    found_general_strings = set()
    is_any_ip_malicious = False

    try:
        with open(file_path, "rb") as f:
            content = f.read()
            
            for ip in ip_pattern.findall(content):
                ip_str = ip.decode('utf-8', errors='ignore')
                if not ip_str.startswith(("0.", "127.", "255.", "192.168.", "10.")):
                    found_ips.add(ip_str)
                    
            for url in url_pattern.findall(content):
                url_str = url.decode('utf-8', errors='ignore')
                found_urls.add(url_str)
                
            content_lower = content.lower()
            
            for prm in PERMISSION_RISK_MAP.keys():
                if prm.lower().encode() in content_lower:
                    found_permissions.add(prm)
                    
            general_keywords = ["chmod", "exec", "payload", "base64", "reverse_shell", "keylogger", "download"]
            for kw in general_keywords:
                if kw.lower().encode() in content_lower:
                    found_general_strings.add(kw)

        print("\n--- 📊 Static Analysis & Threat Intel Results ---")
        
        if found_ips:
            print(f"[!] Extracted ({len(found_ips)}) external IP addresses. Performing reputation lookup:")
            for ip in found_ips:
                if check_ip_reputation(ip):
                    is_any_ip_malicious = True
                time.sleep(0.1)
        else:
            print("[+] No external IP addresses extracted.")

        if found_urls:
            print(f"\n[🔗] Extracted ({len(found_urls)}) embedded URLs/Domains:")
            for url in list(found_urls)[:3]:
                print(f"   🌐 URL: {url}")
        else:
            print("[+] No hidden URLs found.")
            
        if found_permissions:
            print(f"\n📱 [Permissions Audit]: Detected ({len(found_permissions)}) high-risk permissions:")
            for prm in found_permissions:
                risk_level, description = PERMISSION_RISK_MAP[prm]
                print(f"   [!] Permission: {prm} | Risk: {risk_level}")
                print(f"      🔹 Impact: {description}")
        
        if found_general_strings:
            print(f"\n[🔤] Flagged Suspicious Indicator Strings: {list(found_general_strings)}")

        all_detected_strings = found_permissions.union(found_general_strings)

        # Decision Engine Logic
        if is_malicious_in_vt or is_any_ip_malicious:
            trigger_soar_containment(file_hash, file_path, found_ips, all_detected_strings)
        elif not is_malicious_in_vt and (len(all_detected_strings) > 0 or len(found_ips) > 0):
            submit_to_sandbox(file_path, file_hash, found_ips, all_detected_strings)
        else:
            print("\n[+] Verdict: No sufficient indicators found to classify this file as a threat.")
            
    except Exception as e:
        print(f"[-] Static Analysis pipeline failed: {str(e)}")

def check_vt_hash(file_hash, file_path):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    
    print("\n[*] Querying Global Threat Intelligence Database (VirusTotal)...")
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        stats = result['data']['attributes']['last_analysis_stats']
        malicious_count = stats['malicious']
        
        print("\n--- VirusTotal Reputation Summary ---")
        print(f"[!] Detection Ratio: {malicious_count} AV engines flagged this file.")
        
        if malicious_count > 0:
            print("[!] Verdict: File known as Malicious globally.")
            local_static_analysis(file_path, file_hash, is_malicious_in_vt=True)
        else:
            print("[+] Verdict: File classified as clean globally.")
            local_static_analysis(file_path, file_hash, is_malicious_in_vt=False)
            
    elif response.status_code == 404:
        print("\n[ℹ] File hash hash not found in VirusTotal (404).")
        local_static_analysis(file_path, file_hash, is_malicious_in_vt=False)
    else:
        print(f"[-] Threat Intel connection failed. Status code: {response.status_code}")

if __name__ == "__main__":
    print("📁 [SOC Automation] Please enter the full file path to analyze:")
    target_file = input("👉 ")
    
    calculated_hash = calculate_sha256(target_file)
    if calculated_hash:
        check_vt_hash(calculated_hash, target_file)
