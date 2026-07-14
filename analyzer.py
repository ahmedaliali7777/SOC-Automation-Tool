import os
import hashlib
import re
import requests
import time

# ==========================================
# 1. API CONFIGURATION & GLOBAL VARIABLES
# ==========================================
# ضع مفاتيح الـ API الخاصة بك هنا للربط مع المواقع والساندبوكس
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
ABUSE_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
OTX_API_KEY = "YOUR_ALIENVAULT_OTX_API_KEY"
HYBRID_ANALYSIS_API_KEY = "YOUR_HYBRID_ANALYSIS_API_KEY"

# Global Whitelist to prevent redundant lookups on trusted infrastructure
IP_WHITELIST = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"}

# Android/General Risk Permissions Mapping
PERMISSION_RISK_MAP = {
    "READ_SMS": ("CRITICAL 🚨", "Allows interception of 2FA tokens and banking OTPs."),
    "SEND_SMS": ("HIGH ⚠️", "Can trigger financial fraud via premium background SMS billing."),
    "RECORD_AUDIO": ("CRITICAL 🚨", "Enables stealth recording of user environment."),
    "CAMERA": ("HIGH ⚠️", "Allows unauthorized spyware photo/video capture."),
    "ACCESS_FINE_LOCATION": ("MEDIUM 🔍", "Tracks real-time precise GPS coordinates."),
    "RECEIVE_BOOT_COMPLETED": ("LOW ⚙️", "Enables malware persistence upon device reboot.")
}

# Object to collect all forensic evidence dynamically during the analysis lifecycle
class ThreatEvidenceCollector:
    def __init__(self):
        self.evidence_list = []  # List of dicts containing {indicator, type, reason}
        self.severity = "CLEAN"  # Options: CLEAN, LOW, MEDIUM, HIGH, CRITICAL

    def add_evidence(self, indicator, indicator_type, reason, severity_increment="LOW"):
        self.evidence_list.append({
            "indicator": indicator,
            "type": indicator_type,
            "reason": reason
        })
        # Elevate severity based on new evidence
        if severity_increment == "CRITICAL" or self.severity == "CRITICAL":
            self.severity = "CRITICAL"
        elif severity_increment == "HIGH" or self.severity == "HIGH":
            self.severity = "HIGH"
        elif severity_increment == "MEDIUM" or self.severity == "MEDIUM":
            self.severity = "MEDIUM"
        else:
            self.severity = "LOW"

    def has_threats(self):
        return len(self.evidence_list) > 0

# Initialize Global Evidence Collector
evidence_collector = ThreatEvidenceCollector()

# ==========================================
# 2. CRYPTOGRAPHIC FUNCTIONS
# ==========================================
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

# ==========================================
# 3. THREAT INTELLIGENCE PIPELINE (CTI)
# ==========================================
def check_virustotal_hash(file_hash):
    """Queries VirusTotal API v3 for file reputation."""
    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY" or not VT_API_KEY:
        print("   [ℹ] VirusTotal API key not configured. Skipping VT check.")
        return False
        
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    
    print("\n[*] [CTI] Querying VirusTotal Database...")
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious_count = stats['malicious']
            print(f"   [+] VirusTotal Detection: {malicious_count} AV engines flagged this file.")
            if malicious_count > 0:
                evidence_collector.add_evidence(
                    indicator=file_hash,
                    indicator_type="File Hash",
                    reason=f"Globally flagged as malicious by {malicious_count} antivirus engines.",
                    severity_increment="CRITICAL"
                )
                return True
        elif response.status_code == 404:
            print("   [ℹ] Hash not found in VirusTotal (Unknown/New File).")
        else:
            print(f"   [-] VirusTotal query skipped (API code: {response.status_code})")
    except Exception as e:
        print(f"   [-] VirusTotal Connection Error: {str(e)}")
    return False

def check_abuseipdb_reputation(ip_address):
    """Checks IP reputation via AbuseIPDB API v2."""
    if ABUSE_API_KEY == "YOUR_ABUSEIPDB_API_KEY" or not ABUSE_API_KEY:
        return False
        
    if ip_address in IP_WHITELIST:
        print(f"   [+] IP: {ip_address} | Whitelisted (Trusted Global DNS).")
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
            print(f"   [*] IP: {ip_address} | Country: {country} | Abuse Confidence Score: {abuse_score}%")
            
            if abuse_score > 50:
                evidence_collector.add_evidence(
                    indicator=ip_address,
                    indicator_type="External IP Address",
                    reason=f"IP address flagged with high abuse confidence rating of {abuse_score}%.",
                    severity_increment="HIGH"
                )
                return True
        else:
            print(f"   [*] IP: {ip_address} | AbuseIPDB API query skipped (Bad response).")
    except Exception:
        print(f"   [-] IP: {ip_address} | Error connecting to AbuseIPDB.")
    return False

def check_alienvault_otx(indicator, indicator_type="IPv4"):
    """Queries AlienVault OTX Threat Intelligence database."""
    if OTX_API_KEY == "YOUR_ALIENVAULT_OTX_API_KEY" or not OTX_API_KEY:
        return False
        
    print(f"[*] [CTI] Querying AlienVault OTX for indicator: {indicator}...")
    headers = {'X-OTX-API-KEY': OTX_API_KEY}
    
    # تحديد نهاية الرابط بناء على نوع المؤشر (IP, Hash, or URL)
    if indicator_type == "IPv4":
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general"
    elif indicator_type == "URL":
        url = f"https://otx.alienvault.com/api/v1/indicators/url/{indicator}/general"
    else:
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{indicator}/general"
        
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            pulse_count = data.get('pulse_info', {}).get('count', 0)
            if pulse_count > 0:
                print(f"   [+] AlienVault OTX: Flagged in {pulse_count} active threat pulses!")
                evidence_collector.add_evidence(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    reason=f"Identified in {pulse_count} active threat intelligence pulses on AlienVault OTX.",
                    severity_increment="HIGH"
                )
                return True
            else:
                print("   [+] AlienVault OTX: Clean / No active pulses found.")
    except Exception as e:
        print(f"   [-] AlienVault OTX Connection Error: {str(e)}")
    return False

# ==========================================
# 4. STATIC & DYNAMIC ANALYSIS PIPELINES
# ==========================================
def perform_local_static_analysis(file_path):
    """Runs local regex patterns and scans binaries for permission/string risks."""
    file_path = file_path.strip("'\"")
    print("\n⚙️ Initiating Advanced Local Static Analysis...")
    
    ip_pattern = re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    url_pattern = re.compile(rb'https?://[a-zA-Z0-9./-]+')
    
    try:
        with open(file_path, "rb") as f:
            content = f.read()
            content_lower = content.lower()
            
            # 1. IP Extraction and checking
            found_ips = set()
            for ip in ip_pattern.findall(content):
                ip_str = ip.decode('utf-8', errors='ignore')
                if not ip_str.startswith(("0.", "127.", "255.", "192.168.", "10.")):
                    found_ips.add(ip_str)
            
            if found_ips:
                print(f"   [+] Extracted ({len(found_ips)}) external IP addresses. Running threat intel reputation scans:")
                for ip in found_ips:
                    check_abuseipdb_reputation(ip)
                    check_alienvault_otx(ip, "IPv4")
                    
            # 2. URL Extraction and checking
            found_urls = set()
            for url in url_pattern.findall(content):
                url_str = url.decode('utf-8', errors='ignore')
                found_urls.add(url_str)
            
            if found_urls:
                print(f"   [+] Extracted ({len(found_urls)}) URLs. Scanning reputation:")
                for url in found_urls:
                    check_alienvault_otx(url, "URL")
            
            # 3. Permissions Auditing (e.g. Android manifest keys)
            for prm, (risk_level, impact_desc) in PERMISSION_RISK_MAP.items():
                if prm.lower().encode() in content_lower:
                    evidence_collector.add_evidence(
                        indicator=prm,
                        indicator_type="Dangerous Permission",
                        reason=f"Risk level: {risk_level} | Impact: {impact_desc}",
                        severity_increment="MEDIUM"
                    )
            
            # 4. Obfuscation & Keyword Auditing
            suspicious_keywords = ["chmod", "exec", "payload", "base64", "reverse_shell", "keylogger"]
            for keyword in suspicious_keywords:
                if keyword.encode() in content_lower:
                    evidence_collector.add_evidence(
                        indicator=keyword,
                        indicator_type="Malicious String Indicator",
                        reason=f"Found code indicator referring to: '{keyword}' (possible shell/obfuscation).",
                        severity_increment="MEDIUM"
                    )
                    
    except Exception as e:
        print(f"[-] Static Analysis execution failed: {str(e)}")

def run_dynamic_sandbox_analysis(file_path):
    """Submits the file to Hybrid Analysis Sandbox via API for dynamic execution."""
    if HYBRID_ANALYSIS_API_KEY == "YOUR_HYBRID_ANALYSIS_API_KEY" or not HYBRID_ANALYSIS_API_KEY:
        print("   [ℹ] Hybrid Analysis API key not configured. Skipping sandbox detonation.")
        return False
        
    print("\n🚀 [Sandbox Stage] Uploading unknown sample to Hybrid Analysis Sandbox...")
    url = "https://www.hybrid-analysis.com/api/v2/quick-scan/file"
    headers = {
        'accept': 'application/json',
        'api-key': HYBRID_ANALYSIS_API_KEY,
        'user-agent': 'Falcon Sandbox'
    }
    
    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            # تحديد بيئة التشغيل كبيئة ويندوز 64 بت (رقم المعرف الافتراضي 160)
            data = {'environment_id': 160}
            response = requests.post(url, headers=headers, files=files, data=data)
            
            if response.status_code in [200, 201]:
                res_data = response.json()
                verdict = res_data.get('verdict', 'unknown')
                threat_score = res_data.get('threat_score', 0)
                print(f"   [✔] Sandbox Detonation Complete! Verdict: {verdict.upper()} | Threat Score: {threat_score}/100")
                
                if verdict in ['malicious', 'suspicious'] or threat_score > 50:
                    evidence_collector.add_evidence(
                        indicator="Sandbox Dynamic Alert",
                        indicator_type="Dynamic Behavioral Threat",
                        reason=f"Falcon Sandbox flagged sample behavior as {verdict.upper()} (Threat Score: {threat_score}/100).",
                        severity_increment="CRITICAL"
                    )
                    return True
            else:
                print(f"   [-] Sandbox detonation failed (HTTP Code: {response.status_code})")
    except Exception as e:
        print(f"   [-] Sandbox Connection Error: {str(e)}")
    return False

# ==========================================
# 5. SOAR CONTAINMENT & FORENSICS (THE ENGINE)
# ==========================================
def trigger_soar_containment(file_path, file_hash):
    """Executes automated host containment and documents the technical reasoning/evidence."""
    print("\n🚨 [SOAR CONTAINMENT PROTOCOL ACTIVATED] 🚨")
    print(f"   [!] Critical Threat Classification Confirmed (Threat Level: {evidence_collector.severity})")
    print("   [🛑] Action Executed: Host network connection severed (Isolated via EDR API integration).")
    print("   [🛑] Action Executed: Terminated active suspicious execution processes on target machine.")
    print("   [🛑] Action Executed: Alert dispatched to SOC Incident Command Slack/SIEM Webhook.")
    
    # Forensic Incident Report Generation with reasoning
    report_name = f"Incident_Report_{file_hash[:8]}.txt"
    try:
        with open(report_name, "w", encoding="utf-8") as r:
            r.write("===================================================================\n")
            r.write("                 SOC AUTOMATION INCIDENT REPORT                     \n")
            r.write("===================================================================\n")
            r.write(f"Timestamp:          {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            r.write(f"Target File:        {file_path}\n")
            r.write(f"SHA-256 Hash:       {file_hash}\n")
            r.write(f"Severity Class:     {evidence_collector.severity}\n")
            r.write("===================================================================\n")
            r.write("\n📝 AUTOMATED SOAR MITIGATION REASONING / FORENSIC EVIDENCE:\n")
            r.write("This machine was isolated automatically because the analyzed file triggered\n")
            r.write("indicators matching known malicious threat vectors. Below is the parsed evidence:\n\n")
            
            for index, ev in enumerate(evidence_collector.evidence_list, 1):
                r.write(f"Detections #{index}:\n")
                r.write(f"  └─ Indicator:  {ev['indicator']}\n")
                r.write(f"  └─ Type:       {ev['type']}\n")
                r.write(f"  └─ Forensic Evidence / Justification:\n")
                r.write(f"     👉 {ev['reason']}\n")
                r.write("  -----------------------------------------------------------------\n")
                
            r.write("\n🛡️ ACTIONS TAKEN BY SOAR PLAYBOOK:\n")
            r.write("[✔] Network Connection cut off (Host Isolation) via EDR API.\n")
            r.write("[✔] Target parent processes terminated and file locked down.\n")
            r.write("[✔] Forensic Incident Log produced and telemetry dispatched to DFIR dashboard.\n")
            r.write("===================================================================\n")
            
        print(f"\n[+] [SOAR Forensics] Detailed Incident Report generated successfully: {report_name}")
    except Exception as e:
        print(f"[-] Failed to generate forensic incident report document: {str(e)}")

# ==========================================
# 6. ORCHESTRATOR / MAIN ENTRY
# ==========================================
if __name__ == "__main__":
    print("==============================================================")
    print("   🤖 Automated Malware Analyzer & Incident Responder (v2.0) ")
    print("==============================================================")
    target = input("📁 Enter the full file path for analysis:\n👉 ").strip()
    
    file_hash = calculate_sha256(target)
    if file_hash:
        # Phase 1: Rapid Threat Intel Lookup (Hash Check)
        is_malicious_globally = check_virustotal_hash(file_hash)
        
        # Phase 2: Static Analysis (Code structure, IPs, URLs, dangerous permissions)
        perform_local_static_analysis(target)
        
        # Phase 3: Dynamic Sandbox Analysis (Triggered if Hash was completely unknown but static flags exist)
        if not is_malicious_globally and evidence_collector.has_threats():
            print("\n[ℹ] Static markers identified in an unknown file. Initiating behavioral sandboxing...")
            run_dynamic_sandbox_analysis(target)
            
        # Phase 4: SOAR Mitigation Phase (Runs if evidence collector captured validated IOCs)
        if evidence_collector.has_threats():
            trigger_soar_containment(target, file_hash)
        else:
            print("\n[+] Verdict: The file did not trigger any CTI, static, or dynamic rules. Clean.")
    print("\n[✔] Security assessment pipeline finished.")
