# 🛡️ Automated Malware Analyzer & Incident Responder (SOC Automation Tool)

An advanced, lightweight Python-based automation script designed for Security Operations Center (SOC) analysts to accelerate triage, cyber threat intelligence (CTI) lookup, and incident response automation (SOAR). 

The tool optimizes security workflows by performing local static analysis, querying global reputation databases, and simulating immediate containment protocols to stop lateral movement during a breach.

---

## 🚀 Key Features

* **Global Threat Intel Lookup:** Queries **VirusTotal API v3** using the computed SHA-256 hash to check if the file is known globally.
* **IP Reputation Scan:** Extracts embedded IP addresses and queries the **AbuseIPDB API v2** while utilizing an automatic global DNS whitelist to prevent unnecessary API usage.
* **SOC Permissions Audit:** Scans binary files (such as Android APKs or scripts) for critical permissions (`READ_SMS`, `RECORD_AUDIO`, etc.) and maps them to a built-in risk matrix with structural impact explanations.
* **Static Code Analysis:** Flags obfuscation or malicious intents like `payload`, `reverse_shell`, `chmod`, and `base64`.
* **SOAR Orchestration (Playbook Simulation):** If a threat is confirmed, the engine immediately simulates **Host Isolation** via EDR network cutting to prevent lateral movement.
* **Forensic Reporting:** Dynamically writes a comprehensive, timestamped `Incident_Report_[Hash].txt` file on the local machine for DFIR teams.

---

## 📊 Workflow Pipeline

```text
[Input File] ──> [Calculate SHA-256] ──> [VirusTotal API]
                                               │
               ┌───────────────────────────────┴─── (If 404 / Not Found)
               ▼
   [Advanced Local Static Analysis]
       ├── Extract Embedded URLs & Domains
       ├── Scan & Filter IPs via Whitelist ──> [AbuseIPDB Threat Intel]
       └── Permissions Audit & Obfuscation Check
               │
               ▼ (If Malicious Indicators Confirmed)
   [SOAR Containment Playbook]
       ├── Execute Simulated Host Isolation (EDR)
       └── Generate Automated Forensic Incident Report (.txt)

🛠️ Installation & Setup
1. Prerequisites
Ensure you have Python 3.x installed along with the requests library.

Bash
pip install requests
2. Configure API Keys
Open analyzer.py and replace the placeholder keys with your personal free API keys:

Python
VT_API_KEY = "Your_VirusTotal_API_Key"
ABUSE_API_KEY = "Your_AbuseIPDB_API_Key"
3. Usage
Run the script from your terminal and supply the absolute path of the suspicious artifact:

Bash
python analyzer.py
📝 Generated Forensic Report Sample
When the SOAR playbook fires, it generates a real file on disk named Incident_Report_[Short_Hash].txt formatted as follows:

Plaintext
==================================================
        SOC AUTOMATION - INCIDENT REPORT          
==================================================
Timestamp: 2026-07-13 03:25:00
Target File Path: C:\Users\user\Desktop\sample\test_malware.apk
File SHA-256 Hash: ab26bc63573318c114f0a7ce178d232852aa98c12247ecaf858352ce54e06e95
Final Threat Status: CRITICAL - MALICIOUS
--------------------------------------------------
Extracted External IPs: ['89.179.154.116']
Detected Suspicious Indicators: ['RECORD_AUDIO', 'READ_SMS', 'payload']
--------------------------------------------------
SOAR Automated Actions Triggered:
[✔] Host Isolation executed successfully via EDR API simulation.
[✔] Malicious process trees terminated.
[✔] DFIR Team notified via Slack/SIEM webhook.
==================================================
⚖️ License
This project is licensed under the MIT License - see the LICENSE file for details.
