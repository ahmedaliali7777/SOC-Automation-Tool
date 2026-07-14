Markdown
# 🛡️ Automated Malware Analyzer & Incident Responder (v2.0)

An advanced, enterprise-grade Python-based automation tool designed for Security Operations Center (SOC) analysts to accelerate triage, cyber threat intelligence (CTI) enrichment, and automated incident response (SOAR). 

The tool optimizes security workflows by performing local static analysis, querying multiple global reputation databases, orchestrating dynamic sandbox execution, and generating evidence-based forensic reports.

---

## 🚀 Key Features (v2.0 Upgrades)

* **Multi-Source Threat Intelligence (CTI):** Correlates real-time reputation queries from **VirusTotal API v3**, **AbuseIPDB API v2**, and **AlienVault OTX** to detect file hashes, suspicious IPs, and malicious URLs.
* **Dynamic Evidence Collector Engine:** Accumulates parsed Indicators of Compromise (IOCs) dynamically throughout the analysis pipeline and maps them to structural threat contexts.
* **Advanced Local Static Analysis:** Automatically extracts embedded IP addresses and domains, scans for dangerous program permissions, and flags obfuscation key indicators (e.g., `payload`, `reverse_shell`).
* **Falcon Sandbox Integration:** Automatically triggers a simulated dynamic detonation via **Hybrid Analysis Sandbox API** if an unknown file exhibits highly suspicious static markers.
* **Reasoning-Based SOAR Containment:** Orchestrates immediate simulated host isolation and process termination, documenting the exact technical reasoning and forensic justifications.
* **Incident Forensics Auto-Reporting:** Dynamically writes a detailed, timestamped `Incident_Report_[Hash].txt` directly to disk for DFIR teams.

---

## 📊 Automated Pipeline Workflow

```text
       [Input Suspicious File]
                  │
                  ▼
       [Calculate SHA-256 Hash]
                  │
     ┌────────────┴────────────┐
     ▼                         ▼
[Verify Global Hash]     [Local Static Analysis]
(VirusTotal & OTX)       ├── Extract IPs & URLs
     │                   ├── Scan Permissions
     │                   └── Audit Keywords
     │                             │
     │     ┌───────────────────────┘
     ▼     ▼
[Dynamic Threat Evidence Collector] (Consolidates all IOCs)
     │
     ├─► [Threat Confirmed?] ──► NO  ──► [Output: System Clean]
     │
     └─► YES (Static flags but Unknown Hash)
           │
           ▼
     [Hybrid Analysis Sandbox] (Dynamic VM Detonation)
           │
           ▼ (Threat Validated)
     [SOAR Containment Playbook Activated]
           ├── Execute Simulated EDR Host Isolation
           ├── Terminate Suspicious Running Processes
           └── Generate Forensic Incident Report Document (.txt)
🛠️ Installation & Setup
1. Prerequisites
Ensure you have Python 3.x installed along with the requests library.

Bash
pip install requests
2. Configure API Keys
Open analyzer.py and input your personal API keys at the top of the file:

Python
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
ABUSE_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
OTX_API_KEY = "YOUR_ALIENVAULT_OTX_API_KEY"
HYBRID_ANALYSIS_API_KEY = "YOUR_HYBRID_ANALYSIS_API_KEY"
3. Usage
Run the tool and supply the absolute path of the target binary/artifact:

Bash
python analyzer.py
📝 Real-World Forensic Report Sample (Passed Test)
When a threat is confirmed, the SOAR engine generates a localized forensic evidence log on disk named Incident_Report_[Short_Hash].txt formatted as follows:

Plaintext
===================================================================
                 SOC AUTOMATION INCIDENT REPORT                     
===================================================================
Timestamp:          2026-07-14 03:45:00
Target File:        C:\Users\user\Desktop\vierus sample\2.exe
SHA-256 Hash:       46d64d84c114f0a7ce178d232852aa98c12247ecaf858352ce
Severity Class:     CRITICAL
===================================================================

📝 AUTOMATED SOAR MITIGATION REASONING / FORENSIC EVIDENCE:
This machine was isolated automatically because the analyzed file triggered
indicators matching known malicious threat vectors. Below is the parsed evidence:

Detections #1:
  └─ Indicator:  46d64d84c114f0a7ce178d232852aa98c12247ecaf858352ce
  └─ Type:       File Hash
  └─ Forensic Evidence / Justification:
     👉 Globally flagged as malicious by 31 antivirus engines on VirusTotal.
  -----------------------------------------------------------------
Detections #2:
  └─ Indicator:  6.0.0.0
  └─ Type:       IPv4
  └─ Forensic Evidence / Justification:
     👉 Identified in 13 active threat intelligence pulses on AlienVault OTX.
  -----------------------------------------------------------------
Detections #3:
  └─ Indicator:  [http://schemas.microsoft.com/SMI/2016/WindowsSettings](http://schemas.microsoft.com/SMI/2016/WindowsSettings)
  └─ Type:       URL
  └─ Forensic Evidence / Justification:
     👉 Identified in 34 active threat intelligence pulses on AlienVault OTX.
  -----------------------------------------------------------------

🛡️ ACTIONS TAKEN BY SOAR PLAYBOOK:
[✔] Network Connection cut off (Host Isolation) via EDR API.
[✔] Target parent processes terminated and file locked down.
[✔] Forensic Incident Log produced and telemetry dispatched to DFIR dashboard.
===================================================================
⚖️ License
This project is licensed under the MIT License - see the LICENSE file for details.
