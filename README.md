# Enterprise Multi-Endpoint SOC Detection & Incident Investigation Lab

A practical, hands-on Security Operations Center (SOC) home lab built to simulate real-world cyberattacks, analyze telemetry across hybrid environments (Windows & Linux), and perform end-to-end incident investigation using enterprise-grade monitoring tools.

---

## Architecture Overview

The lab environment is fully isolated within a dedicated VirtualBox Host-Only virtual network (`192.168.56.0/24`), mirroring an enterprise segment with segregated endpoints, centralized logging, and an external adversary.

| Role | Hostname | OS / Specs | IP Address | Telemetry / Agent |
| :--- | :--- | :--- | :--- | :--- |
| **SIEM / Manager** | `wazuh-server` | Wazuh OVA (Linux 64-bit) | `192.168.56.103` | Wazuh Indexer, Manager, Dashboard |
| **Endpoint 1** | `Windows-Victim`| Windows 10 Enterprise | `192.168.56.102` | Wazuh Agent v4.14, Sysmon (Process & Netmon) |
| **Endpoint 2** | `Ubuntu-Server` | Ubuntu Server 24.04 LTS | `192.168.56.104` | Wazuh Agent v4.14, PAM / OpenSSH (`sshd-session`)|
| **Adversary** | `kali` | Kali Linux | `192.168.56.101` | Nmap, Hydra, Smbclient, Living-off-the-Land Tools |
                  [ 192.168.56.101 ]
                     Kali Attacker
                          |
   +----------------------+----------------------+
   |                      |                      |
   v                      v                      v
[ 192.168.56.104 ]     [ 192.168.56.102 ]     [ 192.168.56.103 ]
Ubuntu Server          Windows 10 Victim      Wazuh SIEM Manager
(sshd / PAM logs)     (Sysmon ID 1/3, 4625)   (Indexer & Dashboard)


## Executed Attack Scenarios & Detection Telemetry

### Scenario 1: Network Reconnaissance & Port Scanning
* **Adversary Activity:** Nmap SYN Scan (`-sS`) against core ports, followed by TCP Connect Scan (`-sT`) on port 8000.
* **Telemetry & Findings:** Windows Defender Firewall successfully dropped unauthorized SYN probes (`filtered`). When port 8000 was active, **Sysmon Event ID 3 (Network Connection)** captured the full 3-way handshake, source IP (`192.168.56.101`), and corresponding listening process (`powershell.exe`).
* **MITRE ATT&CK:** Reconnaissance: Active Scanning (T1595.001).

### Scenario 2: Linux SSH Brute-Force & Credential Access
* **Adversary Activity:** Automated dictionary attack against user `utkan` using Hydra over port 22.
* **Telemetry & Findings:** Ubuntu PAM/SSH subsystems generated high-frequency authentication failure logs. Wazuh correlated individual failures (`Rule 5760`, Level 5) and escalated to a **Level 10 Alert (`Rule 2502`)**: *User missed the password more than one time* mapped to Credential Access.
* **MITRE ATT&CK:** Credential Access: Brute Force (T1110).

### Scenario 3: Windows Authentication & Lateral Movement
* **Adversary Activity:** Remote SMB authentication probing (`smbclient`) targeting local user credentials.
* **Telemetry & Findings:** Windows Security Log captured **Event ID 4625**. Extracted artifacts revealed:
  * `LogonType: 3` (Network logon via SMB/RPC, not physical or RDP).
  * `SubStatus: 0xC000006A` (Valid username, incorrect password).
* **MITRE ATT&CK:** Credential Access: Password Spraying (T1110.003).

### Scenario 4: Suspicious Obfuscated Execution
* **Adversary Activity:** Execution of Base64-encoded payload via PowerShell in a hidden window (`-WindowStyle Hidden -EncodedCommand`).
* **Telemetry & Findings:** Sysmon Event ID 1 caught the process creation tree (`powershell.exe` -> `powershell.exe`). Wazuh triggered **Rule Level 12 Alert (`Rule 92033`)**. Manual triage decoded the payload to uncover the underlying C2 check-in command.
* **MITRE ATT&CK:** Execution: PowerShell (T1059.001), Defense Evasion: Obfuscated Information (T1027).

### Scenario 5: Windows Persistence (Registry Run Key & Tasks)
* **Adversary Activity:** Creation of autorun registry key under `HKCU\...\CurrentVersion\Run` and scheduled task targeting staging directories (`C:\Windows\Temp\malware.exe`).
* **Telemetry & Findings:** Wazuh triggered **Level 10 Alert (`Rule 92041`)** detecting registry modifications with Base64/suspicious execution patterns originating from `reg.exe` spawned by PowerShell.
* **MITRE ATT&CK:** Persistence: Registry Run Keys (T1547.001), Scheduled Task (T1053.005).

### Scenario 6: End-to-End Multi-Stage Incident Investigation
* **Adversary Activity:** Multi-stage intrusion chaining external recon, brute-force access to Linux, LOLBin download on Windows via `certutil.exe -urlcache -split -f`, and system persistence.
* **Incident Handling & Triage:** Aggregated timeline analysis on Wazuh Dashboard (`rule.level >= 5`) mapped the exact intrusion path, identifying the attacker IP, staging binaries (`beacon.exe`), and triggering a comprehensive NIST SP 800-61 incident response report.
* **MITRE ATT&CK:** Command and Control: Ingress Tool Transfer (T1105), Execution (TA0002), Persistence (TA0003).

---

## Key Takeaways & Analytical Skills Demonstrated
* **Process Lineage Analysis:** Utilizing Sysmon Event ID 1 (`ParentImage` -> `Image`) to distinguish administrative scripts from anomalous process execution.
* **Authentication Triage:** Differentiating between local (`LogonType 2`), network (`LogonType 3`), and remote desktop (`LogonType 10`) logins via Windows Event IDs 4624/4625.
* **Log Pipeline Troubleshooting:** Deploying and configuring Wazuh agents across Linux/Windows environments with custom Sysmon XML schemas.
* **SIEM Correlation:** Building custom DQL filters and column-based investigation boards for root cause timeline reconstruction.
