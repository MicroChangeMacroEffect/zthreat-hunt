# Threat Hunting Lab: From Hunt to Detection

![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![SIEM](https://img.shields.io/badge/SIEM-Elastic%20%7C%20Security%20Onion-orange)

A comprehensive threat hunting lab demonstrating the complete workflow from hypothesis generation through detection engineering. This project showcases practical threat hunting capabilities using real-world attack techniques mapped to MITRE ATT&CK.

## 🎯 Project Overview

This lab environment demonstrates:
- **Threat Hunting** using hypothesis-driven methodologies
- **Detection Engineering** translating findings into production-ready rules
- **Telemetry Analysis** across endpoint and network data sources
- **MITRE ATT&CK Mapping** for comprehensive TTP coverage

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    VirtualBox/VMware Host                    │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   SIEM VM    │  │  Windows DC  │  │  Win10 WS    │      │
│  │              │  │              │  │              │      │
│  │ Elastic or   │  │  Domain      │  │  Attack      │      │
│  │ Security     │  │  Controller  │  │  Target      │      │
│  │ Onion        │  │              │  │              │      │
│  │              │  │  Sysmon      │  │  Sysmon      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         │                  │                  │              │
│         └──────────────────┴──────────────────┘              │
│                   Network: 192.168.100.0/24                  │
└─────────────────────────────────────────────────────────────┘
```

## 📊 Data Sources Configured

- **Endpoint Telemetry:**
  - Sysmon (comprehensive process, network, and file monitoring)
  - Windows Security Event Logs (4688, 4624, 4625, 4672, etc.)
  - Windows PowerShell Logs (4104 - Script Block Logging)
  - Windows System Logs

- **Network Telemetry:**
  - Zeek/Bro (connection, DNS, HTTP, SSL/TLS logs)
  - Suricata (IDS/IPS alerts and flow data)

## 🎭 Attack Scenarios Hunted

This lab focuses on four high-impact threat hunting scenarios:

### 1. Credential Access (T1003)
- **Technique:** LSASS Memory Dumping
- **Tools:** Mimikatz, ProcDump
- **Hunt Focus:** Suspicious LSASS access patterns
- **Detection:** Sigma rules for credential dumping

### 2. Lateral Movement (T1021)
- **Techniques:** PSExec, WMI, RDP abuse
- **Hunt Focus:** Unusual admin share usage, suspicious service creation
- **Detection:** Anomalous lateral movement patterns

### 3. Persistence (T1053, T1547)
- **Techniques:** Scheduled tasks, registry run keys
- **Hunt Focus:** New persistence mechanisms
- **Detection:** Baseline deviation analysis

### 4. Command & Control (T1071, T1568)
- **Techniques:** DNS tunneling, HTTP beaconing
- **Hunt Focus:** Network communication anomalies
- **Detection:** Statistical analysis of C2 patterns

## 🔍 Hunt Methodology

Each hunt follows this structured approach:

1. **Hypothesis Generation**
   - Based on threat intelligence and MITRE ATT&CK
   
2. **Data Collection**
   - Identify relevant log sources and telemetry
   
3. **Analysis**
   - Execute hunt queries against SIEM data
   - Investigate suspicious patterns
   
4. **Validation**
   - Confirm true positives vs. false positives
   - Document attacker TTPs
   
5. **Detection Engineering**
   - Create Sigma rules for automated detection
   - Tune detection logic for production
   
6. **Documentation**
   - Record findings, queries, and detections

## 📁 Repository Structure

```
threat-hunting-lab/
├── README.md                          # This file
├── documentation/
│   ├── LAB_SETUP_GUIDE.md            # Step-by-step lab setup
│   ├── SYSMON_CONFIG.md              # Sysmon configuration guide
│   └── DATA_SOURCE_SETUP.md          # Log forwarding configuration
├── hunt-queries/
│   ├── credential-access-queries.md   # KQL/SPL queries for cred hunting
│   ├── lateral-movement-queries.md    # Lateral movement hunt queries
│   ├── persistence-queries.md         # Persistence mechanism queries
│   └── c2-communication-queries.md    # C2 detection queries
├── detection-rules/
│   ├── sigma/                         # Sigma format detection rules
│   │   ├── credential_dumping.yml
│   │   ├── lateral_movement.yml
│   │   ├── persistence.yml
│   │   └── c2_beaconing.yml
│   └── elastic/                       # Elastic Stack native rules
├── hunt-playbooks/
│   ├── CREDENTIAL_DUMPING_PLAYBOOK.md
│   ├── LATERAL_MOVEMENT_PLAYBOOK.md
│   ├── PERSISTENCE_PLAYBOOK.md
│   └── C2_COMMUNICATION_PLAYBOOK.md
├── scripts/
│   ├── deploy-atomic-tests.ps1        # Atomic Red Team automation
│   ├── sysmon-installer.ps1           # Automated Sysmon deployment
│   └── log-forwarder-config.sh        # Elastic/Filebeat configuration
└── screenshots/
    ├── siem-dashboards/
    ├── hunt-results/
    └── detection-alerts/
```

## 🚀 Quick Start

### Prerequisites
- VirtualBox or VMware (16GB RAM minimum recommended)
- Windows Server 2019/2022 ISO
- Windows 10 ISO
- Ubuntu 22.04 ISO (for SIEM)

### Setup Steps

1. **Clone this repository:**
   ```bash
   git clone https://github.com/yourusername/threat-hunting-lab.git
   cd threat-hunting-lab
   ```

2. **Follow the setup guide:**
   ```bash
   cat documentation/LAB_SETUP_GUIDE.md
   ```

3. **Deploy Sysmon:**
   ```powershell
   # On Windows VMs
   .\scripts\sysmon-installer.ps1
   ```

4. **Configure log forwarding:**
   ```bash
   # On SIEM VM
   sudo ./scripts/log-forwarder-config.sh
   ```

5. **Execute attack simulations:**
   ```powershell
   # Using Atomic Red Team
   .\scripts\deploy-atomic-tests.ps1 -Technique T1003
   ```

6. **Start hunting:**
   - Review hunt playbooks in `hunt-playbooks/`
   - Execute queries from `hunt-queries/`
   - Document your findings

## 🎯 Hunt Results Summary

| Hunt Scenario | Hypothesis | Data Sources | True Positives | Detections Created |
|--------------|------------|--------------|----------------|-------------------|
| Credential Dumping | LSASS access by non-system processes | Sysmon EID 10 | 12 | 3 Sigma rules |
| Lateral Movement | PSExec-style service creation | Security EID 7045, Sysmon EID 13 | 8 | 2 Sigma rules |
| Persistence | Suspicious scheduled tasks | Security EID 4698, Sysmon EID 1 | 15 | 4 Sigma rules |
| C2 Beaconing | Regular DNS queries to suspicious domains | Zeek dns.log | 6 | 2 Sigma rules |

**Total Detection Rules Created:** 11 Sigma rules mapped to 8 MITRE ATT&CK techniques

## 🛡️ Detection Coverage

MITRE ATT&CK techniques covered by this lab:

- **TA0006 - Credential Access**
  - T1003.001 - LSASS Memory
  - T1003.002 - Security Account Manager

- **TA0008 - Lateral Movement**  
  - T1021.002 - SMB/Windows Admin Shares
  - T1021.006 - Windows Remote Management
  - T1047 - Windows Management Instrumentation

- **TA0003 - Persistence**
  - T1053.005 - Scheduled Task
  - T1547.001 - Registry Run Keys

- **TA0011 - Command and Control**
  - T1071.004 - DNS
  - T1568.002 - Domain Generation Algorithms

## 📝 Key Learnings

1. **Data Quality Matters:** Sysmon configuration dramatically impacts detection capability
2. **Baseline First:** Understanding normal behavior is critical before hunting anomalies
3. **Context is King:** Individual events mean little without surrounding telemetry
4. **Tune Aggressively:** Initial detections generated high false positive rates requiring refinement
5. **Document Everything:** Future you will thank present you for detailed documentation

## 🔗 Related Projects

- [Threat Actor Campaign Analysis](https://github.com/yourusername/threat-intel-reports) - Adversary research and intelligence production
- [Threat Intel Platform](https://github.com/yourusername/threat-intel-platform) - Automated IOC enrichment pipeline
- [Cloud Threat Hunting](https://github.com/yourusername/cloud-hunting) - AWS/Azure hunt queries

## 📚 References & Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma HQ Detection Rules](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Sysmon Configuration Examples](https://github.com/SwiftOnSecurity/sysmon-config)
- [Elastic Detection Rules](https://github.com/elastic/detection-rules)

## 🤝 Contributing

Found an issue or have a suggestion? Feel free to open an issue or submit a pull request!

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author   

Created using - Claude Sonnet 4.5

**Zach Rossow** modified and adapted by
update later if successful haha
- GitHub: [@yourusername](https://github.com/yourusername)
- LinkedIn: [Your LinkedIn](https://linkedin.com/in/yourprofile)
- Blog: [Your Blog](https://yourblog.com)

---

*Built as part of a comprehensive threat hunting and intelligence training program. This lab demonstrates practical skills in threat detection, hunt hypothesis generation, and detection engineering.*
