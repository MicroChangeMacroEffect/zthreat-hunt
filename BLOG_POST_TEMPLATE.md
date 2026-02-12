# From Hunt to Detection: Tracking Credential Dumping in the Wild

*A practical guide to detecting LSASS memory dumping attacks*

---

## Introduction

Credential theft remains one of the most critical attack vectors in modern cyber campaigns. In this post, I'll walk you through my hands-on threat hunting project where I built a lab environment, simulated real-world attacks, and created production-ready detection rules.

**Skills Demonstrated:**
- Threat hunting methodology
- SIEM query development (Elastic KQL)
- Detection rule engineering (Sigma format)
- MITRE ATT&CK mapping
- Log analysis and telemetry correlation

---

## Lab Environment

I built a complete threat hunting lab using VirtualBox with three virtual machines:

**Architecture:**
```
┌────────────────────────────────────────────────┐
│              Threat Hunting Lab                 │
├────────────────────────────────────────────────┤
│  SIEM (Elastic Stack)  │  Domain Controller    │
│  Ubuntu 22.04          │  Windows Server 2022  │
│  8GB RAM               │  4GB RAM              │
│  Elasticsearch + Kibana│  Active Directory     │
│                        │  Sysmon               │
├────────────────────────┴───────────────────────┤
│              Windows 10 Workstation             │
│              Attack Target                      │
│              Sysmon + Winlogbeat               │
└────────────────────────────────────────────────┘
```

**Data Sources:**
- Sysmon (SwiftOnSecurity configuration)
- Windows Security Event Logs
- Windows PowerShell Logs
- Network telemetry (Zeek)

**Key Tools:**
- Elastic Stack (SIEM)
- Atomic Red Team (attack simulation)
- Sigma (detection rule format)

---

## The Hunt: Credential Dumping (T1003.001)

### Hypothesis

*"Adversaries will access LSASS process memory to extract credentials, leaving forensic artifacts detectable via process access monitoring."*

### Why This Matters

Credential dumping, particularly LSASS memory extraction, is a technique used by virtually every sophisticated threat actor:
- **APT29** (Cozy Bear) - Russian state-sponsored
- **Scattered Spider** - Recent high-profile ransomware campaigns
- **Conti, LockBit, BlackCat** - Ransomware operators

The technique allows attackers to:
1. Steal credentials without triggering authentication failures
2. Enable lateral movement across the network
3. Escalate privileges using stolen admin credentials

---

## Methodology

### Phase 1: Baseline Collection

Before hunting for malicious activity, I established what "normal" looks like.

**Baseline Query (24 hours):**
```kql
event.code: 10 AND winlog.event_data.TargetImage: *lsass.exe
| stats count() by winlog.event_data.SourceImage
| sort count desc
```

**Normal LSASS Access Patterns:**
- `svchost.exe` - Windows services (most frequent)
- `csrss.exe` - Client/Server Runtime Subsystem
- `MsMpEng.exe` - Windows Defender
- `SenseIR.exe` - Windows Defender ATP

**Key Insight:** Legitimate system processes accounted for 99.8% of LSASS access events. Any deviation from this baseline warrants investigation.

### Phase 2: Attack Simulation

Using Atomic Red Team, I simulated three common credential dumping techniques:

**Test 1: ProcDump LSASS Dumping**
```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 1
# Executes: procdump.exe -ma lsass.exe lsass.dmp
```

**Test 2: Mimikatz Execution**
```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 2
# Executes: mimikatz.exe sekurlsa::logonpasswords
```

**Test 3: Comsvcs.dll MiniDump**
```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 3
# Executes: rundll32.exe comsvcs.dll,MiniDump [PID] dump.dmp full
```

---

## Hunt Execution & Findings

### Finding #1: ProcDump LSASS Memory Dump

**Hunt Query:**
```kql
event.code: 10 AND 
winlog.event_data.TargetImage: *lsass.exe AND 
winlog.event_data.SourceImage: *procdump*.exe
```

**Detection:**
```
Timestamp: 2026-02-12 14:23:15.342
Computer: WS01.hunter.lab
SourceImage: C:\Tools\procdump64.exe
TargetImage: C:\Windows\System32\lsass.exe
GrantedAccess: 0x1fffff (PROCESS_ALL_ACCESS)
User: HUNTER\jadmin
```

**Analysis:**
- ✅ Confirmed: Suspicious LSASS access
- ✅ `GrantedAccess: 0x1fffff` indicates full memory read/write
- ✅ Tool staged in `C:\Tools\` (non-standard location)
- ✅ Executed by domain admin account

**Follow-up Investigation:**

I pivoted to look for the dump file creation:

```kql
event.code: 11 AND 
file.name: lsass.dmp AND 
@timestamp > 2026-02-12T14:23:00
```

**Result:** Dump file created at `C:\Tools\lsass.dmp` (42.3 MB)

---

### Finding #2: Mimikatz Credential Theft

**Hunt Query:**
```kql
event.code: 1 AND 
process.command_line: *sekurlsa::logonpasswords*
```

**Detection:**
```
CommandLine: mimikatz.exe privilege::debug sekurlsa::logonpasswords
Image: C:\Users\jadmin\Downloads\mimikatz.exe
User: HUNTER\jadmin
ParentImage: C:\Windows\System32\cmd.exe
```

**IOCs Extracted:**
- File Hash (MD5): `e4a95b44c40c1d9d96e6c4a6a86ff5d0`
- File Hash (SHA256): `8d4f9e2b7... [truncated]`
- VirusTotal Detections: 67/72 (confirmed malware)

**Network Activity Correlation:**

Checked for lateral movement within 1 hour:

```kql
event.code: 4624 AND 
winlog.logon.type: 3 AND 
user.name: jadmin AND 
@timestamp > 2026-02-12T14:23:00 AND 
@timestamp < 2026-02-12T15:23:00
```

**Result:** 3 network logons to different hosts detected - **confirmed lateral movement**.

---

### Finding #3: Comsvcs.dll Technique

**Hunt Query:**
```kql
event.code: 1 AND 
process.command_line: (*comsvcs.dll* AND *MiniDump*)
```

**Detection:**
```
CommandLine: rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump 624 C:\temp\m.dmp full
Image: C:\Windows\System32\rundll32.exe
User: HUNTER\suser (standard user)
```

**Key Insight:** This technique is particularly insidious because:
- Uses native Windows binary (rundll32.exe)
- Comsvcs.dll is a legitimate Microsoft DLL
- Often bypasses application whitelisting
- More difficult to detect than tool-based dumping

---

## Detection Engineering

Based on my hunt findings, I created production-ready Sigma detection rules.

### Rule 1: LSASS Process Access by Uncommon Process

```yaml
title: LSASS Memory Access by Uncommon Process
id: a7f8a6e8-9b2c-4d1e-8f3a-1c5d7e9f2a3b
status: stable
description: Detects process access to LSASS memory indicating credential dumping
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    product: windows
    category: process_access
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1410'
            - '0x1438'
            - '0x143a'
            - '0x1fffff'
    filter_system:
        SourceImage|endswith:
            - '\svchost.exe'
            - '\csrss.exe'
            - '\MsMpEng.exe'
    condition: selection and not filter_system
falsepositives:
    - Legitimate administrative tools
    - EDR/AV solutions
level: high
```

**Tuning Notes:**
- Initial deployment generated 12 false positives in 24 hours
- Added filters for EDR agent (`SenseIR.exe`, `MsSense.exe`)
- Final false positive rate: < 1 per day

---

### Rule 2: Credential Dumping Tool Execution

```yaml
title: Potential Credential Dumping Tool Execution
id: b8e7c3f1-4a9d-45e2-8c6f-9a1b2c3d4e5f
status: stable
description: Detects execution of known credential dumping tools
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection_names:
        Image|endswith:
            - '\procdump.exe'
            - '\mimikatz.exe'
    selection_cmdline:
        CommandLine|contains:
            - 'sekurlsa::'
            - 'comsvcs.dll,MiniDump'
    condition: selection_names or selection_cmdline
level: critical
```

---

## Results & Impact

### Hunt Metrics

| Metric | Value |
|--------|-------|
| Total Events Analyzed | 487,394 |
| Suspicious Events Flagged | 27 |
| True Positives Confirmed | 8 |
| False Positives | 19 |
| Detection Rules Created | 3 |
| MITRE Techniques Covered | T1003.001, T1003.002 |

### Detection Coverage

My rules now provide automated detection for:
- ✅ LSASS memory dumping (all major techniques)
- ✅ Mimikatz and derivative tools
- ✅ Microsoft Sysinternals abuse (ProcDump, etc.)
- ✅ Native Windows DLL abuse (comsvcs.dll)

### Real-World Value

These detections were deployed to our production SIEM and within the first week:
- **Detected 1 legitimate security team pentest** (coordinated - good validation!)
- **Prevented 0 actual breaches** (yet!) but significantly improved our detection posture
- **Reduced MTTD (Mean Time To Detect)** for credential theft from unknown to ~30 seconds

---

## Lessons Learned

### What Worked Well

1. **Hypothesis-Driven Approach:** Starting with a clear hypothesis kept the hunt focused
2. **Baseline First:** Understanding normal patterns made anomalies obvious
3. **Iterative Tuning:** Detection rules improved significantly through multiple refinement cycles
4. **Documentation:** Detailed notes made it easy to reproduce findings and explain to stakeholders

### Challenges Faced

1. **False Positives:** Initial rules were too broad, triggering on legitimate admin activity
2. **EDR Noise:** Security tools themselves access LSASS frequently
3. **Detection Evasion:** Comsvcs.dll technique is harder to detect than tool-based approaches
4. **Log Volume:** Sysmon generates significant data - required careful configuration tuning

### Areas for Improvement

- **Network Telemetry:** Should have captured C2 beacon patterns more aggressively
- **User Behavior Analytics:** Correlating credential theft with account usage patterns
- **Automated Response:** Could automate containment when high-confidence detections fire

---

## Defensive Recommendations

Based on this research, I recommend organizations:

1. **Enable LSASS Protection (RunAsPPL)**
   ```powershell
   reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
   ```

2. **Deploy Credential Guard** (Windows 10 Enterprise/Education)
   - Protects LSASS using virtualization-based security
   - Prevents most memory dumping techniques

3. **Implement Application Whitelisting**
   - Restrict execution of tools like ProcDump to approved admins
   - Use WDAC or AppLocker policies

4. **Monitor LSASS Access Aggressively**
   - Alert on any non-system process accessing LSASS
   - Investigate dump file creation immediately

5. **Hunt Proactively**
   - Don't wait for alerts - actively search for credential theft indicators
   - Review Sysmon Event ID 10 regularly

---

## Conclusion

This project demonstrated the complete threat hunting lifecycle from hypothesis to production detection. The key takeaway: **effective threat hunting requires understanding both normal baselines and adversary techniques**.

By combining proper telemetry collection (Sysmon), structured hunt methodology, and detection engineering, I successfully created rules that detect credential dumping with high confidence and low false positive rates.

**Next Steps:**
- Expand to cloud environments (Azure AD, AWS IAM)
- Hunt for lateral movement patterns post-credential theft
- Integrate threat intelligence feeds for proactive hunting

---

## Resources

**GitHub Repository:** [github.com/yourname/threat-hunting-lab](https://github.com/yourname/threat-hunting-lab)

**Detection Rules:** All Sigma rules available in the repository

**References:**
- [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Sysmon Configuration Guide](https://github.com/SwiftOnSecurity/sysmon-config)

---

*Published: February 12, 2026*  
*Author: [Your Name] | Threat Hunter | [LinkedIn](https://linkedin.com/in/yourprofile)*

---

**Want to try this yourself?**

1. Clone the repository: `git clone https://github.com/yourname/threat-hunting-lab`
2. Follow the setup guide: `cat documentation/LAB_SETUP_GUIDE.md`
3. Start hunting using the provided playbooks!

**Questions or feedback?** Drop a comment below or reach out on [LinkedIn](https://linkedin.com/in/yourprofile)!

---

## Template Instructions

**To customize this blog post:**

1. Replace `[Your Name]` with your actual name
2. Update GitHub/LinkedIn URLs with your profiles
3. Add actual screenshots from your lab:
   - SIEM dashboard showing detections
   - Sysmon events in Event Viewer
   - Kibana visualizations
   - Detection rule firing alerts

4. Include real metrics from your hunt:
   - Actual event counts
   - Real timestamps
   - Your specific findings

5. Add a "Behind the Scenes" section if desired:
   - Challenges you faced
   - How long each phase took
   - Tools that didn't work as expected

6. Consider adding:
   - Code snippets you're particularly proud of
   - Visualization screenshots
   - Your lab architecture diagram
   - Demo video walkthrough (YouTube/Loom)

**Publishing Platforms:**
- Medium (maximum reach)
- LinkedIn Articles (professional network)
- Personal blog (full control)
- Dev.to (tech community)
- GitHub README (part of portfolio)

**Promotion Tips:**
- Share on LinkedIn with #ThreatHunting #Cybersecurity #BlueTeam tags
- Post in r/cybersecurity, r/blueteam, r/threathunting
- Tweet with security community hashtags
- Email to security newsletters (TL;DR Sec, Risky Business)
