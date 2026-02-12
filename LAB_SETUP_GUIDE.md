# Threat Hunting Lab Setup Guide

## Overview

This guide will walk you through building a complete threat hunting lab environment from scratch. Total setup time: 4-6 hours.

## Hardware Requirements

### Minimum Specifications
- **CPU:** 4 cores
- **RAM:** 16GB
- **Storage:** 100GB free space
- **Hypervisor:** VirtualBox 7.0+ or VMware Workstation 17+

### Recommended Specifications
- **CPU:** 8 cores
- **RAM:** 32GB
- **Storage:** 200GB SSD
- **Network:** Dedicated NIC for lab network isolation

## Lab Components

You will build three virtual machines:

1. **SIEM Server** (Ubuntu 22.04)
   - 4 CPU cores
   - 8GB RAM
   - 80GB disk
   - Elastic Stack or Security Onion

2. **Domain Controller** (Windows Server 2019/2022)
   - 2 CPU cores
   - 4GB RAM
   - 60GB disk
   - Active Directory, DNS, DHCP

3. **Windows Workstation** (Windows 10 Pro)
   - 2 CPU cores
   - 4GB RAM
   - 60GB disk
   - Attack target and testing platform

## Phase 1: Network Configuration

### 1.1 Create Isolated Network

**VirtualBox:**
```bash
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.100.1 --netmask 255.255.255.0
```

**VMware:**
- Go to Edit > Virtual Network Editor
- Add Network: VMnet2
- Subnet IP: 192.168.100.0
- Subnet Mask: 255.255.255.0
- Disable DHCP (we'll use our DC for DHCP)

### 1.2 IP Address Schema

| Host | IP Address | Role |
|------|-----------|------|
| Host Machine | 192.168.100.1 | Gateway |
| SIEM Server | 192.168.100.10 | Log aggregation |
| Domain Controller | 192.168.100.20 | AD, DNS, DHCP |
| Windows Workstation | 192.168.100.30 | Attack target |

## Phase 2: SIEM Server Setup (Elastic Stack)

### 2.1 Install Ubuntu Server 22.04

1. Download Ubuntu Server ISO: https://ubuntu.com/download/server
2. Create VM with specifications above
3. Install with default options
4. Set hostname: `siem-server`
5. Create user: `hunter`

### 2.2 Install Elastic Stack

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install prerequisites
sudo apt install -y apt-transport-https curl gnupg2

# Add Elastic GPG key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Add Elastic repository
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Update package index
sudo apt update

# Install Elasticsearch
sudo apt install -y elasticsearch

# Configure Elasticsearch
sudo nano /etc/elasticsearch/elasticsearch.yml
```

**Elasticsearch Configuration (`/etc/elasticsearch/elasticsearch.yml`):**
```yaml
cluster.name: threat-hunting-lab
node.name: siem-node-1
network.host: 192.168.100.10
http.port: 9200
discovery.type: single-node

# Security settings
xpack.security.enabled: true
xpack.security.enrollment.enabled: true
```

```bash
# Start Elasticsearch
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Set Elasticsearch passwords
sudo /usr/share/elasticsearch/bin/elasticsearch-setup-passwords interactive
# Use password: ThreatHunter2026! (or your chosen password)
```

### 2.3 Install Kibana

```bash
# Install Kibana
sudo apt install -y kibana

# Configure Kibana
sudo nano /etc/kibana/kibana.yml
```

**Kibana Configuration (`/etc/kibana/kibana.yml`):**
```yaml
server.port: 5601
server.host: "192.168.100.10"
elasticsearch.hosts: ["http://192.168.100.10:9200"]
elasticsearch.username: "elastic"
elasticsearch.password: "ThreatHunter2026!"
```

```bash
# Start Kibana
sudo systemctl enable kibana
sudo systemctl start kibana

# Verify services
sudo systemctl status elasticsearch
sudo systemctl status kibana
```

Access Kibana: `http://192.168.100.10:5601`

### 2.4 Install Elastic Agent (Fleet Server)

```bash
# Install Elastic Agent
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.11.0-linux-x86_64.tar.gz
tar xzvf elastic-agent-8.11.0-linux-x86_64.tar.gz
cd elastic-agent-8.11.0-linux-x86_64
```

Setup Fleet in Kibana (Management > Fleet):
1. Add Fleet Server
2. Generate service token
3. Install Fleet Server on SIEM VM

## Phase 3: Domain Controller Setup

### 3.1 Install Windows Server 2022

1. Create VM with specifications above
2. Install Windows Server 2022 Standard (Desktop Experience)
3. Set computer name: `DC01`
4. Configure static IP:
   - IP: 192.168.100.20
   - Subnet: 255.255.255.0
   - Gateway: 192.168.100.1
   - DNS: 127.0.0.1 (itself)

### 3.2 Install Active Directory Domain Services

**PowerShell (as Administrator):**
```powershell
# Install AD DS Role
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to Domain Controller
Install-ADDSForest `
    -DomainName "hunter.lab" `
    -DomainNetbiosName "HUNTER" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "ThreatHunter2026!" -AsPlainText -Force) `
    -Force

# Server will reboot
```

### 3.3 Configure DHCP Server

```powershell
# Install DHCP Role
Install-WindowsFeature -Name DHCP -IncludeManagementTools

# Authorize DHCP server in AD
Add-DhcpServerInDC -DnsName "DC01.hunter.lab" -IPAddress 192.168.100.20

# Create DHCP Scope
Add-DhcpServerv4Scope `
    -Name "Lab Network" `
    -StartRange 192.168.100.100 `
    -EndRange 192.168.100.200 `
    -SubnetMask 255.255.255.0 `
    -State Active

# Set DHCP Options
Set-DhcpServerv4OptionValue `
    -ScopeId 192.168.100.0 `
    -Router 192.168.100.1 `
    -DnsServer 192.168.100.20

# Restart DHCP service
Restart-Service DHCPServer
```

### 3.4 Create Test Users

```powershell
# Create Organizational Units
New-ADOrganizationalUnit -Name "HuntLab Users" -Path "DC=hunter,DC=lab"
New-ADOrganizationalUnit -Name "HuntLab Computers" -Path "DC=hunter,DC=lab"

# Create test users
$Password = ConvertTo-SecureString "Password123!" -AsPlainText -Force

New-ADUser -Name "John Admin" -GivenName "John" -Surname "Admin" `
    -SamAccountName "jadmin" -UserPrincipalName "jadmin@hunter.lab" `
    -Path "OU=HuntLab Users,DC=hunter,DC=lab" `
    -AccountPassword $Password -Enabled $true

New-ADUser -Name "Sarah User" -GivenName "Sarah" -Surname "User" `
    -SamAccountName "suser" -UserPrincipalName "suser@hunter.lab" `
    -Path "OU=HuntLab Users,DC=hunter,DC=lab" `
    -AccountPassword $Password -Enabled $true

# Add John to Domain Admins
Add-ADGroupMember -Identity "Domain Admins" -Members "jadmin"
```

## Phase 4: Windows 10 Workstation Setup

### 4.1 Install Windows 10

1. Create VM with specifications above
2. Install Windows 10 Pro
3. Set computer name: `WS01`
4. Configure network (use DHCP from DC01)

### 4.2 Join Domain

**PowerShell (as Administrator):**
```powershell
# Join domain
Add-Computer -DomainName "hunter.lab" -Credential (Get-Credential) -Restart
# Use credentials: HUNTER\Administrator
```

## Phase 5: Deploy Sysmon

### 5.1 Download Sysmon

Download from: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

### 5.2 Download SwiftOnSecurity Config

```powershell
# On both DC01 and WS01
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\sysmonconfig.xml"
```

### 5.3 Install Sysmon

```powershell
# Extract Sysmon to C:\Tools\
# Install with configuration
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmonconfig.xml

# Verify installation
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
```

### 5.4 Enable PowerShell Logging

```powershell
# Create registry keys for PowerShell logging
$PSLogging = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $PSLogging -Force
New-ItemProperty -Path $PSLogging -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWORD -Force

$PSTranscription = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
New-Item -Path $PSTranscription -Force
New-ItemProperty -Path $PSTranscription -Name "EnableTranscripting" -Value 1 -PropertyType DWORD -Force
New-ItemProperty -Path $PSTranscription -Name "OutputDirectory" -Value "C:\PSTranscripts" -Force
```

## Phase 6: Log Forwarding to SIEM

### 6.1 Install Winlogbeat on Windows Systems

**On DC01 and WS01:**

```powershell
# Download Winlogbeat
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.11.0-windows-x86_64.zip" -OutFile "C:\Tools\winlogbeat.zip"

# Extract
Expand-Archive -Path "C:\Tools\winlogbeat.zip" -DestinationPath "C:\Program Files\"
Rename-Item "C:\Program Files\winlogbeat-8.11.0-windows-x86_64" "Winlogbeat"
```

### 6.2 Configure Winlogbeat

**Edit `C:\Program Files\Winlogbeat\winlogbeat.yml`:**

```yaml
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Security
  - name: System
  - name: Application
  - name: Microsoft-Windows-PowerShell/Operational
  - name: Windows PowerShell

output.elasticsearch:
  hosts: ["192.168.100.10:9200"]
  username: "elastic"
  password: "ThreatHunter2026!"
  index: "winlogbeat-%{+yyyy.MM.dd}"

setup.kibana:
  host: "192.168.100.10:5601"
```

```powershell
# Install as service
cd "C:\Program Files\Winlogbeat"
.\install-service-winlogbeat.ps1

# Test configuration
.\winlogbeat.exe test config
.\winlogbeat.exe test output

# Start service
Start-Service winlogbeat
Set-Service winlogbeat -StartupType Automatic
```

## Phase 7: Install Atomic Red Team

### 7.1 Install on WS01

```powershell
# Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics

# Verify installation
Get-Command Invoke-AtomicTest
```

### 7.2 Test Atomic Execution

```powershell
# Test with a simple technique
Invoke-AtomicTest T1003.001 -ShowDetails
Invoke-AtomicTest T1003.001 -TestNumbers 1 -CheckPrereqs
```

## Phase 8: Verification Checklist

### 8.1 Network Connectivity
- [ ] All VMs can ping each other
- [ ] All VMs can resolve hunter.lab domain
- [ ] Internet access working (if configured)

### 8.2 Active Directory
- [ ] DC01 is domain controller
- [ ] WS01 is domain-joined
- [ ] Test users can log in
- [ ] DNS resolution working

### 8.3 SIEM Stack
- [ ] Elasticsearch running on port 9200
- [ ] Kibana accessible on http://192.168.100.10:5601
- [ ] Can log in with elastic credentials

### 8.4 Logging Pipeline
- [ ] Sysmon installed on both Windows systems
- [ ] Sysmon events appearing in Event Viewer
- [ ] Winlogbeat service running
- [ ] Logs appearing in Kibana Discover

### 8.5 Attack Simulation
- [ ] Atomic Red Team installed
- [ ] Can execute test techniques
- [ ] Atomic tests generating Sysmon events

## Phase 9: Create Kibana Dashboards

### 9.1 Import Index Patterns

In Kibana:
1. Go to Management > Stack Management > Index Patterns
2. Create index pattern: `winlogbeat-*`
3. Select timestamp field: `@timestamp`

### 9.2 Useful Searches to Save

**Sysmon Process Creation (EID 1):**
```
event.code: 1 and event.provider: "Microsoft-Windows-Sysmon"
```

**Suspicious PowerShell:**
```
event.code: 4104 and powershell.file.script_block_text: *
```

**Logon Events:**
```
event.code: (4624 or 4625) and winlog.computer_name: *
```

## Troubleshooting

### Elasticsearch won't start
```bash
# Check logs
sudo journalctl -u elasticsearch -f

# Common fix: Increase VM memory or heap size
sudo nano /etc/elasticsearch/jvm.options
# Set: -Xms4g and -Xmx4g (for 8GB RAM VM)
```

### Logs not appearing in Kibana
```powershell
# On Windows systems, check Winlogbeat
Get-Service winlogbeat
Get-EventLog -LogName Application -Source winlogbeat -Newest 50

# Test connectivity
Test-NetConnection -ComputerName 192.168.100.10 -Port 9200
```

### Domain join fails
```powershell
# Verify DNS
nslookup hunter.lab
nslookup dc01.hunter.lab

# Reset secure channel
Test-ComputerSecureChannel -Repair -Credential (Get-Credential)
```

## Next Steps

Once your lab is fully operational:

1. **Baseline Normal Activity:** Run for 24 hours collecting normal telemetry
2. **Execute Atomic Tests:** Start with T1003.001 (LSASS dumping)
3. **Begin Hunting:** Use queries from hunt-queries/ directory
4. **Create Detections:** Write Sigma rules for findings
5. **Document Everything:** Take screenshots and notes

## Additional Resources

- [Sysmon Configuration Guide](SYSMON_CONFIG.md)
- [Hunt Query Examples](../hunt-queries/)
- [Detection Rule Templates](../detection-rules/)
- [Atomic Red Team Docs](https://github.com/redcanaryco/atomic-red-team/wiki)

---

**Lab Setup Complete!** You now have a fully functional threat hunting environment. Start hunting! 🎯
