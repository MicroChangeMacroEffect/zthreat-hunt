# Threat Hunting Lab - Project Completion Checklist

Use this checklist to track your progress through the Threat Hunting Lab project and ensure all portfolio deliverables are ready for presentation.

---

## 📋 Phase 1: Lab Infrastructure Setup

### Environment Configuration
- [ ] VirtualBox/VMware installed and configured
- [ ] Host-only network created (192.168.100.0/24)
- [ ] All three VMs created:
  - [ ] SIEM Server (Ubuntu 22.04)
  - [ ] Domain Controller (Windows Server 2022)
  - [ ] Windows Workstation (Windows 10)
- [ ] Network connectivity verified between all VMs
- [ ] Internet access configured (if needed)

### Active Directory Setup
- [ ] AD DS role installed and configured
- [ ] Domain `hunter.lab` created
- [ ] DHCP server configured and operational
- [ ] DNS resolution working
- [ ] Test users created (at least 2: admin + standard user)
- [ ] Workstation successfully joined to domain

### SIEM Configuration
- [ ] Elasticsearch installed and running
- [ ] Kibana installed and accessible
- [ ] Fleet Server configured
- [ ] Index patterns created
- [ ] Login credentials tested and documented

**Checkpoint:** Can you access Kibana and see logs from your Windows systems?

---

## 📋 Phase 2: Telemetry Collection

### Sysmon Deployment
- [ ] Sysmon downloaded on both Windows systems
- [ ] SwiftOnSecurity configuration downloaded
- [ ] Sysmon installed on Domain Controller
- [ ] Sysmon installed on Workstation
- [ ] Sysmon service verified running on both systems
- [ ] Sysmon events visible in Event Viewer
- [ ] Custom configuration tuned (if needed)

### Log Forwarding
- [ ] Winlogbeat installed on Domain Controller
- [ ] Winlogbeat installed on Workstation
- [ ] Winlogbeat configuration files updated
- [ ] Winlogbeat service running on both systems
- [ ] Logs appearing in Kibana Discover
- [ ] Data flow verified for all log sources:
  - [ ] Sysmon events (Event ID 1, 3, 10, 11, etc.)
  - [ ] Security events (Event ID 4688, 4624, etc.)
  - [ ] PowerShell logs (Event ID 4104)
  - [ ] System events

### PowerShell Logging
- [ ] Script Block Logging enabled
- [ ] Module Logging enabled
- [ ] Transcription configured
- [ ] PowerShell events flowing to SIEM

**Checkpoint:** Are you seeing at least 100+ events per hour in Kibana?

---

## 📋 Phase 3: Baseline Collection

### Data Collection
- [ ] Lab running for 24-48 hours
- [ ] Normal activity documented
- [ ] Baseline queries executed
- [ ] Common processes accessing LSASS identified
- [ ] Typical GrantedAccess values documented
- [ ] False positive sources identified

### Documentation
- [ ] Baseline results saved
- [ ] Screenshots taken of normal activity
- [ ] Baseline query results exported
- [ ] Known-good process list created
- [ ] Filter criteria documented for detection rules

**Checkpoint:** Do you have a clear understanding of "normal" in your environment?

---

## 📋 Phase 4: Attack Simulation

### Atomic Red Team Setup
- [ ] Atomic Red Team installed
- [ ] Atomics downloaded
- [ ] Installation verified with test execution
- [ ] Execution framework tested

### Attack Execution - T1003.001 (Credential Dumping)
- [ ] Test 1: ProcDump LSASS dump executed
- [ ] Test 2: Mimikatz execution completed
- [ ] Test 3: Comsvcs.dll technique tested
- [ ] Screenshots of attacks taken
- [ ] Process IDs and timestamps documented
- [ ] Attack artifacts preserved (dump files, etc.)

### Additional Techniques (Optional)
- [ ] T1021.002: Lateral movement via SMB
- [ ] T1053.005: Scheduled task persistence
- [ ] T1071.004: DNS C2 communication

**Checkpoint:** Did each attack generate expected telemetry in your SIEM?

---

## 📋 Phase 5: Threat Hunting

### Hunt Execution - Credential Dumping
- [ ] Hunt playbook reviewed
- [ ] Hypothesis documented
- [ ] Hunt queries executed in SIEM
- [ ] Suspicious events identified
- [ ] True positives confirmed
- [ ] False positives documented
- [ ] Parent process analysis performed
- [ ] Network activity correlation completed

### Hunt Documentation
- [ ] Hunt methodology documented
- [ ] Query results saved
- [ ] Screenshots captured:
  - [ ] SIEM dashboard with detections
  - [ ] Individual event details
  - [ ] Process tree/parent-child relationships
  - [ ] Timeline of attack
- [ ] Findings summarized
- [ ] IOCs extracted and documented

**Checkpoint:** Can you walk someone through your hunt step-by-step?

---

## 📋 Phase 6: Detection Engineering

### Sigma Rule Development
- [ ] Rule 1: LSASS access by uncommon process created
- [ ] Rule 2: Credential dumping tool execution created
- [ ] Rule 3: LSASS dump file creation created
- [ ] Rules tested against attack telemetry
- [ ] Rules validated (true positives detected)
- [ ] False positive tuning completed
- [ ] Rules formatted correctly (validated with Sigma tools if available)

### SIEM Rule Deployment
- [ ] Rules converted to SIEM-native format (if needed)
- [ ] Rules imported into SIEM
- [ ] Alert actions configured
- [ ] Notification settings tested
- [ ] Rules documented in GitHub

**Checkpoint:** Do your rules detect attacks without excessive false positives?

---

## 📋 Phase 7: Portfolio Development

### GitHub Repository
- [ ] Repository created (public)
- [ ] README.md completed with:
  - [ ] Project overview
  - [ ] Architecture diagram
  - [ ] Data sources documented
  - [ ] Hunt scenarios described
  - [ ] Results summary included
  - [ ] Detection coverage matrix
- [ ] All files organized in proper structure:
  - [ ] `/documentation`
  - [ ] `/hunt-queries`
  - [ ] `/detection-rules`
  - [ ] `/hunt-playbooks`
  - [ ] `/scripts`
  - [ ] `/screenshots`
- [ ] Meaningful commit messages used
- [ ] .gitignore file created
- [ ] LICENSE file added

### Documentation Quality
- [ ] All markdown files properly formatted
- [ ] Code blocks use syntax highlighting
- [ ] Screenshots clearly labeled
- [ ] Links working and relevant
- [ ] Typos corrected
- [ ] Technical accuracy verified

### Blog Post
- [ ] Blog post template customized
- [ ] Screenshots inserted
- [ ] Real metrics added
- [ ] Code examples tested
- [ ] Proofreading completed
- [ ] Published to platform (Medium/LinkedIn/Personal blog)
- [ ] Shared on social media
- [ ] Added to GitHub README

**Checkpoint:** Can someone clone your repo and understand your project?

---

## 📋 Phase 8: Portfolio Presentation Prep

### Resume/LinkedIn Updates
- [ ] Project added to resume
- [ ] Skills section updated:
  - [ ] Threat Hunting
  - [ ] Detection Engineering
  - [ ] SIEM (Elastic Stack)
  - [ ] Sigma
  - [ ] Sysmon
  - [ ] MITRE ATT&CK
- [ ] LinkedIn profile updated
- [ ] Featured section includes:
  - [ ] GitHub repository link
  - [ ] Blog post link
- [ ] Project description crafted for elevator pitch

### Interview Preparation
- [ ] Can explain project in 2 minutes
- [ ] Can explain project in 10 minutes
- [ ] Can walk through methodology step-by-step
- [ ] Can discuss findings and results
- [ ] Can explain detection rule logic
- [ ] Can discuss false positive tuning
- [ ] Can relate to job requirements
- [ ] Prepared to demonstrate/screenshare if asked

### Talking Points Prepared
- [ ] What was the problem/hypothesis?
- [ ] How did you approach the hunt?
- [ ] What tools and techniques did you use?
- [ ] What did you discover?
- [ ] What detections did you create?
- [ ] What would you do differently?
- [ ] How does this relate to real-world threats?
- [ ] What did you learn?

**Checkpoint:** Practice your 2-minute project explanation out loud!

---

## 📋 Phase 9: Additional Enhancements (Optional)

### Advanced Hunting
- [ ] Additional hunt scenario completed (lateral movement)
- [ ] Another hunt scenario completed (persistence)
- [ ] C2 communication hunting performed
- [ ] Additional Sigma rules created

### Automation
- [ ] Hunt queries automated (scheduled searches)
- [ ] Alert pipeline configured
- [ ] Automated response actions tested
- [ ] Python scripts for analysis created

### Visualization
- [ ] Kibana dashboards created
- [ ] MITRE ATT&CK heatmap generated
- [ ] Timeline visualizations built
- [ ] Custom charts for findings

### Expansion
- [ ] Cloud hunting queries added (AWS/Azure)
- [ ] Container security scenarios
- [ ] Network traffic analysis
- [ ] Malware analysis integration

---

## 📋 Final Quality Check

### Technical Validation
- [ ] All queries execute without errors
- [ ] All Sigma rules validate
- [ ] All scripts run successfully
- [ ] All documentation accurate
- [ ] All links functional

### Portfolio Review
- [ ] GitHub repository is polished and professional
- [ ] README is compelling and clear
- [ ] Code is well-documented
- [ ] Screenshots are high-quality
- [ ] No sensitive information exposed (passwords, IP addresses outside of lab)

### Professional Presentation
- [ ] Spelling and grammar checked
- [ ] Consistent formatting throughout
- [ ] Professional tone maintained
- [ ] Appropriate level of technical detail
- [ ] Tells a clear story

---

## 🎯 Project Completion Criteria

Your project is considered complete when you can answer YES to these questions:

✅ Can a hiring manager clone your GitHub repo and understand what you did?  
✅ Can you explain this project confidently in an interview?  
✅ Do your detection rules actually work?  
✅ Is your documentation professional and clear?  
✅ Can you relate this to real-world threat hunting?  
✅ Are you proud to share this publicly?

---

## 📊 Success Metrics

Track your progress:

| Metric | Target | Actual |
|--------|--------|--------|
| Lab setup time | 4-6 hours | ___ hours |
| Hunt scenarios completed | 1 minimum | ___ scenarios |
| Sigma rules created | 3 minimum | ___ rules |
| Blog posts published | 1 minimum | ___ posts |
| GitHub commits | 20+ | ___ commits |
| Documentation pages | 5+ | ___ pages |
| Screenshots captured | 10+ | ___ images |

---

## 🚀 Next Steps After Completion

1. **Share Your Work**
   - Post on LinkedIn with relevant hashtags
   - Submit to r/blueteam and r/cybersecurity
   - Add to resume and cover letters
   - Include in job applications

2. **Engage with Community**
   - Answer questions about your project
   - Help others starting similar projects
   - Contribute to open-source detection rules
   - Present at local security meetups (if comfortable)

3. **Continue Learning**
   - Move to Project #2: Threat Actor Campaign Analysis
   - Expand into cloud threat hunting
   - Add more hunt scenarios
   - Explore automation and orchestration

4. **Keep Updated**
   - Maintain your repository
   - Update rules as new techniques emerge
   - Refine based on feedback
   - Add new findings periodically

---

## 💡 Tips for Maximum Impact

**For Interviews:**
- Keep your laptop ready to screenshare your GitHub/SIEM
- Have your detection rules memorized
- Prepare examples of false positives you tuned
- Be ready to discuss MITRE ATT&CK in depth

**For Applications:**
- Link to GitHub in every resume/cover letter
- Mention specific techniques (T1003.001, etc.)
- Quantify results (events analyzed, rules created)
- Relate to job description requirements

**For Networking:**
- Share blog post in security communities
- Engage thoughtfully with comments
- Help others with similar projects
- Build relationships with practitioners

---

## 📝 Notes & Lessons Learned

Use this space to document your personal insights:

**Challenges Faced:**
- 
- 
- 

**Solutions Found:**
- 
- 
- 

**Would Do Differently:**
- 
- 
- 

**Most Valuable Learning:**
- 
- 
- 

**Skills Gained:**
- 
- 
- 

---

**Project Start Date:** _____________

**Target Completion Date:** _____________

**Actual Completion Date:** _____________

**Total Hours Invested:** _____________

---

## ✅ Final Signoff

- [ ] I have completed all minimum requirements
- [ ] My portfolio is ready to share publicly
- [ ] I can confidently discuss this project in interviews
- [ ] I am ready to move to the next project

**Signature:** _________________ **Date:** _____________

---

**Congratulations on building your Threat Hunting Lab!** 🎉

This project demonstrates real-world capabilities that employers are actively seeking. You've shown:
- Technical hands-on skills
- Analytical thinking
- Detection engineering capability
- Documentation and communication skills
- Initiative and self-directed learning

**You're ready to be a threat hunter.** Now go land that role! 💪
