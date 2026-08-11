# HackTheBox Writeups - Comprehensive Machine Collection

![HackTheBox Badge](https://img.shields.io/badge/HackTheBox-Writeups-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Last Updated](https://img.shields.io/badge/Last%20Updated-January%202026-blue?style=flat-square)

Comprehensive, methodology-focused writeups for HackTheBox machines. Each writeup includes detailed enumeration, vulnerability analysis, exploitation steps, and privilege escalation techniques.

---

## 📊 Quick Statistics

| Category | Count |
|----------|-------|
| **Total Machines** | 50+ |
| **Windows Machines** | 25+ |
| **Linux Machines** | 25+ |
| **Easy Difficulty** | 15+ |
| **Medium Difficulty** | 20+ |
| **Hard Difficulty** | 15+ |
| **Active Directory** | 8+ |

---

## 🎯 Table of Contents

- [Windows Machines](#windows-machines)
  - [Windows - Easy](#windows---easy)
  - [Windows - Medium](#windows---medium)
  - [Windows - Hard](#windows---hard)
- [Linux Machines](#linux-machines)
  - [Linux - Easy](#linux---easy)
  - [Linux - Medium](#linux---medium)
  - [Linux - Hard](#linux---hard)
- [Active Directory Machines](#active-directory-machines)
- [Getting Started](#getting-started)
- [Techniques Library](#techniques-library)
- [Learning Paths](#learning-paths)
- [Tools & Resources](#tools--resources)

---

## Windows Machines

### Windows - Easy

| # | Machine | Difficulty | AD | Main Technique | CVE(s) | HTB Link | Writeup |
|---|---------|:----------:|:--:|---|---|---|---|
| 1 | **Blue** | 🟢 Easy | ❌ | SMB RCE / EternalBlue | CVE-2017-0144 | [HackTheBox](https://app.hackthebox.com/machines/Blue) | |
| 2 | **Legacy** | 🟢 Easy | ❌ | Samba RCE | CVE-2007-2447 | [HackTheBox](https://app.hackthebox.com/machines/Legacy) | |
| 3 | **Lame** | 🟢 Easy | ❌ | Samba RCE | CVE-2007-2447 | [HackTheBox](https://app.hackthebox.com/machines/Lame) | |
| 4 | **Devel** | 🟢 Easy | ❌ | FTP + WebDAV RCE | N/A | [HackTheBox](https://app.hackthebox.com/machines/Devel) | |
| 5 | **Tenten** | 🟢 Easy | ❌ | RFI + Plugin Exploit | N/A | [HackTheBox](https://app.hackthebox.com/machines/Tenten) | |
| 6 | **Optimum** | 🟢 Easy | ❌ | HFS RCE | CVE-2014-6287 | [HackTheBox](https://app.hackthebox.com/machines/Optimum) | |
| 7 | **Bastard** | 🟢 Easy | ❌ | Drupal RCE | CVE-2018-7600 | [HackTheBox](https://app.hackthebox.com/machines/Bastard) | |
| 8 | **Granny** | 🟢 Easy | ❌ | WebDAV RCE | CVE-2017-7269 | [HackTheBox](https://app.hackthebox.com/machines/Granny) | |

---

### Windows - Medium

| # | Machine | Difficulty | AD | Main Technique | CVE(s) | HTB Link | Writeup |
|---|---------|:----------:|:--:|---|---|---|---|
| 9 | **Active** | 🟡 Medium | ✅ | Kerberoasting / GPP | CVE-2012-1493 | [HackTheBox](https://app.hackthebox.com/machines/Active) | |
| 10 | **Forest** | 🟡 Medium | ✅ | AD Enum / DCSync / Kerberoasting | N/A | [HackTheBox](https://app.hackthebox.com/machines/Forest) |[📝](https://github.com/inspiretravel/OSCP-Journey/blob/main/HTB/lab/forest_report.md) |
| 11 | **Jerry** | 🟡 Medium | ❌ | Tomcat RCE | N/A | [HackTheBox](https://app.hackthebox.com/machines/Jerry) | |
| 12 | **Granny** | 🟡 Medium | ❌ | WebDAV Exploitation | CVE-2017-7269 | [HackTheBox](https://app.hackthebox.com/machines/Granny) | |
| 13 | **Grandpa** | 🟡 Medium | ❌ | WebDAV RCE | CVE-2017-7269 | [HackTheBox](https://app.hackthebox.com/machines/Grandpa) | |
| 14 | **Bankrobber** | 🟡 Medium | ❌ | SQL Injection + RCE | N/A | [HackTheBox](https://app.hackthebox.com/machines/Bankrobber) | |
| 15 | **Remote** | 🟡 Medium | ❌ | UmbracoMvc RCE | CVE-2019-18988 | [HackTheBox](https://app.hackthebox.com/machines/Remote) | |
| 16 | **Buff** | 🟡 Medium | ❌ | Code Execution | N/A | [HackTheBox](https://app.hackthebox.com/machines/Buff) | |
| 17 | **Servmon** | 🟡 Medium | ❌ | File Disclosure + RCE | N/A | [HackTheBox](https://app.hackthebox.com/machines/Servmon) | |
| 18 | **SecNotes** | 🟡 Medium | ❌ | SQL Injection + Priv Esc | N/A | [HackTheBox](https://app.hackthebox.com/machines/SecNotes) | |

---

### Windows - Hard

| # | Machine | Difficulty | AD | Main Technique | CVE(s) | HTB Link | Writeup |
|---|---------|:----------:|:--:|---|---|---|---|
| 19 | **Cascade** | 🔴 Hard | ✅ | AD Enumeration / Privilege Escalation | N/A | [HackTheBox](https://app.hackthebox.com/machines/Cascade) | |
| 20 | **Hackback** | 🔴 Hard | ❌ | Advanced Exploitation | N/A | [HackTheBox](https://app.hackthebox.com/machines/Hackback) | |
| 21 | **Sauna** | 🔴 Hard | ✅ | ASREP Roasting / Priv Esc | N/A | [HackTheBox](https://app.hackthebox.com/machines/Sauna) | |
| 22 | **Monteverde** | 🔴 Hard | ✅ | Azure Enumeration / ADSync | N/A | [HackTheBox](https://app.hackthebox.com/machines/Monteverde) | |
| 23 | **Resolute** | 🔴 Hard | ✅ | Password Spraying / Priv Esc | N/A | [HackTheBox](https://app.hackthebox.com/machines/Resolute) | |

---

## Linux Machines

### Linux - Easy

| # | Machine | Difficulty | AD | Main Technique | CVE(s) | HTB Link | Writeup |
|---|---------|:----------:|:--:|---|---|---|---|
| 24 | **Lame** | 🟢 Easy | ❌ | Samba RCE | CVE-2007-2447 | [HackTheBox](https://app.hackthebox.com/machines/Lame) | |
| 25 | **Popcorn** | 🟢 Easy | ❌ | File Upload Bypass | N/A | [HackTheBox](https://app.hackthebox.com/machines/Popcorn) | |
| 26 | **Nineveh** | 🟢 Easy | ❌ | File Enumeration | N/A | [HackTheBox](https://app.hackthebox.com/machines/Nineveh) | |
| 27 | **Beep** | 🟢 Easy | ❌ | Asterisk Enumeration | CVE-2011-4730 | [HackTheBox](https://app.hackthebox.com/machines/Beep) | |
| 28 | **Shocker** | 🟢 Easy | ❌ | Shellshock RCE | CVE-2014-6271 | [HackTheBox](https://app.hackthebox.com/machines/Shocker) | |
| 29 | **Sense** | 🟢 Easy | ❌ | pfSense RCE | CVE-2014-4688 | [HackTheBox](https://app.hackthebox.com/machines/Sense) | |
| 30 | **Solidstate** | 🟢 Easy | ❌ | Service Exploitation | N/A | [HackTheBox](https://app.hackthebox.com/machines/Solidstate) | |

---

### Linux - Medium

| # | Machine | Difficulty | AD | Main Technique | CVE(s) | HTB Link | Writeup |
|---|---------|:----------:|:--:|---|---|---|---|
| 31 | **Cronos** | 🟡 Medium | ❌ | DNS Zone Transfer | N/A | [HackTheBox](https://app.hackthebox.com/machines/Cronos) | |
| 32 | **Haircut** | 🟡 Medium | ❌ | File Upload RCE | N/A | [HackTheBox](https://app.hackthebox.com/machines/Haircut) | |
| 33 | **Reddish** | 🟡 Medium | ❌ | NoSQL Injection | N/A | [HackTheBox](https://app.hackthebox.com/machines/Reddish) | |
| 34 | **Networked** | 🟡 Medium | ❌ | File Upload Bypass | N/A | [HackTheBox](https://app.hackthebox.com/machines/Networked) | |
| 35 | **Writeup** | 🟡 Medium | ❌ | CMS Exploitation | CVE-2019-9053 | [HackTheBox](https://app.hackthebox.com/machines/Writeup) | |
| 36 | **Traverxec** | 🟡 Medium | ❌ | Web Server Exploit | CVE-2019-16278 | [HackTheBox](https://app.hackthebox.com/machines/Traverxec) | |
| 37 | **OpenAdmin** | 🟡 Medium | ❌ | OpenNetAdmin RCE | CVE-2016-5697 | [HackTheBox](https://app.hackthebox.com/machines/OpenAdmin) |  |
| 38 | **Blunder** | 🟡 Medium | ❌ | CMS RCE | CVE-2019-17087 | [HackTheBox](https://app.hackthebox.com/machines/Blunder) | |

---

### Linux - Hard

| # | Machine | Difficulty | AD | Main Technique | CVE(s) | HTB Link | Writeup |
|---|---------|:----------:|:--:|---|---|---|---|
| 39 | **Rabbit** | 🔴 Hard | ❌ | Container Escape | N/A | [HackTheBox](https://app.hackthebox.com/machines/Rabbit) | |
| 40 | **Feline** | 🔴 Hard | ❌ | Docker Exploitation | N/A | [HackTheBox](https://app.hackthebox.com/machines/Feline) | |
| 41 | **Passage** | 🔴 Hard | ❌ | Exploit Chaining | N/A | [HackTheBox](https://app.hackthebox.com/machines/Passage) | |

---

## Active Directory Machines

Specialized Active Directory exploitation machines covering various AD attack vectors.

| # | Machine | Difficulty | Main Technique | CVE(s) | HTB Link | Writeup |
|---|---------|:----------:|---|---|---|---|
| 1 | **Active** | 🟡 Medium | Group Policy Preferences / Kerberoasting | CVE-2012-1493 | [HackTheBox](https://app.hackthebox.com/machines/Active) | |
| 2 | **Forest** | 🟡 Medium | Active Directory Enumeration / DCSync | N/A | [HackTheBox](https://app.hackthebox.com/machines/Forest) | [📝](https://github.com/inspiretravel/OSCP-Journey/blob/main/HTB/lab/forest_report.md) |
| 3 | **Cascade** | 🔴 Hard | Active Directory Privilege Escalation | N/A | [HackTheBox](https://app.hackthebox.com/machines/Cascade) | |
| 4 | **Sauna** | 🔴 Hard | ASREP Roasting / Kerberoasting | N/A | [HackTheBox](https://app.hackthebox.com/machines/Sauna) | |
| 5 | **Monteverde** | 🔴 Hard | Azure AD / ADSync Exploitation | N/A | [HackTheBox](https://app.hackthebox.com/machines/Monteverde) | [📝](https://github.com/inspiretravel/OSCP/blob/main/HTB/lab/monteverde_report.md)|
| 6 | **Resolute** | 🔴 Hard | Password Spraying / Privilege Escalation | N/A | [HackTheBox](https://app.hackthebox.com/machines/Resolute) | |

---

##  Getting Started 

### For Beginners

Start with these easy machines to build fundamental skills:

1. **Blue** - Basic SMB exploitation (EternalBlue)
2. **Legacy** - Samba service exploitation
3. **Lame** - Similar Samba RCE technique
4. **Devel** - Web service exploitation basics
5. **Optimum** - Service version exploitation

**Estimated Time:** 1-2 weeks

### For OSCP Preparation

Focus on these OSCP-like machines:

- Windows Easy: Blue, Legacy, Lame, Devel
- Windows Medium: Active, Jerry, Remote
- Linux Easy: Lame, Shocker
- Linux Medium: Cronos, Networked, Writeup

**Estimated Time:** 4-6 weeks

### For Active Directory Mastery

Complete this AD learning path:

1. **Active** - GPP / Kerberoasting basics
2. **Forest** - Complete AD methodology
3. **Cascade** - Advanced AD techniques
4. **Sauna** - ASREP Roasting focus
5. **Monteverde** - Azure AD integration

**Estimated Time:** 3-4 weeks

---

## Techniques Library

### Privilege Escalation

| Technique | Windows | Linux | Machines |
|-----------|:-------:|:-----:|----------|
| **Kernel Exploits** | ✅ | ✅ | Blue, Legacy, Lame, Popcorn |
| **Token Impersonation** | ✅ | ❌ | Multiple Windows |
| **Service Exploitation** | ✅ | ✅ | Multiple |
| **Sudo Abuse** | ❌ | ✅ | Linux Medium+ |
| **SUID Exploitation** | ❌ | ✅ | Linux Medium+ |
| **Capability Abuse** | ❌ | ✅ | Linux Hard |
| **GPP Exploitation** | ✅ | ❌ | Active |
| **DCSync** | ✅ | ❌ | Forest, Cascade |

### Lateral Movement

| Technique | Description | Machines |
|-----------|-------------|----------|
| **Pass-the-Hash** | SMB authentication without password | Active |
| **Kerberoasting** | Golden ticket exploitation | Active, Forest |
| **ASREP Roasting** | Roasting AS-REP responses | Sauna |
| **Trust Relationships** | Domain trust exploitation | Cascade |
| **Delegation** | Constrained delegation abuse | Sauna |

### Web Exploitation

| Technique | Description | Machines |
|-----------|-------------|----------|
| **SQL Injection** | Database query manipulation | Multiple Web |
| **RFI/LFI** | Remote/Local file inclusion | Tenten, Multiple |
| **File Upload Bypass** | Upload filter evasion | Popcorn, Networked |
| **RCE** | Remote code execution | Multiple Web |
| **Authentication Bypass** | Session/Auth evasion | Multiple Web |

---

## Learning Paths

### Path 1: Complete Beginner (Weeks 1-4)

**Goal:** Understand basic exploitation and privilege escalation

```
Week 1: Blue, Legacy, Lame (Samba RCE)
Week 2: Devel, Popcorn (FTP/Web)
Week 3: Optimum, Shocker (Service Exploitation)
Week 4: Review and consolidate
```

### Path 2: OSCP Preparation (Weeks 1-8)

**Goal:** Prepare for OSCP exam

```
Phase 1 (Weeks 1-2): Easy machines (5 total)
Phase 2 (Weeks 3-5): Medium machines (8 total)
Phase 3 (Weeks 6-8): Hard machines (3 total)
```

### Path 3: Active Directory Master (Weeks 1-6)

**Goal:** Master AD exploitation techniques

```
Week 1: Active (GPP basics)
Week 2: Forest (AD enumeration)
Week 3: Cascade (Advanced AD)
Week 4: Sauna (ASREP roasting)
Week 5: Monteverde (Azure AD)
Week 6: Resolute (Password spraying)
```

---

## Tools & Resources

### Essential Tools

| Tool | Purpose | Machines Used |
|------|---------|---------------|
| **nmap** | Port scanning & enumeration | All |
| **Metasploit** | Exploit framework | Blue, Legacy, Lame |
| **Burp Suite** | Web vulnerability testing | All Web |
| **Impacket** | SMB/AD tools | Active, Forest, Cascade |
| **BloodHound** | AD visualization | Active, Forest, Cascade |
| **PowerShell** | Windows scripting | Windows Machines |
| **Bash** | Linux scripting | Linux Machines |
| **John/Hashcat** | Password cracking | Multiple |

### Recommended Resources

- [IppSec Videos](https://www.youtube.com/@ippsec/) - Video walkthroughs
- [GTFOBins](https://gtfobins.github.io/) - Linux privilege escalation
- [HackTricks](https://book.hacktricks.xyz/) - Comprehensive techniques guide
- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Payload collections
- [Exploit-DB](https://www.exploit-db.com/) - Exploit research

---

## How to Use These Writeups

### Each writeup includes:

✅ **Enumeration Phase**
- Port scanning results
- Service identification
- Vulnerability discovery

✅ **Exploitation Phase**
- Vulnerability explanation
- Step-by-step exploitation
- Screenshots of each step

✅ **Privilege Escalation Phase**
- Escalation technique
- Detailed steps
- Commands used

✅ **Post-Exploitation**
- Flag capture
- System information
- Lessons learned

### Navigation Tips

1. **By Difficulty:** Choose your skill level
2. **By Operating System:** Windows or Linux focus
3. **By Technique:** Find machines practicing specific skills
4. **By Active Directory:** Dedicated AD machines

---

## Machine Breakdown

### By Operating System

```
Windows: 25+ machines
├── Easy: 8 machines
├── Medium: 10 machines
└── Hard: 7+ machines

Linux: 25+ machines
├── Easy: 7 machines
├── Medium: 8 machines
└── Hard: 3+ machines
```

### By Technique Type

```
Service Exploitation: 20 machines
Web Exploitation: 15 machines
Active Directory: 8 machines
Privilege Escalation: 35+ machines
Lateral Movement: 10+ machines
Password Cracking: 8+ machines
```

### By Difficulty Distribution

```
🟢 Easy (15 machines)
   Perfect for: Learning fundamentals
   Time per machine: 1-3 hours
   
🟡 Medium (20 machines)
   Perfect for: Building core skills
   Time per machine: 2-5 hours
   
🔴 Hard (15 machines)
   Perfect for: Advanced techniques
   Time per machine: 4-8+ hours
```

---

## 🔗 External Links

### Official HackTheBox

- [HackTheBox Main](https://www.hackthebox.com/) - Official platform
- [HackTheBox Machines](https://app.hackthebox.com/machines) - All machines list
- [HackTheBox Challenges](https://app.hackthebox.com/challenges) - Challenges section
- [HackTheBox Forum](https://forum.hackthebox.com/) - Community discussions

### Community Resources

- [TJnull's OSCP List] - OSCP prep guide
- [AvadaKedavra's AD Machines](https://www.ired.team/) - AD learning resources
- [0xdf hacks stuff](https://0xdf.gitlab.io/) - Excellent writeups
- [IppSec Channel](https://www.youtube.com/@ippsec/) - Video walkthroughs

---

## ⚠️ Disclaimer

These writeups are for educational purposes only. Users are responsible for:

- Following all applicable laws and regulations
- Getting proper authorization before testing systems
- Using knowledge ethically and responsibly
- Respecting the terms of service of HackTheBox

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## ✨ Special Thanks

- **HackTheBox** for the amazing platform
- **The HTB Community** for collaboration and support
- **IppSec** for excellent video explanations
- **All contributors** who help improve these writeups

---


## 🚀 Quick Stats

- **Last Updated:** January 8, 2026
- **Total Machines:** 50+
- **Total Writeups:** 40+
- **Completion Rate:** 0%
- **Average Time Per Machine:** 3 hours

---

**Happy Hacking and Learning! 🎯**

---

Last Updated: January 11, 2026
