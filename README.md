# Basic Network Scanner (BNS)

At first you should have Python installed. 

In Linux/MacOS go to CLI (Terminal) and write:

Bash

```
git clone https://github.com/QAhmed09/Basic_Network_Scanner.git
cd Basic_Network_Scanner
chmod +x BNS.py
```

Now you should know all the commands:

- `-h, --help`
Displays the help menu and shows how to use all available commands.
- `-t, --target`
Specifies the target IP address or Hostname you want to scan (Required).
- `-p, --ports`
Specifies the ports to scan. It supports multiple formats:
- `-common` (Scans ports 1-1024, this is the default).
- Single port (e.g., `80`).
- Comma-separated list (e.g., `22,80,443`).
- Range (e.g., `20-100`).
- `-threads`
Specifies the number of concurrent worker threads for the fast discovery phase. Higher numbers mean faster scans (Default is 50).
- `-timeout`
Specifies the connection timeout in seconds. Use lower values for local networks and higher values for remote targets (Default is 0.6).
- `-debug`
Enables verbose debug logging to see real-time background operations.

**⚠️ LEGAL WARNING:**
Using this tool against unauthorized targets without prior explicit written consent is strictly illegal and may violate local and international laws. Use responsibly for authorized security auditing and educational purposes only.

## Practical Examples

- **Running a fast scan on common ports (1-1024) against a target IP:**Bash
    
    ```
    python3 BNS.py -t 192.168.1.15
    ```
    

`* **Scanning a specific list of ports on a domain with an increased timeout for accuracy:**
  ```bash
  python3 BNS.py -t target.com -p 21,22,80,443,8080 --timeout 1.5`

- **Aggressively scanning a custom port range using 100 concurrent threads:**Bash
    
    ```
    python3 BNS.py -t 10.10.10.5 -p 1-5000 --threads 100
    ```
    

`* **Running a scan with debug mode enabled to monitor the background discovery process:**
  ```bash
  python3 BNS.py -t 192.168.1.1 -p 22,80 --debug`
