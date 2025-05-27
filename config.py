import os
import datetime

# --- General Scanner Settings ---
MAX_CONCURRENT_SCANS = 5  # Max concurrent targets scanned at once
OUTPUT_BASE_DIR = "scan_results" # Base directory for all scan results
SCAN_START_TIME = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
CURRENT_OUTPUT_DIR = os.path.join(OUTPUT_BASE_DIR, f"scan_{SCAN_START_TIME}")

# --- Nmap Settings ---
# -sS: SYN Scan, -sV: Service version detection, -O: OS detection
# --min-rate/--max-rate: Control packet rate for stealth or speed
# -T4: Aggressive timing template (faster)
NMAP_DEFAULT_SCAN_TYPES = "-sS -sV -O --min-rate 1000 --max-rate 5000 -T4"

# Nmap NSE scripts for common network vulnerabilities and info gathering
# This focuses on network services, not web-specific ones like http-enum.
# We'll keep vulners/vulscan as they check for CVEs on discovered services.
NMAP_NETWORK_SCRIPTS = (
    "smb-os-discovery,smb-enum-shares,smb-vuln-ms17-010,smb-vuln-cve2009-3103,smb-vuln-ms08-067,"
    "ssh-hostkey,ftp-anon,ftp-bounce,smtp-enum-users,snmp-enum-users,telnet-info,"
    "vulners,vulscan --script-args vulscan.libraries=cve,exploitdb,openvas"
)

# Nmap full port scan options (can be slow, but comprehensive)
NMAP_FULL_PORT_SCAN_OPTIONS = "-p- --min-rate 1000 --max-rate 5000 -T4"

# --- Brute-Force Settings (Hydra) ---
# Default user and password lists (adjust paths as needed for Kali)
# Remember to gunzip /usr/share/wordlists/rockyou.txt.gz if you use it.
HYDRA_USER_LISTS = [
    "/usr/share/wordlists/metasploit/http_default_users.txt",
    "/usr/share/wordlists/nmap/nmap-mac-prefixes.txt" # Example, you might need more relevant ones
]
HYDRA_WORD_LISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/metasploit/http_default_pass.txt"
]

# Common network services to attempt brute-forcing if found open by Nmap
# Removed HTTP/S specific ones as we're focusing off web apps.
HYDRA_SERVICES = [
    "ftp",
    "ssh",
    "telnet",
    "smb"
    # "pop3", "imap", "vnc", "rdp" - add more as needed if you detect them via Nmap
]

# --- Exploitation Settings (Metasploit - Conceptual) ---
# Enable/disable automated exploitation (HIGHLY DANGEROUS, USE WITH EXTREME CAUTION)
ENABLE_AUTO_EXPLOIT = False # Keep False unless you fully understand the implications

# Metasploit payload details (adjust LHOST/LPORT for your attacking machine/VPN IP)
# This is YOUR Kali Linux IP that the target will connect back to.
MSF_LHOST = "192.168.1.10" # <--- IMPORTANT: CHANGE THIS TO YOUR KALI IP
MSF_LPORT = 4444

# --- Reporting Settings ---
REPORT_FILE_NAME_TXT = "VScan_Comprehensive_Report.txt"
REPORT_FILE_NAME_HTML = "VScan_Comprehensive_Report.html"
