import subprocess
import os
import logging
import ipaddress

# --- Logging Setup ---
# This will be configured more fully in main.py, but basic setup here for functions called directly.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_logging(log_file_path):
    """Sets up detailed logging to both console and a file."""
    # Remove existing handlers if any, to avoid duplicate logs
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file_path),
            logging.StreamHandler()
        ]
    )

def run_command(command, log_path, description="Command"):
    """
    Executes a shell command and logs its output.
    Returns True if successful (return code 0), False otherwise.
    """
    logging.info(f"[*] Running {description}: {' '.join(command)}")
    try:
        # Use Popen to capture stdout/stderr in real-time if needed, but for simplicity,
        # we'll let it run and capture after.
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        
        with open(log_path, 'w') as f:
            for line in process.stdout:
                f.write(line)
                # logging.debug(f"[{description}] {line.strip()}") # Uncomment for verbose debug output to console
        process.wait()

        if process.returncode == 0:
            logging.info(f"[+] {description} completed successfully. Output in {log_path}")
            return True
        else:
            logging.error(f"[-] {description} failed with return code {process.returncode}. Check {log_path}")
            return False
    except FileNotFoundError:
        logging.error(f"[-] Error: Tool not found. Please ensure it's installed and in your PATH: {command[0]}")
        return False
    except Exception as e:
        logging.error(f"[-] An unexpected error occurred during {description}: {e}")
        return False

def check_tool_installed(tool_name):
    """Checks if a command-line tool is available in the system's PATH."""
    return subprocess.call(f"type {tool_name}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

def get_live_hosts(cidr_range, output_dir):
    """Scans a CIDR range for live hosts using Nmap ping scan."""
    logging.info(f"[*] Discovering live hosts in {cidr_range} using Nmap ping scan...")
    # Sanitize CIDR for filename
    sanitized_cidr = str(cidr_range).replace('/', '_').replace('.', '_')
    live_hosts_file = os.path.join(output_dir, f"live_hosts_{sanitized_cidr}.gnmap") # Grepable Nmap output
    
    command = ["nmap", "-sn", "-n", "-T4", "-oG", live_hosts_file, str(cidr_range)]
    
    try:
        subprocess.run(command, check=True, text=True, capture_output=True)
        logging.info(f"[+] Live host discovery completed. Results in {live_hosts_file}")
        
        live_hosts = []
        with open(live_hosts_file, 'r') as f:
            for line in f:
                if "Up" in line and "Host:" in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "Host:" and i + 1 < len(parts):
                            live_hosts.append(parts[i+1])
                            break
        logging.info(f"[+] Discovered {len(live_hosts)} live hosts in {cidr_range}.")
        return live_hosts
    except subprocess.CalledProcessError as e:
        logging.error(f"[-] Nmap ping scan failed for {cidr_range}: {e.stderr}")
        return []
    except FileNotFoundError:
        logging.error("[-] Error: nmap not found. Please ensure Nmap is installed and in your PATH.")
        return []
    except Exception as e:
        logging.error(f"[-] An error occurred during live host discovery for {cidr_range}: {e}")
        return []
