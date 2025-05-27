import os
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import configurations
from config import (
    MAX_CONCURRENT_SCANS, CURRENT_OUTPUT_DIR, ENABLE_AUTO_EXPLOIT
)

# Import utilities and scanner classes
from scanner_utils import setup_logging, check_tool_installed, get_live_hosts
from network_scanner import NetworkScanner
from reporter import generate_final_report

def main():
    # Setup global logging first
    log_file = os.path.join(CURRENT_OUTPUT_DIR, "vscan_main.log")
    setup_logging(log_file)
    logging.info(f"VScan started. All logs will be stored in {CURRENT_OUTPUT_DIR}")

    # --- Pre-requisites Check ---
    logging.info("[*] Checking for required tools...")
    required_tools = ["nmap"]
    optional_tools = {
        "hydra": "Brute-force attacks will be skipped.",
        "msfconsole": "Automated exploitation is enabled but will not function." if ENABLE_AUTO_EXPLOIT else "Metasploit integration will be skipped."
    }

    all_tools_present = True
    for tool in required_tools:
        if not check_tool_installed(tool):
            logging.critical(f"Error: '{tool}' is not installed or not in PATH. Please install it to proceed.")
            all_tools_present = False
    
    if not all_tools_present:
        logging.critical("Exiting due to missing required tools.")
        return

    for tool, warning_msg in optional_tools.items():
        if not check_tool_installed(tool):
            logging.warning(f"Warning: '{tool}' is not installed or not in PATH. {warning_msg}")

    # --- Target Input ---
    target_input = input("Enter target(s) (IP, CIDR range, comma-separated): ")
    raw_targets = [t.strip() for t in target_input.split(',') if t.strip()]

    all_hosts = []
    for target in raw_targets:
        try:
            if '/' in target: # CIDR range
                network = ipaddress.ip_network(target, strict=False)
                # For large CIDRs, ping scanning is essential to avoid scanning every single IP.
                live_ips = get_live_hosts(network, CURRENT_OUTPUT_DIR)
                all_hosts.extend(live_ips)
            else: # Single IP or hostname
                # For a single IP/hostname, we assume it's live or let Nmap determine
                all_hosts.append(target)
        except ValueError:
            logging.error(f"[-] Invalid target format: {target}. Skipping.")
    
    if not all_hosts:
        logging.error("No valid targets identified for scanning. Exiting.")
        return

    logging.info(f"[*] Starting comprehensive network scan on {len(all_hosts)} live hosts...")

    results = []
    # Use ThreadPoolExecutor for concurrent scanning of multiple targets
    # Each target gets its own dedicated output subdirectory
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_SCANS) as executor:
        future_to_target = {
            executor.submit(
                NetworkScanner(host, os.path.join(CURRENT_OUTPUT_DIR, host.replace('.', '_'))).run_all_scans
            ): host for host in all_hosts
        }

        for future in as_completed(future_to_target):
            host = future_to_target[future]
            try:
                scan_result = future.result()
                results.append(scan_result)
            except Exception as exc:
                logging.error(f"[-] {host} generated an exception during scan: {exc}")

    generate_final_report(results, CURRENT_OUTPUT_DIR)
    logging.info("[*] VScan comprehensive network scan completed!")
    logging.info(f"Detailed results and logs are in: {CURRENT_OUTPUT_DIR}")

if __name__ == "__main__":
    main()
