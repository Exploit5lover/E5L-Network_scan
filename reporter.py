import os
import datetime
import logging
from config import REPORT_FILE_NAME_TXT, REPORT_FILE_NAME_HTML

def generate_final_report(all_results, output_dir):
    """Generates a comprehensive text and HTML report of the scan findings."""
    report_path_txt = os.path.join(output_dir, REPORT_FILE_NAME_TXT)
    report_path_html = os.path.join(output_dir, REPORT_FILE_NAME_HTML)

    logging.info(f"[*] Generating final report: {report_path_txt} and {report_path_html}")

    # --- Text Report ---
    with open(report_path_txt, 'w') as f:
        f.write("--- VScan Network Vulnerability Report ---\n")
        f.write(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Output Directory: {output_dir}\n")
        f.write("\n" + "="*80 + "\n")
        f.write("Summary of Findings:\n")
        f.write("="*80 + "\n\n")

        if not all_results:
            f.write("No scan results available.\n")
        else:
            for result in all_results:
                f.write(f"--- Target: {result['target']} ---\n")
                f.write(f"  Output Directory: {result['output_dir']}\n")
                
                if result['open_ports']:
                    f.write("  Open Ports:\n")
                    for port, service in result['open_ports'].items():
                        f.write(f"    - {port}/tcp ({service})\n")
                    f.write("\n")

                if result['vulnerabilities']:
                    f.write("  Vulnerabilities Found:\n")
                    for vuln in result['vulnerabilities']:
                        f.write(f"    - Type: {vuln.get('type', 'N/A')}\n")
                        f.write(f"      Name: {vuln.get('name', 'N/A')}\n")
                        f.write(f"      Severity: {vuln.get('severity', 'N/A')}\n")
                        f.write(f"      Details: {vuln.get('details', 'N/A')}\n")
                        if 'source_file' in vuln:
                             f.write(f"      Source File: {os.path.basename(vuln['source_file'])}\n")
                        f.write("\n")
                else:
                    f.write("  No significant vulnerabilities identified by automated tools.\n\n")

                if result['credentials']:
                    f.write("  Credentials Found:\n")
                    for cred in result['credentials']:
                        f.write(f"    - Service: {cred.get('service', 'N/A')}\n")
                        f.write(f"      Details: {cred.get('details', 'N/A')}\n")
                    f.write("\n")
                
                f.write("-" * 50 + "\n\n")

    # --- HTML Report ---
    with open(report_path_html, 'w') as f:
        f.write("<!DOCTYPE html>\n")
        f.write("<html lang='en'>\n")
        f.write("<head>\n")
        f.write("    <meta charset='UTF-8'>\n")
        f.write("    <meta name='viewport' content='width=device-width, initial-scale=1.0'>\n")
        f.write("    <title>VScan Network Vulnerability Report</title>\n")
        f.write("    <style>\n")
        f.write("        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }\n")
        f.write("        .container { background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }\n")
        f.write("        h1, h2, h3 { color: #0056b3; }\n")
        f.write("        .severity-critical { color: #d9534f; font-weight: bold; }\n")
        f.write("        .severity-high { color: #f0ad4e; font-weight: bold; }\n")
        f.write("        .severity-medium { color: #5cb85c; font-weight: bold; }\n")
        f.write("        .severity-low { color: #5bc0de; }\n")
        f.write("        .severity-pwned { color: #8a2be2; font-weight: bold; }\n")
        f.write("        .details { margin-left: 20px; border-left: 2px solid #eee; padding-left: 10px; }\n")
        f.write("        pre { background-color: #eee; padding: 10px; border-radius: 4px; overflow-x: auto; }\n")
        f.write("    </style>\n")
        f.write("</head>\n")
        f.write("<body>\n")
        f.write("    <div class='container'>\n")
        f.write("        <h1>VScan Network Vulnerability Report</h1>\n")
        f.write(f"        <p><strong>Scan Date:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>\n")
        f.write(f"        <p><strong>Output Directory:</strong> {os.path.abspath(output_dir)}</p>\n")
        f.write("        <h2>Summary of Findings</h2>\n")

        if not all_results:
            f.write("        <p>No scan results available.</p>\n")
        else:
            for result in all_results:
                f.write(f"        <h3>Target: {result['target']}</h3>\n")
                f.write(f"        <p><strong>Output Directory:</strong> {os.path.abspath(result['output_dir'])}</p>\n")
                
                if result['open_ports']:
                    f.write("        <h4>Open Ports:</h4>\n")
                    f.write("        <ul>\n")
                    for port, service in result['open_ports'].items():
                        f.write(f"            <li>{port}/tcp ({service})</li>\n")
                    f.write("        </ul>\n")

                if result['vulnerabilities']:
                    f.write("        <h4>Vulnerabilities Found:</h4>\n")
                    f.write("        <ul>\n")
                    for vuln in result['vulnerabilities']:
                        severity_class = f"severity-{vuln.get('severity', 'N/A').lower()}"
                        f.write(f"            <li>\n")
                        f.write(f"                <strong>Type:</strong> {vuln.get('type', 'N/A')}<br>\n")
                        f.write(f"                <strong>Name:</strong> {vuln.get('name', 'N/A')}<br>\n")
                        f.write(f"                <strong>Severity:</strong> <span class='{severity_class}'>{vuln.get('severity', 'N/A')}</span><br>\n")
                        f.write(f"                <strong>Details:</strong> <pre>{vuln.get('details', 'N/A')}</pre><br>\n")
                        if 'source_file' in vuln:
                             f.write(f"                <strong>Source File:</strong> <a href='file://{os.path.abspath(vuln['source_file'])}'>{os.path.basename(vuln['source_file'])}</a><br>\n")
                        f.write("            </li>\n")
                    f.write("        </ul>\n")
                else:
                    f.write("        <p>No significant vulnerabilities identified by automated tools.</p>\n")

                if result['credentials']:
                    f.write("        <h4>Credentials Found:</h4>\n")
                    f.write("        <ul>\n")
                    for cred in result['credentials']:
                        f.write(f"            <li>\n")
                        f.write(f"                <strong>Service:</strong> {cred.get('service', 'N/A')}<br>\n")
                        f.write(f"                <strong>Details:</strong> <pre>{cred.get('details', 'N/A')}</pre><br>\n")
                        f.write("            </li>\n")
                    f.write("        </ul>\n")
                
                f.write("        <hr>\n")
        f.write("    </div>\n")
        f.write("</body>\n")
        f.write("</html>\n")

    logging.info(f"[+] Final report generated at: {report_path_txt} and {report_path_html}")
