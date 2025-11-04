# Vidur.py (Combined Automated and Manual Analyzer)

import subprocess
import os
import sys
import pandas as pd
from datetime import datetime
import requests
import time
import configparser
import shutil
import urllib.request
import math
from collections import Counter, defaultdict

def initialize_config():
    """
    Checks for config.ini. If it doesn't exist, it runs a one-time setup
    to find paths and ask for API keys. Then, it loads and returns the config.
    """
    config = configparser.ConfigParser()
    config_file = 'config.ini'

    if not os.path.exists(config_file):
        print("[*] First-time setup: Creating config.ini file...")
        
        zeek_path = shutil.which('zeek')
        if not zeek_path:
            print("[!] Error: 'zeek' command not found. Please install Zeek and ensure it's in your system's PATH.")
            sys.exit(1)
        print(f"[+] Found Zeek at: {zeek_path}")

        api_key = input("[?] Please enter your VirusTotal API key (or press Enter to skip): ").strip()

        config['paths'] = {'zeek_path': zeek_path}
        config['virustotal'] = {'api_key': api_key}
        
        with open(config_file, 'w') as f:
            config.write(f)
        print(f"[+] Configuration saved to {config_file}.")

    config.read(config_file)
    api_key = config.get('virustotal', 'api_key', fallback=None)
    zeek_path = config.get('paths', 'zeek_path', fallback='zeek')
    return api_key, zeek_path

def capture_traffic(interface='eth0', duration=120):
    """
    Captures network traffic using tshark.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    pcap_file = f"/tmp/capture_{timestamp}.pcap"
    
    print(f"[*] Starting network capture on '{interface}' for {duration} seconds...")
    print(f"[*] Output file will be: {pcap_file}")
    
    command = ["sudo", "tshark", "-i", interface, "-a", f"duration:{duration}", "-w", pcap_file]
    
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"[+] Capture complete. Data saved to {pcap_file}")
        
        # After capture, set correct permissions so Zeek can read it
        print(f"[*] Setting permissions for {pcap_file}...")
        subprocess.run(['sudo', 'chmod', '644', pcap_file], check=True)
        
        return pcap_file
    except subprocess.CalledProcessError as e:
        print(f"[!] Error: Capture failed. Tshark output: {e.stderr.strip()}")
        return None
    except FileNotFoundError:
        print("[!] Error: 'sudo' or 'tshark' command not found.")
        return None

def run_zeek(pcap_file, zeek_exe_path, log_dir="logs"):
    """
    Runs Zeek against a pcap file, loading local scripts (like JA3).
    """
    if not os.path.exists(pcap_file): 
        print(f"[!] Error: PCAP file not found at '{pcap_file}'")
        return False
    print(f"[*] Analyzing '{pcap_file}' with Zeek... Please wait.")
    os.makedirs(log_dir, exist_ok=True)
    pcap_abs_path = os.path.abspath(pcap_file)
    original_cwd = os.getcwd()
    try:
        os.chdir(log_dir)
        for log_file in [f for f in os.listdir('.') if f.endswith('.log')]:
            os.remove(log_file)
        
        command = [zeek_exe_path, 'local', '-r', pcap_abs_path]
        subprocess.run(command, check=True, capture_output=True, text=True)

        print(f"[+] Zeek analysis complete. Logs are in the '{log_dir}' folder.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running Zeek. Exit status: {e.returncode}")
        print(f"[!] Zeek stderr: {e.stderr.strip()}")
        return False
    except Exception as e:
        print(f"[!] An unexpected error occurred while running Zeek: {e}")
        return False
    finally:
        os.chdir(original_cwd)


def get_zeek_log_header(log_file):
    """
    Reads a Zeek log file to find the header row and the number of lines to skip.
    """
    with open(log_file, 'r') as f:
        for i, line in enumerate(f):
            if line.startswith('#fields'):
                return line.strip().split('\t')[1:], i + 2
    return None, 0

def create_ip_to_domain_map(dns_log_path):
    """
    Creates a dictionary mapping IP addresses to domain names from the dns.log.
    """
    ip_to_domain = {}
    if not os.path.exists(dns_log_path): return ip_to_domain
    try:
        col_names, rows_to_skip = get_zeek_log_header(dns_log_path)
        if not col_names: return ip_to_domain
        df = pd.read_csv(dns_log_path, sep='\t', header=None, names=col_names, skiprows=rows_to_skip, comment='#', na_values='-')
        dns_answers = df.dropna(subset=['query', 'answers'])
        for _, row in dns_answers.iterrows():
            domain = row['query']
            answers = str(row['answers']).split(',')
            for ip in answers: ip_to_domain[ip] = domain
    except Exception: pass
    return ip_to_domain

def check_ip_on_vt(ip_address, api_key):
    """
    Checks an IP address on VirusTotal and returns the malicious score.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return stats.get('malicious', 0)
        return -1 # Indicate an error
    except Exception:
        return -1

def check_file_hash_on_vt(hash_val, api_key):
    """
    Checks a file hash on VirusTotal and returns details if malicious.
    """
    url = f"https.virustotal.com/api/v3/files/{hash_val}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious_count = stats.get('malicious', 0)
            if malicious_count > 5:
                names = response.json()['data']['attributes'].get('names', ["Unknown Name"])
                return {"is_malicious": True, "score": malicious_count, "name": names[0]}
        return {"is_malicious": False}
    except Exception:
        return {"is_malicious": False, "error": "API Error"}

def calculate_shannon_entropy(data):
    """
    Calculates the Shannon entropy of a string to check for randomness.
    """
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0: entropy += -p_x * math.log(p_x, 2)
    return entropy

def find_beaconing(conn_log_path, ip_domain_map):
    """
    Finds potential beaconing by analyzing connection counts and timing intervals.
    """
    if not os.path.exists(conn_log_path): return []
    findings = []
    print("\n[*] Analyzing connection patterns for beaconing...")
    try:
        col_names, rows_to_skip = get_zeek_log_header(conn_log_path)
        if not col_names: return []
        df = pd.read_csv(conn_log_path, sep='\t', header=None, names=col_names, skiprows=rows_to_skip, comment='#', na_values='-')
        grouped = df.groupby(['id.orig_h', 'id.resp_h'])
        for name, group in grouped:
            count = len(group)
            if count > 10: # Threshold for number of connections
                timestamps = group['ts'].sort_values()
                intervals = timestamps.diff().dropna()
                if len(intervals) > 1:
                    std_dev = intervals.std()
                    if std_dev < 5.0: # Low standard deviation indicates robotic timing
                        source, dest = name
                        domain = ip_domain_map.get(dest, "")
                        findings.append({"source": source, "destination": dest, "domain": domain, "count": count, "interval_std_dev": f"{std_dev:.2f}s", "vt_score": -1})
    except Exception: pass
    return sorted(findings, key=lambda x: x['count'], reverse=True)

def find_suspicious_dns(dns_log_path):
    """
    Finds suspicious DNS queries by looking for high entropy (randomness).
    """
    if not os.path.exists(dns_log_path): return [], []
    unsafe_domains, safe_domains = [], []
    print("\n[*] Analyzing DNS queries for high entropy (DGA)...")
    
    known_good_suffixes = [
        'microsoft.com', 'windowsupdate.com', 'skype.com', 'google.com',
        'googleapis.com', 'googleadservices.com', 'doubleclick.net',
        'azureedge.net', 'footprintdns.com', 'msedge.net', 'microsoftapp.net',
        'epicgames.com', 'steamstatic.com', 'unrealengine.com'
    ]

    try:
        col_names, rows_to_skip = get_zeek_log_header(dns_log_path)
        if not col_names: return unsafe_domains, safe_domains
        df = pd.read_csv(dns_log_path, sep='\t', header=None, names=col_names, skiprows=rows_to_skip, comment='#', na_values='-')
        for _, row in df.iterrows():
            query = row.get('query')
            if query:
                entropy = calculate_shannon_entropy(query)
                if entropy > 3.5: # Entropy threshold for randomness
                    finding = {"source": row.get('id.orig_h'), "domain": f"{query} (Entropy: {entropy:.2f})"}
                    is_known_good = any(query.endswith(suffix) for suffix in known_good_suffixes)
                    if is_known_good or 'mozilla' in query or 'firefox' in query:
                        safe_domains.append(finding)
                    else:
                        unsafe_domains.append(finding)
    except Exception: pass
    return unsafe_domains, safe_domains

def find_malicious_files(files_log_path, api_key):
    """
    Finds malicious files by checking their MD5 hashes against VirusTotal.
    """
    if not os.path.exists(files_log_path): return []
    print("\n[*] Analyzing transferred files from files.log...")
    findings = []
    try:
        col_names, rows_to_skip = get_zeek_log_header(files_log_path)
        if not col_names: return []
        df = pd.read_csv(files_log_path, sep='\t', header=None, names=col_names, skiprows=rows_to_skip, comment='#', na_values='-')
        unique_hashes = df.dropna(subset=['md5']).drop_duplicates(subset=['md5'])
        if not unique_hashes.empty:
            print(f"[*] Checking {len(unique_hashes)} unique file hashes on VirusTotal...")
            for _, row in unique_hashes.iterrows():
                hash_val = row['md5']
                result = check_file_hash_on_vt(hash_val, api_key)
                if result.get("is_malicious"):
                    findings.append({"source": row.get('id.orig_h'), "details": f"File: {result['name']} | MD5: {hash_val} | VT Score: {result['score']} malicious detections."})
                time.sleep(15)
    except Exception: pass
    return findings

def find_malicious_ja3(ssl_log_path):
    """
    Finds malicious JA3 TLS fingerprints by checking against a downloaded blocklist.
    """
    print("\n[*] Analyzing TLS connections for malicious fingerprints...")
    blocklist_url = "https://sslbl.abuse.ch/ja3-fingerprints.csv"
    blocklist_file = "ja3_blocklist.csv"
    findings = []
    try:
        if not os.path.exists(blocklist_file) or (time.time() - os.path.getmtime(blocklist_file)) > 86400:
            print(f"[*] Downloading JA3 fingerprint blocklist from abuse.ch...")
            headers = {'User-Agent': 'Mozilla/5.0'}
            req = urllib.request.Request(blocklist_url, headers=headers)
            with urllib.request.urlopen(req) as response, open(blocklist_file, 'wb') as out_file:
                out_file.write(response.read())
        malicious_ja3s = set()
        with open(blocklist_file, 'r') as f:
            for line in f:
                if not line.startswith('#'):
                    malicious_ja3s.add(line.split(',')[0])
        if not os.path.exists(ssl_log_path): return []
        col_names, rows_to_skip = get_zeek_log_header(ssl_log_path)
        if not col_names: return []
        df = pd.read_csv(ssl_log_path, sep='\t', header=None, names=col_names, skiprows=rows_to_skip, comment='#', na_values='-')
        if 'ja3' not in df.columns:
            print("[!] Warning: 'ja3' column not found in ssl.log. Skipping JA3 analysis.")
            return []
        malicious_connections = df[df['ja3'].isin(malicious_ja3s)]
        for _, row in malicious_connections.iterrows():
            findings.append({"source": row.get('id.orig_h'), "details": f"Malicious Fingerprint (JA3): {row['ja3']} to Destination: {row['id.resp_h']}"})
    except Exception as e:
        print(f"[!] Could not perform JA3 analysis: {e}")
    return findings

def main():
    """
    Main function to run the analyzer.
    It checks if a pcap file is provided as an argument.
    If not, it runs in automated capture mode.
    If a file is provided, it runs in manual analysis mode.
    """
    log_directory = "logs"
    api_key, zeek_path = initialize_config()
    if not zeek_path: sys.exit(1)
    if not api_key: print("[!] No API key configured. Skipping all VirusTotal checks.")

    # --- NEW LOGIC: Check for command-line arguments ---
    if len(sys.argv) == 2:
        # MANUAL MODE
        pcap_file = sys.argv[1]
        print(f"[*] Manual mode: Analyzing provided file '{pcap_file}'...")
        if not os.path.exists(pcap_file):
            print(f"[!] Error: File not found at '{pcap_file}'")
            sys.exit(1)
        
    elif len(sys.argv) == 1:
        # AUTOMATED MODE
        print("[*] Automated mode: Capturing live traffic...")
        pcap_file = capture_traffic(interface='eth0', duration=120)
        if not pcap_file:
            print("[!] Halting script due to capture failure.")
            sys.exit(1)
        # Note: capture_traffic() already sets permissions
        
    else:
        # ERROR: Wrong usage
        print("Usage: python3 Vidur.py [optional: <path_to_pcap_file>]")
        print("  - Run without arguments for live traffic capture.")
        print("  - Provide a path to a .pcap file for manual analysis.")
        sys.exit(1)

    # --- Analysis pipeline continues from here, using the 'pcap_file' variable ---
    
    if not run_zeek(pcap_file, zeek_path, log_directory): sys.exit(1)

    print("\n[*] Correlating DNS lookups with connections...")
    ip_to_domain_map = create_ip_to_domain_map(os.path.join(log_directory, 'dns.log'))
    
    beacon_findings = find_beaconing(os.path.join(log_directory, 'conn.log'), ip_to_domain_map)
    unsafe_dns, safe_dns = find_suspicious_dns(os.path.join(log_directory, 'dns.log'))
    ja3_findings = find_malicious_ja3(os.path.join(log_directory, 'ssl.log'))
    file_findings = []
    
    if api_key:
        file_findings = find_malicious_files(os.path.join(log_directory, 'files.log'), api_key)
        if beacon_findings:
            print("\n[*] Checking suspicious destination IPs on VirusTotal...")
            unique_ips = {f['destination'] for f in beacon_findings if f.get("destination")}
            for ip in unique_ips:
                score = check_ip_on_vt(ip, api_key)
                for finding in beacon_findings:
                    if finding.get("destination") == ip: finding['vt_score'] = score
                time.sleep(15)

    benign_beacons = []
    unsafe_beacons = []
    if api_key:
        for f in beacon_findings:
            if f['vt_score'] == 0:
                benign_beacons.append(f)
            else:
                unsafe_beacons.append(f)
    else:
        unsafe_beacons = beacon_findings

    correlated_incidents = defaultdict(lambda: defaultdict(list))
    all_unsafe_findings = [
        (unsafe_beacons, 'beaconing'),
        (unsafe_dns, 'dns'),
        (ja3_findings, 'ja3'),
        (file_findings, 'files')
    ]
    for findings, f_type in all_unsafe_findings:
        for finding in findings:
            source_ip = finding.get('source')
            if source_ip:
                correlated_incidents[source_ip][f_type].append(finding)

    report_lines = []
    report_lines.append(f"# Malware Analysis Report for {os.path.basename(pcap_file)} ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")
    
    if not correlated_incidents:
        report_lines.append("\n## Unsafe (Red Flags) 🚩")
        report_lines.append("\n- No specific unsafe activity detected.")
    else:
        report_lines.append("\n## Incident Reports by Host 🚩")
        for host, incidents in correlated_incidents.items():
            report_lines.append(f"\n### Host Under Investigation: `{host}`")
            report_lines.append("This host is considered suspicious due to the following correlated activities:")
            if 'beaconing' in incidents:
                report_lines.append("\n- **Potential C2 Beaconing Detected**:")
                for f in incidents['beaconing']:
                    dest_str = f.get('destination') + (f" ({f.get('domain')})" if f.get('domain') else "")
                    vt_str = f"VT Score: {f.get('vt_score')} vendors flagged as malicious." if f.get('vt_score', -1) > 0 else "VT Score: Unknown or Not Malicious."
                    report_lines.append(f"  - Connected to `{dest_str}` **{f.get('count')}** times with a regular interval (**{f.get('interval_std_dev')}** std dev).")
                    report_lines.append(f"    - **{vt_str}**")
            if 'ja3' in incidents:
                report_lines.append("\n- **Malicious TLS Fingerprint(s) Detected**:")
                for f in incidents['ja3']: report_lines.append(f"  - {f.get('details')}")
            if 'files' in incidents:
                report_lines.append("\n- **Malicious File Transfer(s) Detected**:")
                for f in incidents['files']: report_lines.append(f"  - {f.get('details')}")
            if 'dns' in incidents:
                report_lines.append("\n- **Suspicious DNS Queries (High Entropy)**:")
                for f in incidents['dns']: report_lines.append(f"  - {f.get('domain')}")

    report_lines.append("\n" + ("-"*50))
    report_lines.append("\n## Safe / Suppressed Findings ✅")
    if not safe_dns and not benign_beacons:
        report_lines.append("\n- No known legitimate or benign activity was flagged.")
    else:
        if benign_beacons:
            report_lines.append("\n### Benign Beaconing Activity (Suppressed)")
            report_lines.append("The following connections looked like beaconing but were suppressed because the destination IP has a VirusTotal score of 0:")
            for f in benign_beacons:
                dest_str = f.get('destination') + (f" ({f.get('domain')})" if f.get('domain') else "")
                report_lines.append(f"- **Host**: {f.get('source')} -> **Destination**: {dest_str} | **Connections**: {f.get('count')}")
        if safe_dns:
            report_lines.append("\n### Known Legitimate Domains (High Entropy)")
            for finding in safe_dns:
                report_lines.append(f"- {finding['domain']} (from host: {finding['source']})")
    
    report_content = "\n".join(report_lines)
    print("\n" + ("="*20) + " ANALYSIS REPORT " + ("="*20))
    print(report_content)
    print("="*57)
    
    report_filename = f"report_{os.path.basename(pcap_file)}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.md"
    with open(report_filename, 'w') as f:
        f.write(report_content)
    print(f"\n[+] Report also saved to file: {report_filename}")

if __name__ == "__main__":
    main()
