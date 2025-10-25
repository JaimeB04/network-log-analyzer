import re
import sys
from collections import defaultdict

def analyze_log(file_path):
    #Regex patterns for the events
    failed_login_pattern = re.compile(r"Failed login attempt for user '(\w+)' from ([\d.]+)")
    port_scan_pattern = re.compile(r"Port scan detected from ([\d.]+)")

    failed_logins = defaultdict(int)
    port_scans = set()

    with open(file_path, "r") as f:
        for line in f:
            if match := failed_login_pattern.search(line):
                user, ip = match.groups()
                failed_logins[ip] +=1 
            elif match := port_scan_pattern.search(line):
                ip = match.group(1)
                port_scans.add(ip)
    
    print("\n===== SECURITY LOG ANALYSIS =====\n")
    print("Reated Failed Login Attempts:")
    for ip, count in failed_logins.items():
        if count >= 3:
            print(f" - {ip} ({count} failed attempts)\n")

    print("Ports Scans Detected:")
    for ip in port_scans:
        print(f" - {ip}\n")
    
    if not port_scans and not failed_logins:
        print("No suspicious activity found.\n")
    
if __name__ == "__main__":
    path = sys.argv[1]
    analyze_log(path)
