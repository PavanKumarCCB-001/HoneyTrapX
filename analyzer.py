# Analyzer for HoneyTrapX
# Classifies attack patterns, assigns MITRE ATT&CK tags, and calculates Threat Scores.

import re
import pandas as pd
import os

LOG_FILE = "logs/attacks.csv"

# MITRE ATT&CK Mapping
MITRE_MAP = {
    "brute_force": {"id": "T1110.001", "name": "Brute Force: Password Guessing"},
    "dir_traversal": {"id": "T1083", "name": "File and Directory Discovery"},
    "recon_scan": {"id": "T1046", "name": "Network Service Scanning"},
    "wget_curl": {"id": "T1105", "name": "Ingress Tool Transfer"},
    "sensitive_read": {"id": "T1552.001", "name": "Unsecured Credentials"},
    "sqli_probe": {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "cron_read": {"id": "T1053.003", "name": "Scheduled Task/Job: Cron"},
}

def analyze_payload(payload):
    """Analyzes a payload string for patterns and returns tags and score increments."""
    tags = []
    score_inc = 0

    # 1. Web Exploits
    if re.search(r"(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|--|#)", payload, re.I):
        tags.append("sqli_probe")
        score_inc += 20

    if re.search(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini)", payload, re.I):
        tags.append("dir_traversal")
        score_inc += 25

    # 2. Tool Usage
    if re.search(r"(wget|curl|git|tftp|ftp)", payload, re.I):
        tags.append("wget_curl")
        score_inc += 25

    # 3. Credential Hunting
    if re.search(r"(\.env|config\.php|passwords\.txt|shadow|authorized_keys)", payload, re.I):
        tags.append("sensitive_read")
        score_inc += 40

    return tags, score_inc

def get_mitre_info(tags):
    return [MITRE_MAP[tag] for tag in tags if tag in MITRE_MAP]

def calculate_score(ip_history):
    """Calculates threat score based on history of an IP."""
    # This is a simplified version; in a real app, you'd query the DB/logs.
    score = 0
    ports_hit = len(ip_history["target_port"].unique())
    score += ports_hit * 10

    # Bruteforce detection
    ssh_hits = len(ip_history[ip_history["target_port"] == 2222])
    if ssh_hits > 5:
        score += 15

    # Custom tags from payloads
    for payload in ip_history["payload"]:
        _, inc = analyze_payload(str(payload))
        score += inc

    return min(100, score)

def load_data():
    if not os.path.exists(LOG_FILE):
        return pd.DataFrame()
    return pd.read_csv(LOG_FILE)
