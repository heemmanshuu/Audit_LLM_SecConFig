"""
Detailed security analysis tool for Kubernetes YAML configurations.
This script performs comprehensive security scanning using both Checkov and Terrascan,
generating detailed reports including failure counts, check IDs, and violation severities.

The analysis includes:
- Checkov security checks with failure counts
- Terrascan policy violations with severity levels
- Detailed violation reporting
"""

import json
import subprocess

import pandas as pd
from joblib import Parallel, delayed
from tqdm.rich import tqdm

def check_checkov(path):
    """
    Performs detailed Checkov security analysis on a YAML file.

    Args:
        path (str): Path to the YAML file to analyze

    Returns:
        dict: Complete Checkov scan results including failed checks and counts
    """
    scan_output = subprocess.run(["checkov", "-f", path, "--framework", "kubernetes", "-o", "json", "--compact", "--quiet"], capture_output=True)
    data = json.loads(scan_output.stdout.decode("utf-8"))
    return data

def check_terrascan(path):
    """
    Performs detailed Terrascan security analysis on a YAML file.

    Args:
        path (str): Path to the YAML file to analyze

    Returns:
        dict: Complete Terrascan scan results including violations and severity levels
    """
    scan_output = subprocess.run(["terrascan", "scan", "-i", "k8s", "-f", path, "-o", "json"], capture_output=True)
    data = json.loads(scan_output.stdout.decode("utf-8"))
    return data

def scan(file_path):
    """
    Performs comprehensive security analysis using both tools.

    Args:
        file_path (str): Path to the YAML file to analyze

    Returns:
        dict: Combined analysis results including:
            - Checkov failure counts and check IDs
            - Terrascan violation details and severity levels
            - Summary statistics
    """
    # Run Checkov analysis
    checkov_result = check_checkov(file_path)
    terrascan_result = check_terrascan(file_path)
    
    # Process Checkov results
    if checkov_result.get("summary", None):
        ck_failed_count = checkov_result["summary"]["failed"]
        ck_res = [item["check_id"] for item in checkov_result["results"]["failed_checks"]]
    else:
        ck_res = None
        ck_failed_count = 0
    
    # Process Terrascan results
    if terrascan_result.get("results", None):
        ts_res = [{"ts_id": item["rule_id"], "ts_severity": item["severity"]} for item in terrascan_result["results"]["violations"]]
        ts_failed_count = terrascan_result["results"]["scan_summary"]["violated_policies"]
        ts_low = terrascan_result["results"]["scan_summary"]["low"]
        ts_medium = terrascan_result["results"]["scan_summary"]["medium"]
        ts_high = terrascan_result["results"]["scan_summary"]["high"]
    else:
        ts_res = None
        ts_failed_count = ts_low = ts_medium = ts_high = 0

    return {
        "file": file_path,
        "checkov_result": {
            "ck_failed_count": ck_failed_count,
            "ck_res": ck_res,
        },
        "terrascan_result": {"ts_failed_count": ts_failed_count, "ts_res": ts_res, "ts_low": ts_low, "ts_medium": ts_medium, "ts_high": ts_high},
    }

if __name__ == "__main__":
    # Load list of files to scan
    file_lst = pd.read_csv("fetch_artifacthub/gathered/cleaned_files.csv")
    file_lst = file_lst["files"].tolist()

    # Perform parallel scanning with progress bar
    results = Parallel(n_jobs=-1)(delayed(scan)(f) for f in tqdm(file_lst))
    
    # Save detailed scan results
    with open("fetch_artifacthub/gathered/results.json", "w") as f:
        json.dump(result, f, indent=2)
