"""Module for processing Checkov test datasets.

This module processes Checkov's test files to create a structured dataset of test cases,
categorizing them by type and test result (passed/failed). It also matches test types
with known rule types using fuzzy matching.
"""

import json
from pathlib import Path
from pprint import pprint

import pandas as pd
from thefuzz import fuzz, process

# Directory containing Checkov's Kubernetes test files
TEST_DIR = Path("github/checkov/tests/kubernetes/checks")

# Get all YAML and JSON test files
yaml_files = list(TEST_DIR.glob("example_*/*.yaml"))
json_files = list(TEST_DIR.glob("example_*/*.json"))
files = yaml_files + json_files

# Initialize result dictionary to store test cases by type
res = {}
for file in files:
    # Extract test type from directory name (e.g., "example_Deployment" -> "Deployment")
    _type = str(file.parent).split("/")[-1].split("_")[-1]
    res[_type] = {"passed": [], "failed": [], "unknown": []}

# Categorize files based on their names into passed/failed/unknown
for file in files:
    _type = str(file.parent).split("/")[-1].split("_")[-1]
    if "failed" in file.stem.lower():
        # Files with "failed" in name are failed test cases
        res[_type]["failed"].append(str(file))
    elif "passed" in file.stem.lower() and "failed" not in file.stem.lower():
        # Files with "passed" in name (but not "failed") are passed test cases
        res[_type]["passed"].append(str(file))
    else:
        # Files without clear indication go to unknown
        res[_type]["unknown"].append(str(file))

# Remove types that have no test cases
res = {k: v for k, v in res.items() if v["passed"] != [] or v["failed"] != [] or v["unknown"] != []}

# Load known rule types from CSV file
INFO_CSV = Path("assets/checkov/checkov_k8s_rules.csv")
df = pd.read_csv(INFO_CSV)
types = df["type"].unique().tolist()

# Minimum confidence score for fuzzy matching
confidence = 89

# Match test types with known rule types using fuzzy matching
for k, v in res.items():
    if k not in types:
        if v["failed"] != []:
            # Use fuzzy matching to find similar type names
            _res = process.extract(k, types, limit=20, scorer=fuzz.partial_ratio)
            # Keep only matches above confidence threshold
            _res = [i[0] for i in _res if i[1] >= confidence]
            res[k]["type"] = _res
    else:
        # If type matches exactly, use it as is
        res[k]["type"] = k

# Save processed dataset to JSON file
json.dump(res, open("assets/checkov/checkov_test_dataset.json", "w"), indent=4)
