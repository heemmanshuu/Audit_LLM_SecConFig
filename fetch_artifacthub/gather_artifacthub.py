"""
Consolidates package data from individual JSON files into a single dataset.
This script processes package data from Artifacthub, sorts them by stars,
and outputs both complete and filtered (top 1000) results.
"""

import json
from glob import glob
from itertools import chain

from joblib import Parallel, delayed

def get_packages(file_path):
    """
    Extracts package data from a JSON file.

    Args:
        file_path (str): Path to the JSON file containing package data

    Returns:
        list: List of package dictionaries from the file's "packages" field
    """
    with open(file_path, "r") as f:
        data = json.load(f)
    return data["packages"]

if __name__ == "__main__":
    # Get all JSON files in the package_data directory
    files = glob("fetch_artifacthub/package_data/*.json")

    # Process files in parallel for better performance
    results = Parallel(n_jobs=-1)(delayed(get_packages)(f) for f in files)
    
    # Flatten the list of package lists into a single list
    final_results = list(chain(*results))
    
    # Sort packages by stars in descending order
    final_results.sort(key=lambda x: x["stars"], reverse=True)
    
    # Save complete results
    with open("fetch_artifacthub/gathered/raw_final_results.json", "w") as f:
        json.dump(final_results, f, indent=2)

    # Save top 1000 packages
    final_results = final_results[0:1000]
    with open("fetch_artifacthub/gathered/final_results.json", "w") as f:
        json.dump(final_results, f, indent=2)
