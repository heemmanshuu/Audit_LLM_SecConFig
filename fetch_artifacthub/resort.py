"""
Script to resort and filter YAML files based on their original order in raw results.

This script performs the following operations:
1. Reads raw results and split files data
2. Reorders split files to match the original order in raw results
3. Creates a top 1000 subset of the results while maintaining file integrity
4. Saves both the reordered complete set and the top 1000 subset
"""

import json
from pathlib import Path

def get_file_name_from_raw(item):
    """
    Extract standardized filename from raw package data.

    Args:
        item (dict): Raw package data containing repository and name information.

    Returns:
        str: Standardized filename in format '{repository_name}_{package_name}'.
    """
    repo = item["repository"]["name"]
    app = item["name"]
    return f"{repo}_{app}"

# Load input files
with open("gathered/raw_final_results.json") as f:
    raw = json.load(f)
with open("gathered/split_files.json") as f:
    split = json.load(f)

# Generate filename stems from raw data
raw_files_stems = [get_file_name_from_raw(item) for item in raw]
stems = [Path(item["files"]).stem for item in split]

# Create mapping to original order
stems_order = [raw_files_stems.index(stem) for stem in stems]
split_with_order = list(zip(stems_order, split))
split_with_order.sort(key=lambda x: x[0])

# Extract reordered split data
split = [item[1] for item in split_with_order]

# Save reordered complete set
with open("gathered/split_files.json", "w") as f:
    json.dump(split, f, indent=2)

# Generate top 1000 subset
top_1000 = []
counter = 0
for item in split:
    len_res = len(item["results"])
    if counter + len_res <= 1000:
        top_1000.append(item)
        counter += len_res
    else:
        len_res = 1000 - counter
        results = item["results"][:len_res]
        top_1000.append({"files": item["files"], "results": results})
        break

# Save top 1000 subset
with open("gathered/top_1000_split_files.json", "w") as f:
    json.dump(top_1000, f, indent=2)

print(top_1000)
