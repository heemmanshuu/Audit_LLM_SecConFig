"""
Script to fetch and save Helm chart YAML files from ArtifactHub repositories.

This script processes package information from ArtifactHub, adds Helm repositories,
and saves the rendered YAML templates for each package. It uses parallel processing
for improved performance when handling multiple packages.
"""

import json
import os
import subprocess
from typing import Dict

from joblib import Parallel, delayed
from tqdm.rich import tqdm

def get_package_info(data) -> Dict[str, str]:
    """
    Extract relevant package information from the raw data.

    Args:
        data (dict): Raw package data containing name and repository information.

    Returns:
        Dict[str, str]: Dictionary containing package name, repository name, and URL.
    """
    return {"name": data["name"], "repo": data["repository"]["name"], "url": data["repository"]["url"]}

def save_yaml(info: Dict[str, str], save_dir: str = "fetch_artifacthub/assets") -> int:
    """
    Add Helm repository and save the rendered YAML template for a package.

    Args:
        info (Dict[str, str]): Package information containing name, repo, and URL.
        save_dir (str, optional): Directory to save YAML files. Defaults to "fetch_artifacthub/assets".

    Returns:
        int: Return code indicating success (0) or failure (non-zero).
    """
    repo_add_result = subprocess.run(["helm", "repo", "add", info["name"], info["url"]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if repo_add_result.returncode != 0:
        return repo_add_result.returncode

    os.makedirs(save_dir, exist_ok=True)

    yaml_file_path = os.path.join(save_dir, f"{info['repo']}_{info['name']}.yaml")

    if os.path.exists(yaml_file_path):
        os.remove(yaml_file_path)

    template_command = ["helm", "template", f"my-{info['name']}", f"{info['repo']}/{info['name']}"]
    template_result = subprocess.run(template_command, capture_output=True, text=True)

    if template_result.returncode == 0:
        with open(yaml_file_path, "w") as f:
            f.write(template_result.stdout)
    else:
        return template_result.returncode

    return template_result.returncode

def process_items(data) -> int:
    """
    Process individual package data by extracting info and saving YAML.

    Args:
        data (dict): Raw package data to process.

    Returns:
        int: Return code from save_yaml operation.
    """
    info = get_package_info(data)
    result = save_yaml(info)
    return result

if __name__ == "__main__":
    with open("fetch_artifacthub/gathered/raw_final_results.json", "r") as f:
        data = json.load(f)

    results = Parallel(n_jobs=-1)(delayed(process_items)(item) for item in tqdm(data))
