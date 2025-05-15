import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pandas as pd
import yaml
from tqdm.rich import tqdm

sys.path.append(os.getcwd())

from vendors import KubeSec

def extract_test_info(text):
    def extract_one(func_text):
        # Extract function name
        func_name_match = re.search(r"func\s+(\w+)\(t \*testing\.T\)", func_text)
        if not func_name_match:
            return None, None

        func_name = func_name_match.group(1)

        # Extract YAML content
        yaml_match = re.search(r"var data = `\n(---\s*[\s\S]*?)`", func_text)
        yaml_content = yaml_match.group(1).strip() if yaml_match else None

        return func_name, yaml_content
    test_functions = re.split(r"\n(?=func Test_)", text)
    result = []
    for func in test_functions:
        if func.strip().startswith("func Test_"):
            func_name, yaml_content = extract_one(func)
            result.append((func_name, yaml_content))
    return result

TEST_DIR = "github/kubesec/pkg/rules"

test_files = list(Path(TEST_DIR).glob("*_test.go"))

result = subprocess.run(["kubesec", "print-rules", "-f", "json", ">", "assets/kubesec/kubesec_rules.json"], capture_output=True)
with open("assets/kubesec/kubesec_rules.json", "w") as f:
    _json = json.loads(result.stdout.decode("utf-8"))
    rules = json.dump(_json, f, indent=4)

with open("assets/kubesec/kubesec_rules.json", "r") as f:
    rules = json.loads(f.read())

result = {}
for rule in rules:
    if rule["points"] < 0:
        id = rule["id"]
        for test_file in test_files:
            if id.lower() in test_file.stem.lower():
                result[id] = {}
                with open(test_file, "r") as f:
                    _res = extract_test_info(f.read())
                result[id]["test"] = _res
                break

OUTPUT = "assets/kubesec/test_dataset"
if not os.path.exists(OUTPUT):
    os.makedirs(OUTPUT)

csv_res = []
for k, v in result.items():
    if not os.path.exists(os.path.join(OUTPUT, k)):
        os.makedirs(os.path.join(OUTPUT, k))
    for test_name, test_content in v["test"]:
        with open(os.path.join(OUTPUT, k, f"{test_name}.yaml"), "w") as f:
            yaml.dump(yaml.safe_load(test_content), f, indent=4)
        csv_res.append({"type": k, "yaml_file": os.path.join(OUTPUT, k, f"{test_name}.yaml")})

df = pd.DataFrame(csv_res)
print(df.head())

indices = []
kubesec = KubeSec()
for idx, row in tqdm(enumerate(df.iterrows()), total=len(df)):
    cat = row[1]["type"]
    results = kubesec.scan(row[1]["yaml_file"])
    cats = [i["id"] for i in results]
    if cat not in cats:
        indices.append(idx)

df.drop(indices, inplace=True, axis=0)
# print(df.head())
df.reset_index(drop=True, inplace=True)

df.to_csv("assets/kubesec/kubesec_test_dataset.csv", index=False)
