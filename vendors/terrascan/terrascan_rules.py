import json
from pathlib import Path

# import polars as pl
import pandas as pd

K8S_RULES_DIR = Path("github/terrascan/pkg/policies/opa/rego/k8s")

rules = list(K8S_RULES_DIR.glob("*/*.json"))
regos = list(K8S_RULES_DIR.glob("*/*.rego"))

_tmp = []
for rule in rules:
    _ru = Path(json.load(open(rule, "r"))["file"]).stem
    for rego in regos:
        _re = Path(rego).stem
        if _ru == _re:
            _tmp.append(dict(json_file=str(rule), rego_file=str(rego)))
            continue

def get_id(str):
    with open(str, "r") as f:
        _dict = json.load(f)
    return _dict["id"]

def get_ref_id(str):
    with open(str, "r") as f:
        _dict = json.load(f)
    return _dict["reference_id"]

def get_severity(str):
    with open(str, "r") as f:
        _dict = json.load(f)
    return _dict["severity"]

df = pd.DataFrame(_tmp)
df["id"] = df["json_file"].apply(get_id)
df["ref_id"] = df["json_file"].apply(get_ref_id)
# print(df.head())
df.to_csv("assets/terrascan/terrascan_k8s_rules.csv", index=False)
