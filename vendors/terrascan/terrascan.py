import itertools
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from pprint import pprint
from typing import Any, Dict, Iterator, List, Literal, Optional, Tuple, Union

import jmespath
import pandas as pd
import thefuzz
import yaml
from langchain_core.messages import AIMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import Runnable

from ..llm_vendor import LLMVendor

class Terrascan(LLMVendor):
    def __init__(self):
        super().__init__("terrascan")
        self.config = None
        self.cur_result = dict()
        # self.prev_result = dict()
        self.template = ChatPromptTemplate.from_messages(
            [
                ("system", "You are a Kubernetes configuration checker and fixer. Your task is to analyze the provided configuration, identify potential errors, and provide a corrected version."),
                (
                    "human",
                    """-----------------------------------------------------------------
###Input
####I. Kubernetes Configuration
The following `YAML` configuration contains errors:

```yaml
{input_config}
```
-----------------------------------------------------------------
####II. Terrascan Output
This is the output from the `terrascan` tool:

{error_info}

Each `JSON` object includes:
- Rule Name
- Description
- Rule ID
- Severity
- Error Category

Pay close attention to the `description`, as it may contain crucial information about the error and potential remediation steps.
-----------------------------------------------------------------
####III. JSON Error Information
This `JSON` file contains detailed information about the errors:

{rego_json}

Each `JSON` object includes:
- Rule Name
- Template Arguments
    - Allowed & Not Allowed Values
    - Arguments & Prarameters
    - Prefix & Suffix of Arguments
    - Others
- Severity
- Description
- Reference ID
- Error Category
- Error ID
- Other relevant information

Pay close attention to the `description` and `template_args` fields, as they contain crucial information about the error and potential remediation steps.
-----------------------------------------------------------------
####IV. Rego File
This is the `rego` file associated with the JSON error information:

{rego_code}

The `rego` file contains the code used to detect errors in the Kubernetes configuration.
-----------------------------------------------------------------
""",
                ),
                (
                    "system",
                    """###Instructions
1. Carefully analyze the provided Kubernetes configuration.
2. Review the `terrascan` output, detailed JSON error information, and `rego` file to understand the nature and context of each error.
3. For each identified error:
    a. Determine the root cause based on the provided information.
    b. Develop a solution that addresses the issue while maintaining the original intent of the configuration.
    c. Apply the fix to the `YAML` configuration.
4. Ensure that your fixes do not introduce new errors or conflicts.
5. Double-check that all identified errors have been addressed.
6. Do not introduce new errors or conflicts into your result.
-----------------------------------------------------------------
###Output
Provide the fully corrected Kubernetes configuration in `YAML` format. Include only the fixed `YAML` file in your response, without any additional explanations or comments.
""",
                ),
            ]
        )
        self.df_path = "assets/terrascan/terrascan_k8s_rules.csv"
        self.df = pd.read_csv(self.df_path)

    def _scan(self, config: Iterator[Any]):
        tmp_path = self.generate_tempfile(config, "yaml")
        with open(tmp_path, "r") as f:
            self.config = yaml.load_all(f.read(), Loader=yaml.FullLoader)
        scan_output = subprocess.run([f"{self.name}", "scan", "-i", "k8s", "-f", tmp_path, "-o", "json"], capture_output=True)
        os.remove(tmp_path)
        self.cur_result = json.loads(scan_output.stdout.decode("utf-8"))
        return self.cur_result

    def get_context(self, result, df):
        def query_full_info(df, rule_id):
            _item = df[df["id"] == rule_id]
            return {
                "json_path": _item["json_file"].values[0],
                "rego_path": _item["rego_file"].values[0],
                "id": _item["id"].values[0],
                "ref_id": _item["ref_id"].values[0],
            }

        def _get_context(result, df):
            jsons = []
            regos = []
            for item in result["results"]["violations"]:
                res_dict = query_full_info(df, item["rule_id"])
                json_id = res_dict["json_path"].split("/")[-1]
                with open(res_dict["json_path"], "r") as f:
                    _json = json.dumps(json.load(f), indent=4)
                if json_id not in [i[0] for i in jsons]:
                    jsons.append((json_id, _json))

                rego_id = res_dict["rego_path"].split("/")[-1]
                with open(res_dict["rego_path"], "r") as f:
                    _str = f.read()
                if rego_id not in [i[0] for i in regos]:
                    regos.append((rego_id, _str))
            return jsons, regos
        _context = _get_context(result, df)
        self.failed_count = result["results"]["scan_summary"]["violated_policies"]
        return {"output": result["results"]["violations"], "jsons": _context[0], "regos": _context[1]}

    def compose_result(self, result):
        c_output = []
        c_jsons = []
        c_regos = []
        for item in result["output"]:
            item = "```json\n" + str(json.dumps(item, indent=4)) + "\n```"
            c_output.append(item)
        for name, item in result["jsons"]:
            item = "-" * 3 + name + "-" * 3 + "\n" + "```json\n" + str(item) + "\n```"
            c_jsons.append(item)
        for name, item in result["regos"]:
            item = "-" * 3 + name + "-" * 3 + "\n" + "```rego\n" + str(item) + "\n```"
            c_regos.append(item)
        return c_output, c_jsons, c_regos

    def parse_result(self, result):
        output = []
        jsons = []
        regos = []
        for item in result["output"]:
            output.append(str(json.dumps(item, indent=4)))
        for _, item in result["jsons"]:
            jsons.append(str(item))
        for _, item in result["regos"]:
            regos.append(str(item))
        return output, jsons, regos

    def one_round(self, result: Dict[Any, Any]):
        if result.get("results", None):
            if result["results"]["scan_summary"]["violated_policies"] == 0:
                return dict(error_info=None, rego_json="", rego_code="")
            result = self.get_context(result, self.df)
            c_output, c_jsons, c_regos = self.compose_result(result)
            c_output = "\n".join(c_output)
            c_jsons = "\n".join(c_jsons)
            c_regos = "\n".join(c_regos)
            output, jsons, regos = self.parse_result(result)
            return dict(
                error_info=output,
                rego_json=jsons,
                rego_code=regos,
                composed_error_info=c_output,
                composed_rego_json=c_jsons,
                composed_rego_code=c_regos,
            )
        else:
            return dict(error_info=False, rego_json="", rego_code="")

    def fix(self, config: Union[str, Iterator[Any]], llm_chain: Runnable, retry=3):
        _config = config
        for step_id in range(retry):
            _result = self.scan(_config)  # GET SCAN RESULT
            result = self.one_round(_result)  # GET CONTEXT
            if not result["error_info"]:
                return None, _result, step_id
            input_config = self.dump_yaml(self.config)
            # print(_result)
            # print(self.template.format_prompt(**{"input_config": input_config, "error_info": result["composed_error_info"], "rego_json": result["composed_rego_json"], "rego_code": result["composed_rego_code"]}))
            raw_fixed_config = llm_chain.invoke(
                {"input_config": input_config, "error_info": result["composed_error_info"], "rego_json": result["composed_rego_json"], "rego_code": result["composed_rego_code"]}
            )
            if isinstance(raw_fixed_config, AIMessage):
                raw_fixed_config = raw_fixed_config.content
            fixed_config = list(self.read_yaml_from_str(raw_fixed_config.replace("```yaml", "").replace("```", "")))
            _config = fixed_config
            _result = self.scan(_config)  # GET SCAN RESULT
        return fixed_config, _result, step_id
