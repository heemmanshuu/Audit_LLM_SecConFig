"""Checkov security scanner integration with LLM capabilities.

This module provides an enhanced interface to the Checkov security scanner,
integrating it with Large Language Models (LLMs) for automated fixing of
security issues in Kubernetes configurations. It supports multiple modes of
operation and can utilize various sources of information including Python
code analysis and Prisma Cloud documentation.

The module operates in four modes:
- all: Uses all available information sources
- raw: Only uses basic Checkov output
- code: Includes Python code analysis
- prisma: Includes Prisma Cloud documentation
"""

import json
import os
import subprocess
import time
from functools import lru_cache
from typing import Any, Dict, Iterator, List, Literal, Optional, Tuple, Union

import httpx
import pandas as pd
import yaml
from groq import APIStatusError
from langchain_community.callbacks import UpstashRatelimitError
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import Runnable
from openai import RateLimitError

from ..llm_vendor import LLMVendor

class Checkov(LLMVendor):
    """Checkov security scanner with LLM-powered fixing capabilities.
    
    This class extends LLMVendor to provide automated security scanning and fixing
    of Kubernetes configurations using the Checkov tool and Large Language Models.
    
    Args:
        name (str): The name of the vendor. Defaults to "checkov"
        mode (Literal["all", "raw", "code", "prisma"]): Operation mode determining
            what information sources to use. Defaults to "all"
            
    Attributes:
        conda_prefix (str): Path to the Conda environment
        exec (str): Path to the Checkov executable
        config (Any): Current configuration being processed
        cur_result (dict): Current scan results
        mode (str): Current operation mode
        template (ChatPromptTemplate): Template for LLM interaction
        prisma (str): Path to Prisma Cloud documentation
        df_path (str): Path to Checkov rules CSV file
        df (pd.DataFrame): DataFrame containing Checkov rules
        
    Raises:
        EnvironmentError: If Conda environment is not activated
        ValueError: If an invalid mode is specified
    """
    def __init__(self, name="checkov", mode: Literal["all", "raw", "code", "prisma"] = "all"):
        super().__init__(name)
        self.conda_prefix = os.environ.get("CONDA_PREFIX")
        if not self.conda_prefix:
            raise EnvironmentError("Conda environment not activated")
        self.exec = os.path.join(self.conda_prefix, "bin", self.name)
        self.config = None
        self.cur_result = dict()
        # self.prev_result = dict()
        self.mode = mode
        match mode:
            case "raw":
                self.template = ChatPromptTemplate.from_messages([self.pt_begin, self.pt_raw_conf, self.pt_checkov_output, self.pt_instructions_output])
            case "code":
                self.template = ChatPromptTemplate.from_messages([self.pt_begin, self.pt_raw_conf, self.pt_checkov_output, self.pt_python_code, self.pt_instructions_output])
            case "prisma":
                self.template = ChatPromptTemplate.from_messages([self.pt_begin, self.pt_raw_conf, self.pt_checkov_output, self.pt_prisma, self.pt_instructions_output])
            case "all":
                self.template = ChatPromptTemplate.from_messages([self.pt_begin, self.pt_raw_conf, self.pt_checkov_output, self.pt_python_code, self.pt_prisma, self.pt_instructions_output])
            case _:
                raise ValueError(f"Invalid mode: {mode}")
        self.prisma = "github/prisma-cloud-docs/docs/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index"
        self.df_path = "assets/checkov/checkov_k8s_rules.csv"
        self.df = pd.read_csv(self.df_path)

    @property
    def pt_begin(self):
        """Get the initial system prompt.
        
        Returns:
            Tuple[str, str]: Message type and content for the system prompt
        """
        return (
            "system",
            """You are a Kubernetes configuration checker and fixer. Your task is to analyze the provided configuration, identify potential errors, and provide a corrected version only.
-----------------------------------------------------------------""",
        )

    @property
    def pt_raw_conf(self):
        """Get the raw configuration prompt.
        
        Returns:
            Tuple[str, str]: Message type and content for the raw configuration prompt
        """
        return (
            "human",
            """###Input
####I. Kubernetes Configuration
The following `YAML` configuration contains errors:

```yaml
{input_config}
```
-----------------------------------------------------------------""",
        )

    @property
    def pt_checkov_output(self):
        """Get the Checkov output prompt.
        
        Returns:
            Tuple[str, str]: Message type and content for the Checkov output prompt
        """
        return (
            "human",
            """####II. Checkov Output
This is the output from the `checkov` tool:

{error_info}

Each `JSON` object includes:
- Check ID
- BC Check ID
- Check Name (Description)
- Check result
- File Line Range
- Resource and Check Class
- Guideline (pair with bc_check_id)
- Other relevant information

Pay close attention to the `check_name` and `check_result` fields, as they contain crucial information about the error and potential remediation steps.
-----------------------------------------------------------------""",
        )

    @property
    def pt_python_code(self):
        """Get the Python code prompt.
        
        Returns:
            Tuple[str, str]: Message type and content for the Python code prompt
        """
        return (
            "human",
            """####III. Python/YAML File
This is the `python`/`yaml` file associated with the JSON error information:

{python_code}

Each `python` code includes:
- Error Description: `name` in __init__()
- Error ID: `id` in __init__()
- Detection Function: attibute functions in the class

Each `YAML` object includes:
- Metadata
    - ID
    - Description
- Definition
    - Actual Implementation

The `python` file contains the code used to detect errors in the Kubernetes configuration.
For `yaml`, pay close attention to the `Description` and `Definition` fields, as they contain crucial information about the error and potential remediation steps.
-----------------------------------------------------------------""",
        )

    @property
    def pt_prisma(self):
        """Get the Prisma Cloud information prompt.
        
        Returns:
            Tuple[str, str]: Message type and content for the Prisma Cloud information prompt
        """
        return (
            "human",
            """####IV. Prisma Cloud Information
This `ADOC` file contain detailed information about the errors:

{prisma}

Each `ADOC` object includes:
- Policy Details
    - Checkov ID
    - Severity
    - Other Relevant Information
- Description
- Fix - Buildtime
    - Namespace & Description
    - Examples (Important)
        - if line start with `-`, you should remove the line from the input YAML
        - if line start with `+`, you should add the line to the input YAML

Pay close attention to the `Description` and `Fix - Buildtime` fields, as they contain crucial information about the error and potential remediation steps.
-----------------------------------------------------------------""",
        )

    @property
    def pt_instructions_output(self):
        """Get the instructions and output prompt.
        
        Returns:
            Tuple[str, str]: Message type and content for the instructions and output prompt
        """
        match self.mode:
            case "all":
                return (
                    "system",
                    """###Instructions
1. Carefully analyze the provided Kubernetes configuration.
2. Review the `checkov` output, `python` file and Prisma Cloud/YAML Information to understand the nature and context of each error.
3. For each identified error:
    a. Determine the root cause based on the provided information.
    b. Develop a solution that addresses the issue while maintaining the original intent of the configuration.
    c. Apply the fix to the YAML configuration.
4. Ensure that your fixes do not introduce new errors or conflicts.
5. Double-check that all identified errors have been addressed.
6. Do not introduce new errors or conflicts into your result.
-----------------------------------------------------------------
###Output
Provide the fully corrected Kubernetes configuration in `YAML` format. Include only the fixed `YAML` file in your response, without any additional explanations or comments, code block starts with '```yaml' and ends with '```'.""",
                )
            case "raw":
                return (
                    "system",
                    """###Instructions
1. Carefully analyze the provided Kubernetes configuration.
2. Review the `checkov` output to understand the nature and context of each error.
3. For each identified error:
    a. Determine the root cause based on the provided information.
    b. Develop a solution that addresses the issue while maintaining the original intent of the configuration.
    c. Apply the fix to the YAML configuration.
4. Ensure that your fixes do not introduce new errors or conflicts.
5. Double-check that all identified errors have been addressed.
6. Do not introduce new errors or conflicts into your result.
-----------------------------------------------------------------
###Output
Provide the fully corrected Kubernetes configuration in `YAML` format. Include only the fixed `YAML` file in your response, without any additional explanations or comments, code block starts with '```yaml' and ends with '```'.""",
                )
            case "code":
                return (
                    "system",
                    """###Instructions
1. Carefully analyze the provided Kubernetes configuration.
2. Review the `checkov` output and `python` file to understand the nature and context of each error.
3. For each identified error:
    a. Determine the root cause based on the provided information.
    b. Develop a solution that addresses the issue while maintaining the original intent of the configuration.
    c. Apply the fix to the YAML configuration.
4. Ensure that your fixes do not introduce new errors or conflicts.
5. Double-check that all identified errors have been addressed.
6. Do not introduce new errors or conflicts into your result.
-----------------------------------------------------------------
###Output
Provide the fully corrected Kubernetes configuration in `YAML` format. Include only the fixed `YAML` file in your response, without any additional explanations or comments, code block starts with '```yaml' and ends with '```'.""",
                )
            case "prisma":
                return (
                    "system",
                    """###Instructions
1. Carefully analyze the provided Kubernetes configuration.
2. Review the `checkov` output and Prisma Cloud/YAML Information to understand the nature and context of each error.
3. For each identified error:
    a. Determine the root cause based on the provided information.
    b. Develop a solution that addresses the issue while maintaining the original intent of the configuration.
    c. Apply the fix to the YAML configuration.
4. Ensure that your fixes do not introduce new errors or conflicts.
5. Double-check that all identified errors have been addressed.
6. Do not introduce new errors or conflicts into your result.
-----------------------------------------------------------------
###Output
Provide the fully corrected Kubernetes configuration in `YAML` format. Include only the fixed `YAML` file in your response, without any additional explanations or comments, code block starts with '```yaml' and ends with '```'.""",
                )

    def _scan(self, config: Iterator[Any]) -> Dict[Any, Any]:
        """Scan a configuration using Checkov.
        
        Args:
            config (Iterator[Any]): Configuration to scan
            
        Returns:
            Dict[Any, Any]: Scan results
        """
        tmp_path = self.generate_tempfile(config, "yaml")
        with open(tmp_path, "r") as f:
            self.config = yaml.load_all(f.read(), Loader=yaml.FullLoader)
        scan_output = subprocess.run([self.exec, "-f", tmp_path, "--framework", "kubernetes", "-o", "json", "--compact", "--quiet"], capture_output=True)
        os.remove(tmp_path)
        self.cur_result = json.loads(scan_output.stdout.decode("utf-8"))
        return self.cur_result

    @staticmethod
    def get_source_code_path(df: pd.DataFrame, rule_id: str) -> str:
        """Get the source code path for a rule.
        
        Args:
            df (pd.DataFrame): DataFrame containing rule information
            rule_id (str): ID of the rule
            
        Returns:
            str: Path to the source code file
        """
        return df[df["id"] == rule_id]["file"].values[0]

    def _get_context(self, result: Dict[Any, Any], df: pd.DataFrame) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str, str]]]:
        """Get source code and Prisma documentation context for scan results.
        
        Args:
            result (Dict[Any, Any]): Scan results
            df (pd.DataFrame): DataFrame containing rule information
            
        Returns:
            Tuple[List[Tuple[str, str]], List[Tuple[str, str, str]]]:
                Files and Prisma documentation content
        """
        """Get unique source code and prismas from result"""

        files = []
        prismas = []
        for item in result["results"]["failed_checks"]:
            self._add_source_code(item, df, files)
            self._add_prisma_info(item, prismas)
        return files, prismas

    def _add_source_code(self, item: Dict[str, Any], df: pd.DataFrame, files: List[Tuple[str, str]]):
        """Add source code for a failed check.
        
        Args:
            item (Dict[str, Any]): Failed check information
            df (pd.DataFrame): DataFrame containing rule information
            files (List[Tuple[str, str]]): List of files to add to
        """
        check_id = item["check_id"]
        if check_id not in [i[0] for i in files]:
            code_path = self.get_source_code_path(df, check_id)
            file_content = self._read_file(code_path)
            with open(code_path, "r") as f:
                files.append((check_id, file_content))

    def _add_prisma_info(self, item: Dict[str, Any], prismas: List[Tuple[str, str, str]]):
        """Add Prisma documentation for a failed check.
        
        Args:
            item (Dict[str, Any]): Failed check information
            prismas (List[Tuple[str, str, str]]): List of Prisma documentation to add to
        """
        check_id = item["check_id"]
        bc_check_id = item.get("bc_check_id")
        if bc_check_id:
            try:
                prisma_content = self._get_prisma_content_from_bc_check_id(bc_check_id)
                if bc_check_id not in [i[1] for i in prismas]:
                    prismas.append((check_id, bc_check_id, prisma_content))
            except FileNotFoundError:
                self._add_prisma_from_guideline(item, check_id, prismas)

    @lru_cache(maxsize=128)
    def _get_prisma_content_from_bc_check_id(self, bc_check_id: str) -> str:
        """Get Prisma documentation content from a BC check ID.
        
        Args:
            bc_check_id (str): BC check ID
            
        Returns:
            str: Prisma documentation content
        """
        file_name = f"{bc_check_id.lower().replace('_', '-')}.adoc"
        with open(os.path.join(self.prisma, file_name), "r") as f:
            return f.read()

    def _add_prisma_from_guideline(self, item: Dict[str, Any], check_id: str, prismas: List[Tuple[str, str, str]]):
        """Add Prisma documentation from a guideline.
        
        Args:
            item (Dict[str, Any]): Failed check information
            check_id (str): Check ID
            prismas (List[Tuple[str, str, str]]): List of Prisma documentation to add to
        """
        guideline = item.get("guideline")
        if guideline:
            name = guideline.split("/")[-1] + ".adoc"
            try:
                prisma_content = self._get_prisma_content_from_name(name)
                if name not in [i[1] for i in prismas]:
                    prismas.append((check_id, name, prisma_content))
            except FileNotFoundError:
                pass

    @lru_cache(maxsize=128)
    def _get_prisma_content_from_name(self, name: str) -> str:
        """Get Prisma documentation content from a name.
        
        Args:
            name (str): Name of the Prisma documentation
            
        Returns:
            str: Prisma documentation content
        """
        try:
            return self._read_file(os.path.join(self.prisma, name))
        except FileNotFoundError:
            return self._find_and_read_file(name)

    def _find_and_read_file(self, name: str) -> str:
        """Find and read a file.
        
        Args:
            name (str): Name of the file
            
        Returns:
            str: File content
        """
        _tmp_prismas = "/".join(self.prisma.split("/")[:-2])
        for root, _, files in os.walk(_tmp_prismas):
            if name in files:
                return self._read_file(os.path.join(root, name))
        raise FileNotFoundError(f"Could not find file: {name}")

    @staticmethod
    @lru_cache(maxsize=128)
    def _read_file(file_path: str) -> str:
        """Read a file.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            str: File content
        """
        with open(file_path, "r") as f:
            return f.read()

    def get_context(self, result: Dict[Any, Any], df: pd.DataFrame):
        """Get context for scan results.
        
        Args:
            result (Dict[Any, Any]): Scan results
            df (pd.DataFrame): DataFrame containing rule information
            
        Returns:
            dict: Context for scan results
        """
        self.failed_count = result["summary"]["failed"]
        _context = self._get_context(result, df)
        return {"error_info": result["results"]["failed_checks"], "python_code": _context[0], "prisma": _context[1]}

    def compose_result(self, result):
        """Compose result data.
        
        Args:
            result: Scan results and context
            
        Returns:
            dict: Composed result data
        """
        output = []
        files = []
        prismas = []
        for item in result["error_info"]:
            item = "```json\n" + json.dumps(item, indent=4) + "\n```"
            # item = json.dumps(item, indent=4)
            output.append(item)
        for name, item in result["python_code"]:
            item = "-" * 3 + name + "-" * 3 + "\n" + "```python\n" + str(item) + "\n```"
            files.append(item)
        for name, bc, item in result["prisma"]:
            item = "-" * 3 + name + "-" * 3 + bc + "-" * 3 + "\n" + "```adoc\n" + str(item) + "\n```"
            prismas.append(item)
        return {"composed_error_info": output, "composed_python_code": files, "composed_prisma": prismas}

    def parse_result(self, result):
        """Parse result data.
        
        Args:
            result: Scan results and context
            
        Returns:
            dict: Parsed result data
        """
        output = []
        files = []
        prismas = []
        for item in result["error_info"]:
            output.append(json.dumps(item, indent=4))
        for _, item in result["python_code"]:
            files.append(str(item))
        for _, _, item in result["prisma"]:
            prismas.append(str(item))
        return {"error_info": output, "python_code": files, "prisma": prismas}

    def one_round(self, result: Dict[Any, Any]) -> Dict[Any, Any]:
        """Process one round of scan results.
        
        Args:
            result (Dict[Any, Any]): Scan results
            
        Returns:
            dict: Processed results
        """
        if result.get("summary", None):
            if result["summary"]["failed"] == 0:
                return dict(error_info=None, python_code="", prisma="")
            result = self.get_context(result, self.df)
            return dict(error_info=result["error_info"], python_code=result["python_code"], prisma=result["prisma"])
        else:
            return dict(error_info=False, python_code="", prisma="")

    def fix(self, config: Union[str, Iterator[Any]], llm_chain: Runnable, retry=3, PARSE_RETRY=5, stop_word: Optional[str] = None):
        """Fix security issues in a configuration using LLM.
        
        Args:
            config (Union[str, Iterator[Any]]): Configuration to fix
            llm_chain (Runnable): LLM chain to use for fixing
            retry (int): Number of fix attempts. Defaults to 3
            PARSE_RETRY (int): Number of LLM parsing retries. Defaults to 5
            stop_word (Optional[str]): Stop when this check passes. Defaults to None
            
        Returns:
            Tuple[Any, Dict, int, bool]: Fixed config, final results, steps taken, success flag
        """
        _config = config
        stop_id = self.get_id_from_type(stop_word, self.df) if stop_word else None

        for step_id in range(retry):
            _result = self.scan(_config)
            result = self.process_scan_result(_result)

            if not result["error_info"]:
                return None, _result, step_id, None

            input_config = self.dump_yaml(self.config)
            result.update(self.prepare_result_data(result))

            raw_fixed_config = self.get_fixed_config_from_llm(llm_chain, input_config, result, PARSE_RETRY)
            fixed_config = list(self.read_yaml_from_str(raw_fixed_config))

            _config = fixed_config
            _result = self.scan(_config)

            if self.check_stop_condition(stop_id, _result) or self.check_all_passed(_result):
                return fixed_config, _result, step_id, True

        return fixed_config, _result, step_id, False

    async def afix(self, config: Union[str, Iterator[Any]], llm_chain: Runnable, retry=3, PARSE_RETRY=5, stop_word: Optional[str] = None):
        """Asynchronously fix security issues in a configuration using LLM.
        
        Args:
            config (Union[str, Iterator[Any]]): Configuration to fix
            llm_chain (Runnable): LLM chain to use for fixing
            retry (int): Number of fix attempts. Defaults to 3
            PARSE_RETRY (int): Number of LLM parsing retries. Defaults to 5
            stop_word (Optional[str]): Stop when this check passes. Defaults to None
            
        Returns:
            Tuple[Any, Dict, int, bool]: Fixed config, final results, steps taken, success flag
        """
        _config = config
        stop_id = self.get_id_from_type(stop_word, self.df) if stop_word else None

        for step_id in range(retry):
            _result = self.scan(_config)
            result = self.process_scan_result(_result)

            if not result["error_info"]:
                return None, _result, step_id, None

            input_config = self.dump_yaml(self.config)
            result.update(self.prepare_result_data(result))

            raw_fixed_config = await self.get_fixed_config_from_llm_async(llm_chain, input_config, result, PARSE_RETRY)
            fixed_config = list(self.read_yaml_from_str(raw_fixed_config))

            _config = fixed_config
            _result = self.scan(_config)

            if self.check_stop_condition(stop_id, _result) or self.check_all_passed(_result):
                return fixed_config, _result, step_id, True

        return fixed_config, _result, step_id, False

    def get_fixed_config_from_llm(self, llm_chain, input_config, result, PARSE_RETRY):
        """Get fixed configuration from LLM.
        
        Args:
            llm_chain: LLM chain to use
            input_config: Original configuration
            result: Scan results and context
            PARSE_RETRY: Number of retry attempts
            
        Returns:
            str: Fixed configuration
            
        Raises:
            Exception: If failed to get fixed config after retries
        """
        curr = 0
        while curr < PARSE_RETRY:
            try:
                match self.mode:
                    case "all":
                        raw_fixed_config = llm_chain.invoke(
                            {"input_config": input_config, "error_info": result["composed_error_info"], "python_code": result["composed_python_code"], "prisma": result["composed_prisma"]}
                        )
                    case "raw":
                        raw_fixed_config = llm_chain.invoke({"input_config": input_config, "error_info": result["composed_error_info"]})
                    case "code":
                        raw_fixed_config = llm_chain.invoke({"input_config": input_config, "error_info": result["composed_error_info"], "python_code": result["composed_python_code"]})
                    case "prisma":
                        raw_fixed_config = llm_chain.invoke({"input_config": input_config, "error_info": result["composed_error_info"], "prisma": result["composed_prisma"]})
                self._scan(list(self.read_yaml_from_str(raw_fixed_config)))
                return raw_fixed_config.content if isinstance(raw_fixed_config, AIMessage) else raw_fixed_config
            except (RateLimitError, UpstashRatelimitError) as e:
                raise e
            except APIStatusError as e:
                raise e
            except httpx.ReadTimeout as e:
                print(e)
                time.sleep(1)
                curr += 1
            except Exception as e:
                print(f"{type(e)}: {e}")
                curr += 1
        raise Exception("Failed to get fixed config from LLM")

    async def get_fixed_config_from_llm_async(self, llm_chain, input_config, result, PARSE_RETRY):
        """Asynchronously get fixed configuration from LLM.
        
        Args:
            llm_chain: LLM chain to use
            input_config: Original configuration
            result: Scan results and context
            PARSE_RETRY: Number of retry attempts
            
        Returns:
            str: Fixed configuration
            
        Raises:
            Exception: If failed to get fixed config after retries
        """
        curr = 0
        while curr < PARSE_RETRY:
            try:
                match self.mode:
                    case "all":
                        raw_fixed_config = await llm_chain.ainvoke(
                            {"input_config": input_config, "error_info": result["composed_error_info"], "python_code": result["composed_python_code"], "prisma": result["composed_prisma"]}
                        )
                    case "raw":
                        raw_fixed_config = await llm_chain.ainvoke({"input_config": input_config, "error_info": result["composed_error_info"]})
                    case "code":
                        raw_fixed_config = await llm_chain.ainvoke({"input_config": input_config, "error_info": result["composed_error_info"], "python_code": result["composed_python_code"]})
                    case "prisma":
                        raw_fixed_config = await llm_chain.ainvoke({"input_config": input_config, "error_info": result["composed_error_info"], "prisma": result["composed_prisma"]})
                self._scan(list(self.read_yaml_from_str(raw_fixed_config)))
                return raw_fixed_config.content if isinstance(raw_fixed_config, AIMessage) else raw_fixed_config
            except (RateLimitError, UpstashRatelimitError) as e:
                raise e
            except APIStatusError as e:
                raise e
            except httpx.ReadTimeout as e:
                print(e)
                await time.sleep(1)
                curr += 1
            except Exception as e:
                print(f"{type(e)}: {e}")
                curr += 1
        raise Exception("Failed to get fixed config from LLM")

    def process_scan_result(self, _result):
        """Process scan results, handling both single and multiple results.
        
        Args:
            _result: Raw scan results
            
        Returns:
            dict: Processed results with error info and context
        """
        if isinstance(_result, list):
            return self.merge_subresults([self.one_round(subresult) for subresult in _result])
        return self.one_round(_result)

    def merge_subresults(self, subresults):
        """Merge multiple scan results into one.
        
        Args:
            subresults: List of scan results to merge
            
        Returns:
            dict: Merged results
        """
        result = {}
        for subresult in subresults:
            for k, v in subresult.items():
                if k in result and isinstance(v, list):
                    result[k] += v
                else:
                    result[k] = v
        return result

    def prepare_result_data(self, result):
        """Prepare result data for LLM consumption.
        
        Args:
            result: Raw scan results
            
        Returns:
            dict: Processed results with composed and parsed data
        """
        c_result = self.compose_result(result)
        p_result = self.parse_result(result)
        for data in (c_result, p_result):
            for k, v in data.items():
                data[k] = "\n".join(list(set(v)))
        return {**c_result, **p_result}

    def check_stop_condition(self, stop_id, _result):
        """Check if we should stop fixing based on a specific check.
        
        Args:
            stop_id: ID of the check to stop on
            _result: Current scan results
            
        Returns:
            bool: True if should stop, False otherwise
        """
        if not stop_id:
            return False
        failed_checks_ids = self.get_failed_check_ids(_result)
        return stop_id not in failed_checks_ids

    def get_failed_check_ids(self, _result):
        """Get IDs of all failed checks.
        
        Args:
            _result: Scan results
            
        Returns:
            List[str]: List of failed check IDs
        """
        if isinstance(_result, list):
            return list(set([item["check_id"] for __result in _result for item in __result["results"]["failed_checks"]]))
        return list(set([item["check_id"] for item in _result["results"]["failed_checks"]]))

    def check_all_passed(self, _result):
        """Check if all security checks passed.
        
        Args:
            _result: Scan results
            
        Returns:
            bool: True if all passed, False otherwise
        """
        return _result.get("summary", {}).get("failed", 1) == 0

    @lru_cache(maxsize=None)
    def get_id_from_type(self, type, df):
        """Get rule ID from its type.
        
        Args:
            type: Rule type
            df: DataFrame containing rule information
            
        Returns:
            str: Rule ID
        """
        item = df[df["type"] == type]
        return item["id"].values[0]
