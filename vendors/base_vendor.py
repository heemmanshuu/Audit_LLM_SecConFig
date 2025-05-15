"""Base module for security configuration vendors."""

import io
import json
import re
import tempfile
from typing import Any, Dict, Iterator, Literal

import yaml
from langchain_core.exceptions import OutputParserException
from langchain_core.output_parsers import BaseOutputParser

class BaseVendor:
    """Base class for security configuration vendors.
    
    This class provides a common interface for all security configuration vendors
    to implement scanning, updating, and fixing security configurations.
    
    Args:
        name (str): The name of the vendor
    """
    def __init__(self, name):
        self.name = name
        self.flatten = None

    def __call__(self):
        pass

    def scan(self):
        """Scan configuration files for security issues.
        
        This method should be implemented by subclasses to perform security scans.
        """
        pass

    def update(self):
        """Update security configurations.
        
        This method should be implemented by subclasses to update configurations.
        """
        pass

    def fix(self):
        """Fix identified security issues.
        
        This method should be implemented by subclasses to fix security issues.
        """
        pass

    def generate_tempfile(self, data, target_format: Literal["json", "yaml"] = "yaml"):
        """Generate a temporary file with the given data in specified format.
        
        Args:
            data: The data to write to the temporary file
            target_format (Literal["json", "yaml"]): The format to write the data in. Defaults to "yaml"
            
        Returns:
            str: The path to the generated temporary file
        """
        with tempfile.NamedTemporaryFile(delete=False, mode="w+", suffix=f".{target_format}") as temp:
            match target_format:
                case "json":
                    json.dump(data, temp, indent=4)
                case "yaml":
                    yaml.dump_all(data, temp, indent=4)
            temp.seek(0)  # Ensure file is ready for reading if needed
            return temp.name

    @staticmethod
    def flatten_json(obj):
        """Flatten a nested JSON object into a single level dictionary.
        
        Args:
            obj: The nested JSON object to flatten
            
        Returns:
            dict: A flattened dictionary where nested keys are joined with dots
        """
        out = {}
        def flatten(_obj, name=""):
            if isinstance(_obj, dict):
                for a in _obj:
                    flatten(_obj[a], name + a + ".")
            elif isinstance(_obj, list):
                for idx, a in enumerate(_obj):
                    flatten(a, (name[:-1] if name.endswith(".") else name) + f"[{idx}].")
            else:
                out[name[:-1] if name.endswith(".") else name] = _obj
        flatten(obj)
        return out

    def get_flatten(self, obj):
        self.flatten = self.flatten_json(obj)
        return self.flatten

    def read_json_from_file(self, filename):
        """Read JSON data from a file.
        
        Args:
            filename (str): The path to the JSON file
            
        Returns:
            dict: The JSON data read from the file
        """
        with open(filename, "r") as f:
            return json.load(f)

    def read_json_from_str(self, data: str):
        """Read JSON data from a string.
        
        Args:
            data (str): The JSON data as a string
            
        Returns:
            dict: The JSON data read from the string
        """
        return json.loads(data)

    def dump_json_from_dict(self, data: Dict[Any, Any]):
        """Dump JSON data from a dictionary.
        
        Args:
            data (Dict[Any, Any]): The dictionary to dump as JSON
            
        Returns:
            str: The JSON data as a string
        """
        return json.dumps(data, indent=4)

    def read_yaml_from_file(self, filename):
        """Read YAML data from a file.
        
        Args:
            filename (str): The path to the YAML file
            
        Returns:
            Iterator[Any]: The YAML data read from the file
        """
        with open(filename, "r") as f:
            return yaml.load_all(f.read(), Loader=yaml.FullLoader)

    def read_yaml_from_str(self, data: str):
        """Read YAML data from a string.
        
        Args:
            data (str): The YAML data as a string
            
        Returns:
            Iterator[Any]: The YAML data read from the string
        """
        return yaml.load_all(data, Loader=yaml.FullLoader)

    def dump_yaml(self, input_obj: Iterator[Any]):
        """Dump YAML data from an iterator.
        
        Args:
            input_obj (Iterator[Any]): The YAML data to dump
            
        Returns:
            str: The YAML data as a string
        """
        stringio = io.StringIO()
        yaml.dump_all(input_obj, stringio, indent=4)
        return stringio.getvalue()

    def dump_yaml_to_file(self, input_obj: Iterator[Any], filename: str):
        """Dump YAML data to a file.
        
        Args:
            input_obj (Iterator[Any]): The YAML data to dump
            filename (str): The path to the file to write to
        """
        with open(filename, "w") as f:
            yaml.dump_all(input_obj, f, indent=4)

    def dump_json_to_file(self, input_obj: Dict[Any, Any], filename: str):
        """Dump JSON data to a file.
        
        Args:
            input_obj (Dict[Any, Any]): The JSON data to dump
            filename (str): The path to the file to write to
        """
        with open(filename, "w") as f:
            json.dump(input_obj, f, indent=4)

    def dump_from_file(self, filename: str):
        """Dump data from a file.
        
        Args:
            filename (str): The path to the file to read from
            
        Returns:
            str: The data read from the file as a string
        """
        if filename.endswith(".json"):
            _dict = self.read_json_from_file(filename)
            return self.dump_yaml([_dict])
        elif filename.endswith(".yaml") or filename.endswith(".yml"):
            _dict = self.read_yaml_from_file(filename)
            return self.dump_yaml(_dict)
        else:
            raise ValueError("File format not supported")

class YAMLTextOutputParser(BaseOutputParser):
    """Parser for extracting YAML content from text blocks.
    
    This parser looks for YAML content between markdown code blocks and parses it.
    """
    pattern: re.Pattern = re.compile(r"^```(?:ya?ml)?\s*\n(.*?)\n\s*```", re.MULTILINE | re.DOTALL)

    def parse(self, text: str) -> str:
        try:
            matches = list(self.pattern.finditer(text))

            if not matches:
                raise OutputParserException("No YAML block found")
            if len(matches) > 1:
                raise OutputParserException(f"Found {len(matches)} YAML blocks, expected only 1")

            return matches[0].group(1).strip()
        except:
            try:
                content = text.strip().replace("```yaml", "").replace("```", "")
                yaml.load_all(content, Loader=yaml.FullLoader)
                return content.strip()
            except:
                raise OutputParserException("No YAML block found")

    @property
    def _type(self) -> str:
        return "yaml_text_output_parser"

if __name__ == "__main__":
    print(BaseVendor("test").generate_tempfile([{"test": "test"}], "json"))
