"""Base module for LLM-based security configuration vendors.

This module provides a base class for vendors that use Large Language Models (LLMs)
to analyze and fix security configurations.
"""

import os
from typing import Any, Dict, Iterator, Union

from .base_vendor import BaseVendor

class LLMVendor(BaseVendor):
    """Base class for LLM-based security configuration vendors.
    
    This class extends BaseVendor to provide additional functionality for vendors
    that use Large Language Models to process security configurations.
    
    Args:
        name (str): The name of the vendor
    """
    def __init__(self, name):
        super(LLMVendor, self).__init__(name)
        self.failed_count = None

    @property
    def failed_num(self):
        """Get the number of failed security checks.
        
        Returns:
            int: The number of failed security checks
        """
        return self.failed_count

    def __call__(self, config: Union[str, Iterator[Any]], **kwargs):
        """Call the vendor's fix method on the given configuration.
        
        Args:
            config (Union[str, Iterator[Any]]): The configuration to fix
            **kwargs: Additional arguments to pass to the fix method
            
        Returns:
            Any: The result of the fix operation
        """
        return self.fix(config, **kwargs)

    def _scan(config):
        """Internal method to scan a configuration.
        
        This method should be implemented by subclasses.
        
        Args:
            config: The configuration to scan
        """
        pass

    def scan(self, config: Union[str, Iterator[Any]]) -> Dict[Any, Any]:
        """Scan a configuration for security issues.
        
        Args:
            config (Union[str, Iterator[Any]]): The configuration to scan,
                can be a file path, string content, or iterator
                
        Returns:
            Dict[Any, Any]: The scan results
        """
        if isinstance(config, str):
            if os.path.exists(config):
                _config = self.read_yaml_from_file(config)
            else:
                _config = self.read_yaml_from_str(config)
            return self._scan(_config)
        return self._scan(config)

    def fix(self, config: Union[str, Iterator[Any]], **kwargs):
        """Fix security issues in a configuration.
        
        This method should be implemented by subclasses.
        
        Args:
            config (Union[str, Iterator[Any]]): The configuration to fix
            **kwargs: Additional arguments for the fix operation
        """
        pass
