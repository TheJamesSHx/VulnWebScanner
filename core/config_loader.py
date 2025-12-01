"""Configuration Loader - Loads and validates YAML configurations"""

import yaml
import os
import logging
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class ConfigLoader:
    """Load and validate configuration files"""
    
    def __init__(self):
        self.env_vars = os.environ
    
    def load_targets(self, config_path: str) -> List[Dict[str, Any]]:
        """Load target configuration from YAML file"""
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        
        with open(path, 'r') as f:
            config = yaml.safe_load(f)
        
        targets = config.get("targets", [])
        
        # Substitute environment variables
        targets = self._substitute_env_vars(targets)
        
        # Validate targets
        validated = []
        for target in targets:
            if self._validate_target(target):
                validated.append(target)
            else:
                logger.warning(f"Invalid target configuration: {target.get('name', 'unknown')}")
        
        return validated
    
    def load_tools_config(self, config_path: str) -> Dict[str, Any]:
        """Load tools configuration from YAML file"""
        path = Path(config_path)
        if not path.exists():
            logger.warning(f"Tools config not found: {config_path}, using defaults")
            return {}
        
        with open(path, 'r') as f:
            config = yaml.safe_load(f)
        
        return config
    
    def _substitute_env_vars(self, config: Any) -> Any:
        """Recursively substitute ${VAR} with environment variables"""
        if isinstance(config, dict):
            return {
                key: self._substitute_env_vars(value)
                for key, value in config.items()
            }
        elif isinstance(config, list):
            return [self._substitute_env_vars(item) for item in config]
        elif isinstance(config, str) and config.startswith("${") and config.endswith("}"):
            var_name = config[2:-1]
            return self.env_vars.get(var_name, config)
        else:
            return config
    
    def _validate_target(self, target: Dict) -> bool:
        """Validate target configuration"""
        required_fields = ["url"]
        
        for field in required_fields:
            if field not in target:
                logger.error(f"Missing required field: {field} in target")
                return False
        
        # Validate URL format
        url = target["url"]
        if not url.startswith(("http://", "https://")):
            logger.error(f"Invalid URL format: {url}")
            return False
        
        return True
