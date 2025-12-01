"""Base module for all scanning modules"""

from abc import ABC, abstractmethod
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class BaseModule(ABC):
    """Abstract base class for all scanning modules"""
    
    def __init__(self, tool_manager):
        self.tool_manager = tool_manager
        self.name = self.__class__.__name__
    
    @abstractmethod
    async def scan(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Execute scan - must be implemented by subclasses"""
        pass
    
    def log_info(self, message: str):
        """Log info message"""
        logger.info(f"[{self.name}] {message}")
    
    def log_error(self, message: str):
        """Log error message"""
        logger.error(f"[{self.name}] {message}")
    
    def log_warning(self, message: str):
        """Log warning message"""
        logger.warning(f"[{self.name}] {message}")
