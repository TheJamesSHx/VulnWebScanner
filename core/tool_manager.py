"""Tool Manager - Manages execution of external security tools"""

import asyncio
import logging
import shutil
from pathlib import Path
from typing import Dict, Optional, List
import subprocess
import json

logger = logging.getLogger(__name__)

class ToolManager:
    """Manages external pentesting tools"""
    
    def __init__(self, config: Dict):
        self.config = config.get("tools", {})
        self.settings = config.get("settings", {})
        self._validate_tools()
    
    def _validate_tools(self):
        """Validate that configured tools are available"""
        for tool_name, tool_config in self.config.items():
            if not tool_config.get("enabled", False):
                continue
            
            tool_path = tool_config.get("path")
            if tool_path and not Path(tool_path).exists():
                if not shutil.which(tool_name):
                    logger.warning(f"Tool not found: {tool_name} at {tool_path}")
                    tool_config["enabled"] = False
                else:
                    logger.info(f"Tool {tool_name} found in PATH")
    
    async def run_tool(self, tool_name: str, target: str, 
                       additional_args: List[str] = None) -> Dict:
        """Execute an external tool asynchronously"""
        if tool_name not in self.config:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        tool_config = self.config[tool_name]
        if not tool_config.get("enabled", False):
            logger.warning(f"Tool {tool_name} is disabled")
            return {"error": "Tool disabled", "tool": tool_name}
        
        # Build command
        cmd = self._build_command(tool_name, tool_config, target, additional_args)
        
        logger.info(f"Executing: {' '.join(cmd)}")
        
        try:
            # Run tool with timeout
            timeout = tool_config.get("timeout", 300)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )
            
            return {
                "tool": tool_name,
                "success": proc.returncode == 0,
                "return_code": proc.returncode,
                "stdout": stdout.decode('utf-8', errors='ignore'),
                "stderr": stderr.decode('utf-8', errors='ignore'),
                "command": ' '.join(cmd)
            }
            
        except asyncio.TimeoutError:
            logger.error(f"Tool {tool_name} timed out")
            return {
                "tool": tool_name,
                "error": "Timeout",
                "timeout": timeout
            }
        except Exception as e:
            logger.error(f"Tool {tool_name} execution failed: {str(e)}")
            return {
                "tool": tool_name,
                "error": str(e)
            }
    
    def _build_command(self, tool_name: str, tool_config: Dict, 
                       target: str, additional_args: List[str] = None) -> List[str]:
        """Build command line for tool execution"""
        cmd = [tool_config["path"]]
        
        # Add configured arguments
        if "args" in tool_config:
            cmd.extend(tool_config["args"].split())
        
        # Add tool-specific options
        if "wordlist" in tool_config:
            cmd.extend(["-w", tool_config["wordlist"]])
        
        if "templates" in tool_config:
            cmd.extend(["-t", tool_config["templates"]])
        
        # Add additional arguments
        if additional_args:
            cmd.extend(additional_args)
        
        # Add target (URL or file)
        if tool_name in ["nmap", "masscan"]:
            # For network scanners, target might be IP/domain
            cmd.append(target)
        elif tool_name in ["nuclei", "nikto", "sqlmap", "xsstrike"]:
            cmd.extend(["-u", target])
        elif tool_name == "ffuf":
            cmd.extend(["-u", f"{target}/FUZZ"])
        elif tool_name == "gobuster":
            cmd.extend(["-u", target])
        else:
            cmd.append(target)
        
        return cmd
    
    async def run_parallel(self, tools: List[str], target: str, 
                          max_concurrent: int = 3) -> Dict[str, Dict]:
        """Run multiple tools in parallel with concurrency limit"""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def run_with_semaphore(tool_name: str):
            async with semaphore:
                return await self.run_tool(tool_name, target)
        
        tasks = [run_with_semaphore(tool) for tool in tools]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            tool: result if not isinstance(result, Exception) else {"error": str(result)}
            for tool, result in zip(tools, results)
        }
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available and enabled"""
        return (
            tool_name in self.config and 
            self.config[tool_name].get("enabled", False)
        )
