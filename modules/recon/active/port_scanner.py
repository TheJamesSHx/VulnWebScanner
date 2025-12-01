"""Port Scanner Module - Active network reconnaissance"""

import asyncio
from typing import Dict, Any
from modules.base_module import BaseModule
from utils.validators import extract_domain
import socket

class PortScannerModule(BaseModule):
    """Active port scanning and service detection"""
    
    async def scan(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Execute port scanning"""
        url = target["url"]
        domain = extract_domain(url)
        
        self.log_info(f"Starting port scan for {domain}")
        
        results = {
            "target": domain,
            "nmap_scan": {},
            "quick_scan": {},
            "services": []
        }
        
        # Try nmap first (most comprehensive)
        if self.tool_manager.is_tool_available("nmap"):
            nmap_result = await self._run_nmap(domain)
            if not nmap_result.get("error"):
                results["nmap_scan"] = nmap_result
                self.log_info("Nmap scan completed")
            else:
                self.log_warning(f"Nmap failed: {nmap_result.get('error')}")
                # Fallback to quick scan
                results["quick_scan"] = await self._quick_port_scan(domain)
        else:
            # Nmap not available, use quick scan
            self.log_info("Nmap not available, using quick scan")
            results["quick_scan"] = await self._quick_port_scan(domain)
        
        return results
    
    async def _run_nmap(self, target: str) -> Dict:
        """Run nmap scan with proper configuration"""
        self.log_info("Running nmap scan...")
        
        # Use more reliable nmap args for web targets
        nmap_args = [
            "-Pn",  # Skip ping (treat host as online)
            "-sV",  # Service version detection
            "-sC",  # Run default scripts
            "-p-",  # All ports (or use -p 80,443,8000,8080,8443 for web only)
            "--open",  # Only show open ports
            "-T4",  # Timing template (faster)
            "--min-rate", "1000",  # Minimum packets per second
        ]
        
        result = await self.tool_manager.run_tool("nmap", target, nmap_args)
        
        if result.get("success"):
            return self._parse_nmap_output(result.get("stdout", ""))
        else:
            return {"error": result.get("error", "Nmap scan failed")}
    
    def _parse_nmap_output(self, output: str) -> Dict:
        """Parse nmap output"""
        parsed = {
            "raw_output": output,
            "open_ports": [],
            "services": {}
        }
        
        if not output:
            return parsed
        
        lines = output.split("\n")
        for line in lines:
            line = line.strip()
            # Parse port lines (e.g., "80/tcp open http")
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split("/")[0]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    parsed["open_ports"].append(port)
                    parsed["services"][port] = service
        
        return parsed
    
    async def _quick_port_scan(self, target: str) -> Dict:
        """Quick port scan using Python sockets"""
        self.log_info("Running quick port scan...")
        
        # Common web ports
        common_ports = [80, 443, 8000, 8080, 8443, 8888, 3000, 5000]
        
        open_ports = []
        
        async def check_port(port: int):
            try:
                # Resolve hostname to IP
                ip = await asyncio.to_thread(socket.gethostbyname, target)
                
                # Try to connect
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=2
                )
                writer.close()
                await writer.wait_closed()
                return port
            except Exception:
                return None
        
        tasks = [check_port(port) for port in common_ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = [port for port in results if port is not None]
        
        self.log_info(f"Quick scan found {len(open_ports)} open ports")
        
        return {
            "scanned_ports": common_ports,
            "open_ports": open_ports,
            "method": "socket"
        }
