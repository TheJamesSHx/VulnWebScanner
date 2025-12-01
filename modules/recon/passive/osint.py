"""OSINT Module - Passive information gathering"""

import asyncio
from typing import Dict, Any
from modules.base_module import BaseModule
from utils.validators import extract_domain

class OSINTModule(BaseModule):
    """Passive OSINT reconnaissance"""
    
    async def scan(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Execute OSINT scan"""
        url = target["url"]
        domain = extract_domain(url)
        
        self.log_info(f"Starting OSINT for {domain}")
        
        results = {
            "domain": domain,
            "subdomains": [],
            "technologies": {},
            "waf_detection": {},
            "ssl_info": {}
        }
        
        # Subdomain enumeration (parallel)
        tasks = []
        
        if self.tool_manager.is_tool_available("subfinder"):
            tasks.append(self._run_subfinder(domain))
        
        if self.tool_manager.is_tool_available("assetfinder"):
            tasks.append(self._run_assetfinder(domain))
        
        if self.tool_manager.is_tool_available("amass"):
            tasks.append(self._run_amass(domain))
        
        # Technology detection
        if self.tool_manager.is_tool_available("whatweb"):
            tasks.append(self._run_whatweb(url))
        
        # WAF detection
        if self.tool_manager.is_tool_available("wafw00f"):
            tasks.append(self._run_wafw00f(url))
        
        # SSL/TLS analysis
        if self.tool_manager.is_tool_available("testssl"):
            tasks.append(self._run_testssl(url))
        elif self.tool_manager.is_tool_available("sslscan"):
            tasks.append(self._run_sslscan(domain))
        
        if tasks:
            scan_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in scan_results:
                if isinstance(result, dict) and not result.get("error"):
                    if "subdomains" in result:
                        results["subdomains"].extend(result["subdomains"])
                    if "technologies" in result:
                        results["technologies"].update(result["technologies"])
                    if "waf" in result:
                        results["waf_detection"] = result["waf"]
                    if "ssl" in result:
                        results["ssl_info"] = result["ssl"]
        
        # Remove duplicates from subdomains
        results["subdomains"] = list(set(results["subdomains"]))
        
        self.log_info(f"OSINT complete: {len(results['subdomains'])} subdomains found")
        
        return results
    
    async def _run_subfinder(self, domain: str) -> Dict:
        """Run subfinder for subdomain enumeration"""
        self.log_info("Running subfinder...")
        result = await self.tool_manager.run_tool("subfinder", domain, ["-silent"])
        
        subdomains = []
        if result.get("success") and result.get("stdout"):
            subdomains = [line.strip() for line in result["stdout"].split("\n") if line.strip()]
        
        return {"subdomains": subdomains}
    
    async def _run_assetfinder(self, domain: str) -> Dict:
        """Run assetfinder"""
        self.log_info("Running assetfinder...")
        result = await self.tool_manager.run_tool("assetfinder", domain)
        
        subdomains = []
        if result.get("success") and result.get("stdout"):
            subdomains = [line.strip() for line in result["stdout"].split("\n") if line.strip()]
        
        return {"subdomains": subdomains}
    
    async def _run_amass(self, domain: str) -> Dict:
        """Run amass passive enumeration"""
        self.log_info("Running amass...")
        result = await self.tool_manager.run_tool("amass", domain, ["-d", domain])
        
        subdomains = []
        if result.get("success") and result.get("stdout"):
            subdomains = [line.strip() for line in result["stdout"].split("\n") if line.strip()]
        
        return {"subdomains": subdomains}
    
    async def _run_whatweb(self, url: str) -> Dict:
        """Run whatweb for technology detection"""
        self.log_info("Running whatweb...")
        result = await self.tool_manager.run_tool("whatweb", url, ["-v"])
        
        technologies = {}
        if result.get("success") and result.get("stdout"):
            # Parse whatweb output
            output = result["stdout"]
            technologies["raw"] = output
        
        return {"technologies": technologies}
    
    async def _run_wafw00f(self, url: str) -> Dict:
        """Run wafw00f for WAF detection"""
        self.log_info("Running wafw00f...")
        result = await self.tool_manager.run_tool("wafw00f", url)
        
        waf_info = {"detected": False, "name": None}
        if result.get("success") and result.get("stdout"):
            output = result["stdout"].lower()
            if "is behind" in output or "detected" in output:
                waf_info["detected"] = True
                waf_info["raw"] = result["stdout"]
        
        return {"waf": waf_info}
    
    async def _run_testssl(self, url: str) -> Dict:
        """Run testssl.sh"""
        self.log_info("Running testssl...")
        result = await self.tool_manager.run_tool("testssl", url)
        
        ssl_info = {}
        if result.get("success") and result.get("stdout"):
            ssl_info["raw"] = result["stdout"]
            # Parse for vulnerabilities
            output = result["stdout"].lower()
            ssl_info["vulnerable"] = "vulnerable" in output
        
        return {"ssl": ssl_info}
    
    async def _run_sslscan(self, domain: str) -> Dict:
        """Run sslscan as fallback"""
        self.log_info("Running sslscan...")
        result = await self.tool_manager.run_tool("sslscan", domain)
        
        ssl_info = {}
        if result.get("success") and result.get("stdout"):
            ssl_info["raw"] = result["stdout"]
        
        return {"ssl": ssl_info}
