"""Web Crawler Module - Content discovery and mapping"""

import asyncio
from typing import Dict, Any, Set
from modules.base_module import BaseModule
import aiohttp
from urllib.parse import urljoin, urlparse
import re

class CrawlerModule(BaseModule):
    """Web crawler and content discovery"""
    
    async def scan(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Execute crawling and content discovery"""
        url = target["url"]
        
        self.log_info(f"Starting content discovery for {url}")
        
        results = {
            "target": url,
            "discovered_paths": [],
            "crawled_urls": [],
            "forms": [],
            "technologies": []
        }
        
        # Try automated tools first
        tool_results = await self._run_discovery_tools(url)
        results.update(tool_results)
        
        # Then do basic crawling
        if len(results["discovered_paths"]) < 10:
            self.log_info("Running basic crawler...")
            crawl_results = await self._basic_crawl(url, max_depth=2)
            results["crawled_urls"] = crawl_results["urls"]
            results["forms"] = crawl_results["forms"]
        
        self.log_info(f"Discovery complete: {len(results['discovered_paths'])} paths found")
        
        return results
    
    async def _run_discovery_tools(self, url: str) -> Dict:
        """Run directory/content discovery tools"""
        results = {
            "discovered_paths": [],
            "tool_outputs": {}
        }
        
        # Try ffuf first (fastest)
        if self.tool_manager.is_tool_available("ffuf"):
            self.log_info("Running ffuf...")
            ffuf_result = await self._run_ffuf(url)
            if not ffuf_result.get("error"):
                results["discovered_paths"].extend(ffuf_result.get("paths", []))
                results["tool_outputs"]["ffuf"] = ffuf_result
        
        # Try feroxbuster (good alternative)
        elif self.tool_manager.is_tool_available("feroxbuster"):
            self.log_info("Running feroxbuster...")
            ferox_result = await self._run_feroxbuster(url)
            if not ferox_result.get("error"):
                results["discovered_paths"].extend(ferox_result.get("paths", []))
                results["tool_outputs"]["feroxbuster"] = ferox_result
        
        # Fallback to gobuster
        elif self.tool_manager.is_tool_available("gobuster"):
            self.log_info("Running gobuster...")
            gobuster_result = await self._run_gobuster(url)
            if not gobuster_result.get("error"):
                results["discovered_paths"].extend(gobuster_result.get("paths", []))
                results["tool_outputs"]["gobuster"] = gobuster_result
        
        # Run nikto for web vulnerabilities
        if self.tool_manager.is_tool_available("nikto"):
            self.log_info("Running nikto...")
            nikto_result = await self._run_nikto(url)
            if not nikto_result.get("error"):
                results["tool_outputs"]["nikto"] = nikto_result
        
        return results
    
    async def _run_ffuf(self, url: str) -> Dict:
        """Run ffuf for directory fuzzing"""
        # Better ffuf configuration
        args = [
            "-mc", "200,204,301,302,307,401,403",  # Match these status codes
            "-fc", "404",  # Filter 404s
            "-t", "50",  # 50 threads
            "-rate", "100",  # 100 requests/sec
            "-timeout", "10",  # 10 second timeout
            "-recursion",  # Enable recursion
            "-recursion-depth", "1",  # Max 1 level deep
            "-se",  # Stop on spurious errors
        ]
        
        result = await self.tool_manager.run_tool("ffuf", url, args)
        
        paths = []
        if result.get("success") and result.get("stdout"):
            # Parse ffuf output
            for line in result["stdout"].split("\n"):
                if " [Status:" in line:
                    # Extract path from line
                    match = re.search(r'(\S+)\s+\[Status:', line)
                    if match:
                        paths.append(match.group(1))
        
        return {"paths": paths, "raw_output": result.get("stdout", "")}
    
    async def _run_feroxbuster(self, url: str) -> Dict:
        """Run feroxbuster"""
        args = [
            "-t", "50",
            "--auto-bail",
            "--smart",
            "-d", "1",  # Depth 1
            "--timeout", "10",
        ]
        
        result = await self.tool_manager.run_tool("feroxbuster", url, args)
        
        paths = []
        if result.get("success") and result.get("stdout"):
            for line in result["stdout"].split("\n"):
                if "200" in line or "301" in line or "302" in line:
                    parts = line.split()
                    if len(parts) > 0:
                        paths.append(parts[-1])
        
        return {"paths": paths, "raw_output": result.get("stdout", "")}
    
    async def _run_gobuster(self, url: str) -> Dict:
        """Run gobuster"""
        args = [
            "-t", "50",
            "-k",  # Skip SSL verification
            "--no-error",
            "--timeout", "10s",
        ]
        
        result = await self.tool_manager.run_tool("gobuster", url, args)
        
        paths = []
        if result.get("success") and result.get("stdout"):
            for line in result["stdout"].split("\n"):
                if " (Status:" in line:
                    parts = line.split()
                    if len(parts) > 0:
                        paths.append(parts[0])
        
        return {"paths": paths, "raw_output": result.get("stdout", "")}
    
    async def _run_nikto(self, url: str) -> Dict:
        """Run nikto scan"""
        result = await self.tool_manager.run_tool("nikto", url, ["-nointeractive"])
        
        return {
            "raw_output": result.get("stdout", ""),
            "vulnerabilities": self._parse_nikto_output(result.get("stdout", ""))
        }
    
    def _parse_nikto_output(self, output: str) -> list:
        """Parse nikto output for vulnerabilities"""
        vulns = []
        for line in output.split("\n"):
            if "+" in line and ("OSVDB" in line or "CVE" in line or "vulnerable" in line.lower()):
                vulns.append(line.strip())
        return vulns
    
    async def _basic_crawl(self, start_url: str, max_depth: int = 2) -> Dict:
        """Basic recursive crawler"""
        visited: Set[str] = set()
        to_visit = [(start_url, 0)]  # (url, depth)
        forms = []
        
        async with aiohttp.ClientSession() as session:
            while to_visit and len(visited) < 50:  # Limit to 50 URLs
                url, depth = to_visit.pop(0)
                
                if url in visited or depth > max_depth:
                    continue
                
                visited.add(url)
                
                try:
                    async with session.get(url, timeout=10, ssl=False) as response:
                        if response.status == 200:
                            html = await response.text()
                            
                            # Find forms
                            form_matches = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
                            for form in form_matches:
                                forms.append({
                                    "url": url,
                                    "form_html": form[:200]  # First 200 chars
                                })
                            
                            # Find links
                            if depth < max_depth:
                                links = re.findall(r'href=["\']([^"\']+)["\']', html)
                                for link in links:
                                    full_url = urljoin(url, link)
                                    parsed = urlparse(full_url)
                                    # Only follow same domain
                                    if parsed.netloc == urlparse(start_url).netloc:
                                        if full_url not in visited:
                                            to_visit.append((full_url, depth + 1))
                except Exception as e:
                    self.log_warning(f"Error crawling {url}: {str(e)}")
        
        return {
            "urls": list(visited),
            "forms": forms
        }
