"""Result Manager - Handles structured output and reporting"""

import logging
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
from utils.helpers import save_json, save_list, save_csv, save_text

logger = logging.getLogger(__name__)

class ResultManager:
    """Manages scan results and structured output"""
    
    def __init__(self, output_dir: str, target_name: str):
        self.output_dir = Path(output_dir) / target_name
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Result storage
        self.urls = set()
        self.endpoints = []
        self.parameters = {}
        self.vulnerabilities = []
        self.technologies = {}
        self.subdomains = set()
        self.open_ports = []
        self.api_endpoints = []
        
    def add_urls(self, urls: List[str]):
        """Add discovered URLs"""
        self.urls.update(urls)
        logger.info(f"Added {len(urls)} URLs (total: {len(self.urls)})")
    
    def add_endpoint(self, endpoint: Dict[str, Any]):
        """Add discovered endpoint with details"""
        self.endpoints.append(endpoint)
        
        # Extract parameters
        if "parameters" in endpoint:
            url = endpoint.get("url", "unknown")
            self.parameters[url] = endpoint["parameters"]
    
    def add_api_endpoint(self, api_endpoint: Dict[str, Any]):
        """Add API endpoint"""
        self.api_endpoints.append(api_endpoint)
    
    def add_vulnerability(self, vuln: Dict[str, Any]):
        """Add vulnerability finding"""
        # Ensure required fields
        vuln.setdefault("timestamp", datetime.now().isoformat())
        vuln.setdefault("severity", "MEDIUM")
        
        self.vulnerabilities.append(vuln)
        logger.warning(f"Vulnerability found: {vuln.get('type', 'Unknown')} - {vuln.get('endpoint', 'N/A')}")
    
    def add_subdomain(self, subdomain: str):
        """Add discovered subdomain"""
        self.subdomains.add(subdomain)
    
    def add_port(self, port: str, service: str = None):
        """Add open port"""
        self.open_ports.append({
            "port": port,
            "service": service or "unknown"
        })
    
    def add_technology(self, tech_name: str, details: Any = None):
        """Add detected technology"""
        self.technologies[tech_name] = details
    
    def save_all(self):
        """Save all results to files"""
        logger.info(f"Saving results to {self.output_dir}")
        
        # Save URLs
        if self.urls:
            save_list(
                sorted(self.urls),
                self.output_dir / "urls.txt"
            )
            logger.info(f"Saved {len(self.urls)} URLs")
        
        # Save endpoints with details
        if self.endpoints:
            save_json(
                self.endpoints,
                self.output_dir / "endpoints.json"
            )
            logger.info(f"Saved {len(self.endpoints)} endpoints")
        
        # Save parameters
        if self.parameters:
            save_json(
                self.parameters,
                self.output_dir / "parameters.json"
            )
            logger.info(f"Saved parameters for {len(self.parameters)} endpoints")
        
        # Save API endpoints
        if self.api_endpoints:
            save_json(
                self.api_endpoints,
                self.output_dir / "api_endpoints.json"
            )
            logger.info(f"Saved {len(self.api_endpoints)} API endpoints")
        
        # Save vulnerabilities
        if self.vulnerabilities:
            save_json(
                self.vulnerabilities,
                self.output_dir / "vulnerabilities.json"
            )
            
            # Also save as CSV for easy analysis
            save_csv(
                self.vulnerabilities,
                self.output_dir / "vulnerabilities.csv"
            )
            logger.info(f"Saved {len(self.vulnerabilities)} vulnerabilities")
        
        # Save subdomains
        if self.subdomains:
            save_list(
                sorted(self.subdomains),
                self.output_dir / "subdomains.txt"
            )
            logger.info(f"Saved {len(self.subdomains)} subdomains")
        
        # Save open ports
        if self.open_ports:
            save_json(
                self.open_ports,
                self.output_dir / "ports.json"
            )
            logger.info(f"Saved {len(self.open_ports)} open ports")
        
        # Save technologies
        if self.technologies:
            save_json(
                self.technologies,
                self.output_dir / "technologies.json"
            )
            logger.info(f"Saved {len(self.technologies)} technologies")
        
        # Save summary
        self._save_summary()
    
    def _save_summary(self):
        """Save scan summary"""
        summary = {
            "timestamp": datetime.now().isoformat(),
            "statistics": {
                "urls": len(self.urls),
                "endpoints": len(self.endpoints),
                "api_endpoints": len(self.api_endpoints),
                "parameters": len(self.parameters),
                "subdomains": len(self.subdomains),
                "open_ports": len(self.open_ports),
                "technologies": len(self.technologies),
                "vulnerabilities": {
                    "total": len(self.vulnerabilities),
                    "critical": len([v for v in self.vulnerabilities if v.get("severity") == "CRITICAL"]),
                    "high": len([v for v in self.vulnerabilities if v.get("severity") == "HIGH"]),
                    "medium": len([v for v in self.vulnerabilities if v.get("severity") == "MEDIUM"]),
                    "low": len([v for v in self.vulnerabilities if v.get("severity") == "LOW"])
                }
            },
            "files": {
                "urls": "urls.txt",
                "endpoints": "endpoints.json",
                "parameters": "parameters.json",
                "api_endpoints": "api_endpoints.json",
                "vulnerabilities": "vulnerabilities.json",
                "subdomains": "subdomains.txt",
                "ports": "ports.json",
                "technologies": "technologies.json"
            }
        }
        
        save_json(summary, self.output_dir / "summary.json")
        
        # Also create human-readable summary
        summary_text = f"""
=== SCAN SUMMARY ===
Timestamp: {summary['timestamp']}

DISCOVERY:
- URLs: {summary['statistics']['urls']}
- Endpoints: {summary['statistics']['endpoints']}
- API Endpoints: {summary['statistics']['api_endpoints']}
- Parameters: {summary['statistics']['parameters']}
- Subdomains: {summary['statistics']['subdomains']}
- Open Ports: {summary['statistics']['open_ports']}
- Technologies: {summary['statistics']['technologies']}

VULNERABILITIES:
- Total: {summary['statistics']['vulnerabilities']['total']}
- Critical: {summary['statistics']['vulnerabilities']['critical']}
- High: {summary['statistics']['vulnerabilities']['high']}
- Medium: {summary['statistics']['vulnerabilities']['medium']}
- Low: {summary['statistics']['vulnerabilities']['low']}

OUTPUT FILES:
- URLs: {self.output_dir}/urls.txt
- Endpoints: {self.output_dir}/endpoints.json
- Parameters: {self.output_dir}/parameters.json
- Vulnerabilities: {self.output_dir}/vulnerabilities.json
- Full Summary: {self.output_dir}/summary.json
        """
        
        save_text(summary_text, self.output_dir / "summary.txt")
        logger.info(f"Scan summary saved")
