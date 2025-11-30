"""OWASP A06: Vulnerable and Outdated Components - Production Grade Scanner.

Detects:
- Outdated libraries/frameworks/CMS (based on known patterns)
- Known vulnerabilities (CVE database lookup)
- Insecure dependencies and plugins
- Client-side and server-side package leak
"""

import asyncio
import re
import requests
from typing import List, Dict
from urllib.parse import urljoin
from loguru import logger

class VulnerableComponentsScanner:
    """Advanced vulnerable component discovery and CVE lookup."""

    def __init__(self, async_scanner, config: Dict = None):
        self.scanner = async_scanner
        self.config = config or {}
        self.results = []
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="

    async def scan(self, target: str, recon_data: Dict = None) -> List[Dict]:
        logger.info("[A06] Starting Vulnerable Components scan")
        await asyncio.gather(
            self._detect_cms_versions(target, recon_data),
            self._detect_js_libraries(target, recon_data),
            self._exposed_pkg_files(target),
        )
        logger.success(f"[A06] Scan complete: {len(self.results)} vulnerabilities found")
        return self.results

    async def _detect_cms_versions(self, target: str, recon_data: Dict = None):
        """Detect CMS/framework version leaks and check for CVEs."""
        if recon_data and 'technologies' in recon_data:
            for tech in recon_data['technologies']:
                name = tech['name']
                match = re.search(r'(\d+\.[\d.]+)', str(tech.get('matches')))
                if match:
                    version = match.group(1)
                    cves = self._search_cves(f"{name} {version}")
                    if cves:
                        self.results.append({
                            'type': 'Outdated CMS/Framework',
                            'url': target,
                            'component': name,
                            'version': version,
                            'severity': 'high',
                            'evidence': f"{name} {version} vulnerable: {', '.join(cves[:3])}",
                            'confidence': 0.8,
                            'cvss_score': 7.9,
                            'remediation': f"Update {name} to latest stable version"
                        })
                        logger.warning(f"[A06] Outdated {name} detected: v{version}")

    async def _detect_js_libraries(self, target: str, recon_data: Dict = None):
        """Detect outdated JS libraries from script tags and compare to known issues."""
        response = await self.scanner.fetch(target)
        if not response or 'content' not in response:
            return
        js_libs = re.findall(r'<script[^>]+src=["\']?([^"\'>]+)["\']?', response['content'])
        for src in js_libs:
            match = re.search(r'(jquery|react|angular|vue|bootstrap)[.\-]?(\d+\.\d+(?:\.\d+)?)', src, re.IGNORECASE)
            if match:
                lib, version = match.group(1), match.group(2)
                cves = self._search_cves(f"{lib} {version}")
                if cves:
                    self.results.append({
                        'type': 'Outdated JS Library',
                        'url': urljoin(target, src),
                        'component': lib,
                        'version': version,
                        'severity': 'medium',
                        'evidence': f"{lib} {version} vulnerable: {', '.join(cves[:3])}",
                        'confidence': 0.7,
                        'cvss_score': 6.5,
                        'remediation': f"Update {lib} to latest version"
                    })

    async def _exposed_pkg_files(self, target: str):
        pkg_files = ['package.json', 'composer.json', 'Gemfile', 'pyproject.toml', 'requirements.txt', 'yarn.lock', 'go.mod']
        for file in pkg_files:
            url = urljoin(target, file)
            response = await self.scanner.fetch(url)
            if response and response['status'] == 200 and 'content' in response:
                found = re.findall(r'([a-zA-Z][a-zA-Z0-9_-]+)[\s:"=]+([\d.]{1,12})', response['content'])
                for dep, ver in found[:5]:
                    cves = self._search_cves(f"{dep} {ver}")
                    if cves:
                        self.results.append({
                            'type': 'Outdated Dependency',
                            'url': url,
                            'component': dep,
                            'version': ver,
                            'severity': 'medium',
                            'evidence': f"{dep} {ver} vulnerable: {', '.join(cves[:3])}",
                            'confidence': 0.6,
                            'cvss_score': 6.1,
                            'remediation': f"Update {dep} to a patched version"
                        })

    def _search_cves(self, keyword: str) -> List[str]:
        """Query NVD for CVEs by keyword."""
        try:
            r = requests.get(f"{self.nvd_api_url}{keyword}", timeout=10)
            if r.status_code != 200:
                return []
            data = r.json()
            cves = []
            for cve_obj in data.get('vulnerabilities') or []:
                cve = cve_obj.get('cve', {}).get('id', '')
                if cve:
                    cves.append(cve)
            return cves
        except Exception as e:
            logger.debug(f"CVE lookup error for '{keyword}': {str(e)}")
            return []
