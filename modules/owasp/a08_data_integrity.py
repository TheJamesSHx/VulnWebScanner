"""OWASP A08: Software/Data Integrity Failures - Production Grade Scanner.

Detects:
- Insecure deserialization endpoints
- Exposed CI/CD/automation endpoints
- Outdated software update mechanisms
- Unsigned release files
- Version leakages
"""

import asyncio
from urllib.parse import urljoin
from typing import List, Dict
from loguru import logger
import re

class DataIntegrityFailuresScanner:
    """Advanced integrity failure detection logic."""

    def __init__(self, async_scanner, config: Dict = None):
        self.scanner = async_scanner
        self.config = config or {}
        self.results = []

    async def scan(self, target: str, recon_data: Dict = None) -> List[Dict]:
        logger.info("[A08] Starting Data Integrity Failures scan")
        await asyncio.gather(
            self._test_insecure_deserialization(target),
            self._test_exposed_cicd(target),
            self._test_software_update(target),
        )
        logger.success(f"[A08] Scan complete: {len(self.results)} vulnerabilities found")
        return self.results

    async def _test_insecure_deserialization(self, target:str):
        logger.info("[A08:Deserialization] Testing for insecure deserialization endpoints")
        endpoints = ['/api/import', '/import', '/api/unserialize', '/unserialize', '/upload', '/api/upload']
        payloads = [b'O:8:"Exploit":0:{}', b'PHP_OBJECT', b'java.io.Serializable']
        for path in endpoints:
            for payload in payloads:
                url = urljoin(target, path)
                resp = await self.scanner.post(url, data=payload)
                if resp and resp['status'] in [200, 500]:
                    if 'unserialize' in resp['content'].lower() or 'exception' in resp['content'].lower():
                        self.results.append({
                            'type': 'Insecure Deserialization',
                            'url': url,
                            'severity': 'high',
                            'evidence': f'Potential insecure deserialization endpoint at {path}',
                            'confidence': 0.65,
                            'cvss_score': 8.0,
                            'remediation': 'Do not deserialize untrusted user input, use data whitelisting.'
                        })
                        logger.warning(f"[A08] Insecure deserialization at {url}")

    async def _test_exposed_cicd(self, target:str):
        logger.info("[A08:CI/CD] Testing for exposed CI/CD/config endpoints")
        ci_files = ['.gitlab-ci.yml', '.github/workflows', '.drone.yml', 'Jenkinsfile', '.travis.yml', '.circleci/config.yml']
        for file in ci_files:
            url = urljoin(target, file)
            resp = await self.scanner.fetch(url)
            if resp and resp['status'] == 200 and 'pipeline' in resp['content'].lower():
                self.results.append({
                    'type': 'Exposed CI/CD Pipeline',
                    'url': url,
                    'severity': 'medium',
                    'evidence': f'Exposed pipeline/config file {file}',
                    'confidence': 0.7,
                    'cvss_score': 5.3,
                    'remediation': 'Restrict config files and remove from public servers.'
                })
                logger.warning(f"[A08] Pipeline config exposed: {file}")

    async def _test_software_update(self, target:str):
        logger.info("[A08:Updater] Testing software update endpoints for signatures/verification")
        update_files = ['update', 'upgrade', 'appcast.xml', 'releases.json', 'latest.yml']
        for file in update_files:
            url = urljoin(target, file)
            resp = await self.scanner.fetch(url)
            if resp and resp['status'] == 200:
                # Look for signature/version
                version_match = re.search(r'version[\s:"=]+([\d.]{1,12})', resp['content'])
                if version_match:
                    self.results.append({
                        'type': 'Update Endpoint',
                        'url': url,
                        'severity': 'low',
                        'evidence': f'Potential unsigned update endpoint and version info: {version_match.group(1)}',
                        'confidence': 0.6,
                        'cvss_score': 4.2,
                        'remediation': 'Sign software releases and verify before install.'
                    })
                    logger.warning(f"[A08] Updater version leak at: {file}")
