"""OWASP A09: Logging & Monitoring Failures - Production Grade Scanner.

Detects:
- Log injection
- Sensitive data in logs
- Absence of logging endpoints/messages
"""
import asyncio
from urllib.parse import urljoin
from typing import List, Dict
from loguru import logger
import re
class LoggingFailuresScanner:
    """Advanced logging and monitoring failures scanner."""
    def __init__(self, async_scanner, config: Dict = None):
        self.scanner = async_scanner
        self.config = config or {}
        self.results = []
    async def scan(self, target: str, recon_data: Dict = None) -> List[Dict]:
        logger.info("[A09] Starting Logging & Monitoring Failures scan")
        await asyncio.gather(
            self._test_log_injection(target),
            self._test_sensitive_log_leak(target),
            self._test_logging_mechanism(target),
        )
        logger.success(f"[A09] Scan complete: {len(self.results)} vulnerabilities found")
        return self.results
    async def _test_log_injection(self, target:str):
        logger.info("[A09:LogInjection] Testing for log injection endpoints")
        payload = "test\nLOGFAIL:INJECTED:%s" % id(self)
        endpoints = [urljoin(target, e) for e in ['/login','/search','/feedback','/api/contact','/user/profile','/admin']]  
        for url in endpoints:
            resp = await self.scanner.post(url, data={'username': payload, 'message': payload})
            if resp and resp['status'] == 200:
                # TODO: Real world: check log files if accessible, here warn of endpoints that may be vulnerable
                if payload in resp['content']:
                    self.results.append({
                        'type': 'Log Injection',
                        'url': url,
                        'severity': 'medium',
                        'evidence': 'Application outputted log injection string, may be vulnerable.',
                        'confidence': 0.5,
                        'cvss_score': 3.8,
                        'remediation': 'Sanitize all user input before logging.'
                    })
                    logger.warning(f"[A09] Log injection reflected at {url}")
    async def _test_sensitive_log_leak(self, target:str):
        logger.info("[A09:LogLeak] Testing for sensitive data exposure in logs/pages")
        log_files = ['app.log','debug.log','error.log','access.log','events.log','logs/latest.log','logs/errors.log']
        for file in log_files:
            url = urljoin(target, file)
            resp = await self.scanner.fetch(url)
            if resp and resp['status'] == 200:
                indicators = ['password','api_key','token','auth','user','session','cookie']
                for i in indicators:
                    if i in resp['content'].lower():
                        self.results.append({
                            'type': 'Sensitive Data in Logs',
                            'url': url,
                            'severity': 'high',
                            'evidence': f'Log file exposes sensitive data: {i}',
                            'confidence': 0.8,
                            'cvss_score': 7.6,
                            'remediation': 'Rotate logs, mask sensitive fields, restrict access.'
                        })
                        logger.critical(f"[A09] Sensitive log data in {file}")
                        break
    async def _test_logging_mechanism(self, target:str):
        logger.info("[A09:Mechanism] Testing for lack of logging mechanism")
        resp = await self.scanner.fetch(target)
        if resp and "log" not in resp['content'].lower():
            self.results.append({
                'type': 'No Logging Mechanism Detected',
                'url': target,
                'severity': 'low',
                'evidence': 'No logging messages visible, review required.',
                'confidence': 0.3,
                'cvss_score': 1.8,
                'remediation': 'Implement, monitor, and review logs for sensitive activities.'
            })
            logger.info(f"[A09] No logging detected for {target}")
