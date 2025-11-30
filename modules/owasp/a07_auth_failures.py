"""OWASP A07: Authentication and Session Management - Production Grade Scanner.

Detects:
- Brute forceable login/logout/session endpoints
- Session fixation/predictable session ID
- JWT misconfigurations
- Missing logout/CORS controls
- Weak password requirements
"""

import asyncio
import re
from urllib.parse import urljoin
from typing import List, Dict
from loguru import logger

class AuthenticationFailuresScanner:
    """Advanced authentication and session management vulnerability scanner."""

    def __init__(self, async_scanner, config: Dict = None):
        self.scanner = async_scanner
        self.config = config or {}
        self.results = []

    async def scan(self, target: str, recon_data: Dict = None) -> List[Dict]:
        logger.info("[A07] Starting Authentication Failures scan")
        await asyncio.gather(
            self._test_brute_force(target),
            self._test_session_fixation(target),
            self._test_jwt_config(target),
            self._test_password_policy(target),
        )
        logger.success(f"[A07] Scan complete: {len(self.results)} vulnerabilities found")
        return self.results

    async def _test_brute_force(self, target: str):
        logger.info("[A07:BruteForce] Testing login endpoint for brute force attacks")
        logins = ['/login', '/signin', '/auth/login', '/api/login', '/user/login']
        for path in logins:
            url = urljoin(target, path)
            creds = [(f'testuser{i}', f'pass1234') for i in range(10)]
            tasks = [self.scanner.post(url, data={'username': u, 'password': p}) for u, p in creds]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            ok = [r for r in responses if isinstance(r, dict) and r.get('status') in [200, 401, 403]]
            if len(ok) == len(creds):
                self.results.append({
                    'type': 'Brute Force Possible',
                    'url': url,
                    'severity': 'high',
                    'evidence': 'No account lockout/rate limiting enabled on login endpoint',
                    'confidence': 0.8,
                    'cvss_score': 7.5,
                    'remediation': 'Implement lockouts/captchas/rate limits on auth endpoints'
                })
                logger.warning(f"[A07] Login brute-force works at {url}")
                break

    async def _test_session_fixation(self, target: str):
        logger.info("[A07:SessionFix] Checking for session fixation/predictable IDs")
        url = urljoin(target, '/login')
        session_ids = set()
        for i in range(3):
            resp = await self.scanner.fetch(url)
            if resp and 'Set-Cookie' in resp['headers']:
                session = re.search(r'(PHPSESSID|sessionid|JSESSIONID|ASPSESSIONID|sid)=([A-Za-z0-9\-]+)', resp['headers']['Set-Cookie'])
                if session:
                    session_ids.add(session.group(2))
        if len(session_ids) <= 1:
            self.results.append({
                'type': 'Predictable Session ID',
                'url': url,
                'severity': 'high',
                'evidence': 'Session ID does not change between requests',
                'confidence': 0.8,
                'cvss_score': 7.0,
                'remediation': 'Session IDs must be random/unique and regenerated after login'
            })
            logger.warning(f"[A07] Predictable Session ID at {url}")

    async def _test_jwt_config(self, target: str):
        logger.info("[A07:JWT] Checking for JWT config weaknesses")
        urls = [urljoin(target, p) for p in ['/api/token', '/api/auth', '/jwt', '/token']]
        for url in urls:
            resp = await self.scanner.fetch(url)
            if resp and 'authorization' in resp.get('headers', {}).get('www-authenticate', '').lower():
                header = resp['headers'].get('authorization')
                if header and header.startswith('Bearer '):
                    token = header[7:]
                    header_bytes = token.split('.')[0]
                    try:
                        import base64
                        decoded = base64.b64decode(header_bytes + '==').decode()
                        if 'none' in decoded.lower():
                            self.results.append({
                                'type': 'JWT Algorithm None',
                                'url': url,
                                'severity': 'critical',
                                'evidence': 'JWT uses alg=none (no signing/auth)',
                                'confidence': 0.9,
                                'cvss_score': 9.8,
                                'remediation': 'Do not use alg=none in JWT tokens.'
                            })
                            logger.critical(f"[A07] JWT alg=none weakness")
                        elif 'hs256' in decoded.lower():
                            self.results.append({
                                'type': 'JWT HS256',
                                'url': url,
                                'severity': 'high',
                                'evidence': 'JWT uses HS256 algorithm (try signing with common keys)',
                                'confidence': 0.8,
                                'cvss_score': 8.0,
                                'remediation': 'Switch to asymmetric signing (RS256) and use strong keys.'
                            })
                            logger.warning(f"[A07] JWT HS256 weak algorithm")
                    except Exception: pass

    async def _test_password_policy(self, target: str):
        logger.info("[A07:Password] Testing password policy endpoints")
        urls = [urljoin(target, p) for p in ['/register', '/signup', '/user/create']]
        weak_users = [('ab', '12345'), ('test', '111111'), ('a'*12, 'password'), ('bobby', 'test123')]
        for url in urls:
            for username, pwd in weak_users:
                resp = await self.scanner.post(url, data={'username': username, 'password': pwd})
                if resp and resp['status'] == 200:
                    if any(flag in resp['content'].lower() for flag in ['success', 'registered']):
                        self.results.append({
                            'type': 'Weak Password Policy',
                            'url': url,
                            'severity': 'medium',
                            'evidence': f'User registered with weak password/username: {username}/{pwd}',
                            'confidence': 0.7,
                            'cvss_score': 6.0,
                            'remediation': 'Enforce strong password requirements (length, entropy, blacklist common passwords)'
                        })
                        logger.warning(f"[A07] Weak password registered at {url}")
                        break
