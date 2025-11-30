"""OWASP A04: Insecure Design - Production Grade Scanner.

Detects:
- Business logic flaws
- Insufficient rate limiting
- 2FA/MFA bypass
- Authentication flow vulnerabilities
- Account enumeration
- Password reset flaws
"""

import asyncio
import re
import time
from typing import List, Dict
from loguru import logger


class InsecureDesignScanner:
    """Advanced insecure design vulnerability scanner."""

    def __init__(self, async_scanner, config: Dict = None):
        self.scanner = async_scanner
        self.config = config or {}
        self.results = []

    async def scan(self, target: str, recon_data: Dict = None) -> List[Dict]:
        """Comprehensive insecure design scan.
        
        Args:
            target: Target URL
            recon_data: Reconnaissance data
            
        Returns:
            List of vulnerability findings
        """
        logger.info("[A04] Starting Insecure Design scan")
        
        await asyncio.gather(
            self._test_rate_limiting(target),
            self._test_account_enumeration(target),
            self._test_2fa_bypass(target),
            self._test_password_reset_flaws(target),
            self._test_business_logic(target, recon_data)
        )
        
        logger.success(f"[A04] Scan complete: {len(self.results)} vulnerabilities found")
        return self.results

    async def _test_rate_limiting(self, target: str):
        """Test for missing or insufficient rate limiting."""
        logger.info("[A04:RateLimit] Testing rate limiting")
        
        # Common endpoints to test
        test_endpoints = [
            '/login',
            '/api/login',
            '/auth/login',
            '/signin',
            '/api/v1/auth',
            '/password-reset',
            '/forgot-password',
            '/register',
            '/api/register'
        ]
        
        from urllib.parse import urljoin
        
        for endpoint in test_endpoints:
            test_url = urljoin(target, endpoint)
            
            # Send multiple rapid requests
            request_count = 25
            start_time = time.time()
            
            tasks = [self.scanner.post(test_url, data={'username': f'test{i}', 'password': 'test'}) 
                    for i in range(request_count)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            elapsed = time.time() - start_time
            
            # Check if all requests succeeded
            successful = sum(1 for r in responses if isinstance(r, dict) and r.get('status') in [200, 401, 403])
            
            if successful >= request_count * 0.8:  # 80% success rate
                self.results.append({
                    'type': 'Missing Rate Limiting',
                    'url': test_url,
                    'severity': 'high',
                    'evidence': f'{successful}/{request_count} requests succeeded in {elapsed:.2f}s without rate limiting',
                    'confidence': 0.85,
                    'cvss_score': 7.5,
                    'remediation': 'Implement rate limiting (e.g., 5 attempts per minute per IP)'
                })
                logger.warning(f"[RateLimit] No rate limiting on {endpoint}")
                break  # Found one, skip others

    async def _test_account_enumeration(self, target: str):
        """Test for account enumeration vulnerabilities."""
        logger.info("[A04:Enumeration] Testing account enumeration")
        
        from urllib.parse import urljoin
        
        test_endpoints = [
            '/login',
            '/forgot-password',
            '/password-reset',
            '/register',
            '/api/users/check'
        ]
        
        for endpoint in test_endpoints:
            test_url = urljoin(target, endpoint)
            
            # Test with existing vs non-existing user
            common_usernames = ['admin', 'administrator', 'root', 'test']
            random_username = 'nonexistentuser9999xyz'
            
            responses_existing = []
            for username in common_usernames:
                resp = await self.scanner.post(test_url, data={'username': username, 'password': 'wrongpassword'})
                if resp:
                    responses_existing.append(resp)
            
            resp_nonexistent = await self.scanner.post(test_url, data={'username': random_username, 'password': 'wrongpassword'})
            
            if responses_existing and resp_nonexistent:
                # Check for differences in responses
                for resp_exist in responses_existing:
                    if self._responses_differ(resp_exist, resp_nonexistent):
                        self.results.append({
                            'type': 'Account Enumeration',
                            'url': test_url,
                            'severity': 'medium',
                            'evidence': 'Different responses for existing vs non-existing users allow enumeration',
                            'confidence': 0.80,
                            'cvss_score': 5.3,
                            'remediation': 'Use generic error messages for all authentication failures'
                        })
                        logger.warning(f"[Enumeration] Account enumeration possible at {endpoint}")
                        break

    def _responses_differ(self, resp1: Dict, resp2: Dict) -> bool:
        """Check if two responses differ significantly."""
        if resp1['status'] != resp2['status']:
            return True
        
        # Check response time difference (timing attack)
        time_diff = abs(resp1.get('elapsed', 0) - resp2.get('elapsed', 0))
        if time_diff > 0.5:  # 500ms difference
            return True
        
        # Check content length difference
        len_diff = abs(resp1.get('length', 0) - resp2.get('length', 0))
        if len_diff > 50:  # Significant content difference
            return True
        
        # Check for specific error messages
        error_indicators_exist = ['user not found', 'invalid username', 'account does not exist']
        error_indicators_wrong = ['incorrect password', 'wrong password', 'invalid credentials']
        
        content1_lower = resp1.get('content', '').lower()
        content2_lower = resp2.get('content', '').lower()
        
        for indicator in error_indicators_exist:
            if indicator in content1_lower or indicator in content2_lower:
                if indicator in content1_lower and indicator not in content2_lower:
                    return True
                if indicator not in content1_lower and indicator in content2_lower:
                    return True
        
        return False

    async def _test_2fa_bypass(self, target: str):
        """Test for 2FA/MFA bypass vulnerabilities."""
        logger.info("[A04:2FA] Testing 2FA bypass techniques")
        
        from urllib.parse import urljoin
        
        # Common 2FA endpoints
        mfa_endpoints = [
            '/2fa/verify',
            '/mfa/verify',
            '/verify-otp',
            '/verify-code',
            '/api/2fa/verify'
        ]
        
        for endpoint in mfa_endpoints:
            test_url = urljoin(target, endpoint)
            
            # Test 1: Direct access bypass
            response = await self.scanner.fetch(test_url)
            if response and response['status'] == 302:
                # Check if redirects to authenticated area
                location = response['headers'].get('Location', '')
                if 'dashboard' in location.lower() or 'home' in location.lower():
                    self.results.append({
                        'type': '2FA Bypass',
                        'url': test_url,
                        'severity': 'critical',
                        'evidence': '2FA can be bypassed by directly accessing post-authentication URL',
                        'confidence': 0.70,
                        'cvss_score': 8.1,
                        'remediation': 'Enforce 2FA verification on server-side for all protected resources'
                    })
                    logger.critical(f"[2FA] Direct access bypass found at {endpoint}")
            
            # Test 2: Brute force OTP (0000-9999 for 4-digit codes)
            # Limited testing to avoid lockout
            common_otps = ['000000', '111111', '123456', '000000', '999999', '012345']
            for otp in common_otps:
                resp = await self.scanner.post(test_url, data={'otp': otp, 'code': otp, 'token': otp})
                if resp and resp['status'] in [200, 302]:
                    # Check if we got authenticated
                    if 'success' in resp['content'].lower() or 'dashboard' in resp.get('headers', {}).get('Location', '').lower():
                        self.results.append({
                            'type': '2FA Weak OTP',
                            'url': test_url,
                            'severity': 'high',
                            'evidence': f'Weak/predictable OTP accepted: {otp}',
                            'confidence': 0.65,
                            'cvss_score': 7.5,
                            'remediation': 'Use cryptographically secure random OTP generation'
                        })
                        logger.warning(f"[2FA] Weak OTP found: {otp}")
                        break

    async def _test_password_reset_flaws(self, target: str):
        """Test for password reset vulnerabilities."""
        logger.info("[A04:PwdReset] Testing password reset flaws")
        
        from urllib.parse import urljoin
        
        reset_endpoints = [
            '/reset-password',
            '/password-reset',
            '/forgot-password',
            '/api/password/reset'
        ]
        
        for endpoint in reset_endpoints:
            test_url = urljoin(target, endpoint)
            
            # Test 1: Token in URL (GET request)
            test_tokens = ['123456', 'token123', 'abcdef']
            for token in test_tokens:
                resp = await self.scanner.fetch(f"{test_url}?token={token}")
                if resp and resp['status'] == 200:
                    # Check if password reset form is displayed
                    if 'new password' in resp['content'].lower() or 'reset password' in resp['content'].lower():
                        self.results.append({
                            'type': 'Weak Password Reset Token',
                            'url': test_url,
                            'severity': 'high',
                            'evidence': 'Password reset accepts weak/predictable tokens',
                            'confidence': 0.60,
                            'cvss_score': 7.5,
                            'remediation': 'Use cryptographically strong random tokens with expiration'
                        })
                        logger.warning(f"[PwdReset] Weak token accepted at {endpoint}")
                        break
            
            # Test 2: Mass password reset (no rate limiting)
            emails = [f'test{i}@example.com' for i in range(10)]
            tasks = [self.scanner.post(test_url, data={'email': email}) for email in emails]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            successful = sum(1 for r in responses if isinstance(r, dict) and r.get('status') == 200)
            if successful >= 8:  # 80% success
                self.results.append({
                    'type': 'Password Reset Abuse',
                    'url': test_url,
                    'severity': 'medium',
                    'evidence': 'No rate limiting on password reset allows mass email flooding',
                    'confidence': 0.75,
                    'cvss_score': 5.3,
                    'remediation': 'Implement rate limiting on password reset requests'
                })
                logger.warning(f"[PwdReset] No rate limiting on password reset")

    async def _test_business_logic(self, target: str, recon_data: Dict = None):
        """Test for business logic vulnerabilities."""
        logger.info("[A04:BizLogic] Testing business logic flaws")
        
        from urllib.parse import urljoin, urlparse, parse_qs
        
        # Test negative values in price/quantity fields
        urls = [target]
        if recon_data and 'urls' in recon_data:
            urls.extend([u for u in recon_data['urls'] if any(k in u.lower() for k in ['cart', 'checkout', 'order', 'payment', 'price'])][:10])
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Look for price/quantity parameters
            for param in params:
                if any(keyword in param.lower() for keyword in ['price', 'amount', 'quantity', 'total', 'cost']):
                    # Test negative values
                    negative_payloads = ['-1', '-100', '0', '-999999']
                    for payload in negative_payloads:
                        test_url = self._replace_param(url, param, payload)
                        resp = await self.scanner.fetch(test_url)
                        
                        if resp and resp['status'] == 200:
                            # Check if negative value is accepted
                            if payload in resp['content'] or 'success' in resp['content'].lower():
                                self.results.append({
                                    'type': 'Business Logic Flaw',
                                    'url': test_url,
                                    'parameter': param,
                                    'severity': 'high',
                                    'evidence': f'Negative value accepted in {param}: {payload}',
                                    'confidence': 0.70,
                                    'cvss_score': 7.5,
                                    'payload': payload,
                                    'remediation': 'Implement server-side validation for all business logic parameters'
                                })
                                logger.warning(f"[BizLogic] Negative value accepted: {param}={payload}")
                                break

    def _replace_param(self, url: str, param: str, value: str) -> str:
        """Replace parameter value in URL."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))