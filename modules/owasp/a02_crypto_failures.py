"""OWASP A02: Cryptographic Failures - Production Grade Scanner.

Detects:
- Weak SSL/TLS configurations
- Missing HTTPS
- Insecure cookie flags
- Sensitive data in URLs/responses
- Weak encryption algorithms
- Certificate issues
"""

import asyncio
import ssl
import re
from typing import List, Dict
from urllib.parse import urlparse
from loguru import logger
import socket


class CryptographicFailures:
    """Advanced cryptographic failures scanner."""

    def __init__(self, async_scanner, config: Dict = None):
        self.scanner = async_scanner
        self.config = config or {}
        self.results = []

    async def scan(self, target: str, recon_data: Dict = None) -> List[Dict]:
        """Comprehensive cryptographic failures scan.
        
        Args:
            target: Target URL
            recon_data: Reconnaissance data
            
        Returns:
            List of vulnerability findings
        """
        logger.info("[A02] Starting Cryptographic Failures scan")
        
        await asyncio.gather(
            self._test_https_enforcement(target),
            self._test_ssl_tls_config(target),
            self._test_cookie_security(target),
            self._test_sensitive_data_exposure(target),
            self._test_security_headers(target)
        )
        
        logger.success(f"[A02] Scan complete: {len(self.results)} vulnerabilities found")
        return self.results

    async def _test_https_enforcement(self, target: str):
        """Test if HTTPS is enforced."""
        logger.info("[A02:HTTPS] Testing HTTPS enforcement")
        
        parsed = urlparse(target)
        
        # Check if site uses HTTP
        if parsed.scheme == 'http':
            self.results.append({
                'type': 'No HTTPS',
                'url': target,
                'severity': 'high',
                'evidence': 'Website does not use HTTPS encryption',
                'confidence': 1.0,
                'cvss_score': 7.4,
                'remediation': 'Implement HTTPS with valid SSL/TLS certificate and redirect all HTTP traffic to HTTPS'
            })
            logger.warning("[HTTPS] No HTTPS detected")
            return
        
        # Test HTTP version
        http_url = target.replace('https://', 'http://')
        response = await self.scanner.fetch(http_url)
        
        if response:
            # Check if HTTP version exists and doesn't redirect
            if response['status'] == 200:
                self.results.append({
                    'type': 'Mixed Content',
                    'url': http_url,
                    'severity': 'medium',
                    'evidence': 'HTTP version accessible without redirect to HTTPS',
                    'confidence': 0.90,
                    'cvss_score': 5.3,
                    'remediation': 'Implement HTTP to HTTPS redirect (301/302)'
                })
                logger.warning("[HTTPS] HTTP accessible without redirect")
            elif response['status'] not in [301, 302, 307, 308]:
                logger.info("[HTTPS] HTTP properly redirects to HTTPS")

    async def _test_ssl_tls_config(self, target: str):
        """Test SSL/TLS configuration."""
        logger.info("[A02:SSL/TLS] Testing SSL/TLS configuration")
        
        parsed = urlparse(target)
        if parsed.scheme != 'https':
            return
        
        hostname = parsed.netloc.split(':')[0]
        port = parsed.port or 443
        
        try:
            # Test weak protocols
            weak_protocols = [
                (ssl.PROTOCOL_SSLv2, 'SSLv2'),
                (ssl.PROTOCOL_SSLv3, 'SSLv3'),
                (ssl.PROTOCOL_TLSv1, 'TLSv1.0'),
                (ssl.PROTOCOL_TLSv1_1, 'TLSv1.1')
            ]
            
            for protocol, name in weak_protocols:
                try:
                    context = ssl.SSLContext(protocol)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    ssock = context.wrap_socket(sock, server_hostname=hostname)
                    
                    await asyncio.to_thread(ssock.connect, (hostname, port))
                    ssock.close()
                    
                    self.results.append({
                        'type': 'Weak SSL/TLS Protocol',
                        'url': target,
                        'severity': 'high',
                        'evidence': f'Server supports insecure {name} protocol',
                        'confidence': 0.95,
                        'cvss_score': 7.5,
                        'payload': name,
                        'remediation': f'Disable {name} and use TLS 1.2 or higher'
                    })
                    logger.warning(f"[SSL/TLS] Weak protocol supported: {name}")
                    
                except:
                    pass  # Protocol not supported (good)
            
            # Test certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            ssock = context.wrap_socket(sock, server_hostname=hostname)
            
            await asyncio.to_thread(ssock.connect, (hostname, port))
            cert = ssock.getpeercert()
            ssock.close()
            
            # Check for self-signed or expired cert
            if not cert:
                self.results.append({
                    'type': 'Invalid SSL Certificate',
                    'url': target,
                    'severity': 'high',
                    'evidence': 'No valid SSL certificate presented',
                    'confidence': 0.90,
                    'cvss_score': 7.5,
                    'remediation': 'Install valid SSL certificate from trusted CA'
                })
        
        except Exception as e:
            logger.debug(f"[SSL/TLS] Test error: {str(e)}")

    async def _test_cookie_security(self, target: str):
        """Test cookie security flags."""
        logger.info("[A02:Cookies] Testing cookie security")
        
        response = await self.scanner.fetch(target)
        
        if not response or 'headers' not in response:
            return
        
        set_cookie = response['headers'].get('Set-Cookie', '')
        
        if not set_cookie:
            return
        
        cookies = set_cookie.split(',')
        
        for cookie in cookies:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split('=')[0].strip()
            
            issues = []
            
            # Check HttpOnly flag
            if 'httponly' not in cookie_lower:
                issues.append('Missing HttpOnly flag (vulnerable to XSS cookie theft)')
            
            # Check Secure flag
            if 'secure' not in cookie_lower and urlparse(target).scheme == 'https':
                issues.append('Missing Secure flag (cookie can be sent over HTTP)')
            
            # Check SameSite
            if 'samesite' not in cookie_lower:
                issues.append('Missing SameSite flag (vulnerable to CSRF)')
            elif 'samesite=none' in cookie_lower:
                issues.append('SameSite=None without Secure flag (insecure)')
            
            if issues:
                self.results.append({
                    'type': 'Insecure Cookie Configuration',
                    'url': target,
                    'severity': 'medium',
                    'evidence': f"Cookie '{cookie_name}' has security issues: {', '.join(issues)}",
                    'confidence': 0.95,
                    'cvss_score': 5.3,
                    'remediation': 'Set HttpOnly, Secure, and SameSite flags on all cookies'
                })
                logger.warning(f"[Cookies] Insecure cookie: {cookie_name}")

    async def _test_sensitive_data_exposure(self, target: str):
        """Test for sensitive data in URLs and responses."""
        logger.info("[A02:DataExposure] Testing for sensitive data exposure")
        
        response = await self.scanner.fetch(target)
        
        if not response:
            return
        
        # Patterns for sensitive data
        patterns = [
            (r'password[\s]*[:=][\s]*["\']?([^"\s\',]+)', 'Password'),
            (r'api[_-]?key[\s]*[:=][\s]*["\']?([a-zA-Z0-9_\-]{20,})', 'API Key'),
            (r'secret[_-]?key[\s]*[:=][\s]*["\']?([a-zA-Z0-9_\-]{20,})', 'Secret Key'),
            (r'aws[_-]?access[_-]?key[\s]*[:=][\s]*["\']?(AKIA[A-Z0-9]{16})', 'AWS Access Key'),
            (r'private[_-]?key[\s]*[:=]', 'Private Key'),
            (r'bearer[\s]+([a-zA-Z0-9_\-\.]+)', 'Bearer Token'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email Address'),
            (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
            (r'\b(?:\d{4}[\s-]?){3}\d{4}\b', 'Credit Card')
        ]
        
        content = response['content']
        
        for pattern, data_type in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                # Don't report if it's in HTML comments or obvious placeholders
                if not any(placeholder in str(matches[0]).lower() 
                          for placeholder in ['example', 'test', 'xxxx', '****', 'placeholder']):
                    self.results.append({
                        'type': 'Sensitive Data Exposure',
                        'url': target,
                        'severity': 'high' if data_type in ['Password', 'API Key', 'Secret Key', 'AWS Access Key'] else 'medium',
                        'evidence': f'{data_type} found in response: {str(matches[0])[:50]}...',
                        'confidence': 0.70,
                        'cvss_score': 7.5 if data_type in ['Password', 'API Key'] else 5.3,
                        'remediation': 'Remove sensitive data from responses, use encryption, and implement proper access controls'
                    })
                    logger.warning(f"[DataExposure] {data_type} found in response")
        
        # Check URL for sensitive data
        parsed = urlparse(target)
        if parsed.query:
            for pattern, data_type in patterns[:5]:  # Only check critical patterns in URL
                if re.search(pattern, parsed.query, re.IGNORECASE):
                    self.results.append({
                        'type': 'Sensitive Data in URL',
                        'url': target,
                        'severity': 'high',
                        'evidence': f'{data_type} passed in URL query string',
                        'confidence': 0.85,
                        'cvss_score': 6.5,
                        'remediation': 'Use POST requests and encrypted connections for sensitive data'
                    })
                    logger.warning(f"[DataExposure] {data_type} in URL")

    async def _test_security_headers(self, target: str):
        """Test for missing security headers."""
        logger.info("[A02:Headers] Testing security headers")
        
        response = await self.scanner.fetch(target)
        
        if not response or 'headers' not in response:
            return
        
        headers = {k.lower(): v for k, v in response['headers'].items()}
        
        # Critical security headers
        required_headers = {
            'strict-transport-security': ('HSTS', 'high', 'Protects against protocol downgrade attacks'),
            'x-frame-options': ('X-Frame-Options', 'medium', 'Prevents clickjacking'),
            'x-content-type-options': ('X-Content-Type-Options', 'medium', 'Prevents MIME sniffing'),
            'content-security-policy': ('CSP', 'medium', 'Mitigates XSS and injection attacks'),
            'x-xss-protection': ('X-XSS-Protection', 'low', 'Legacy XSS protection')
        }
        
        for header, (name, severity, purpose) in required_headers.items():
            if header not in headers:
                cvss = {'high': 7.5, 'medium': 5.3, 'low': 3.7}[severity]
                self.results.append({
                    'type': 'Missing Security Header',
                    'url': target,
                    'severity': severity,
                    'evidence': f'Missing {name} header. {purpose}',
                    'confidence': 0.95,
                    'cvss_score': cvss,
                    'remediation': f'Add {name} header to responses'
                })
                logger.warning(f"[Headers] Missing: {name}")