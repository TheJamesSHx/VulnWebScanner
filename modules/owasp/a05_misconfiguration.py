"""OWASP A05: Security Misconfiguration - Production Grade Scanner.

Detects:
- Default credentials
- Directory listing
- Debug mode enabled
- Missing security headers
- Exposed configuration files
- Information disclosure
- Unnecessary services/features
"""

import asyncio
import re
from typing import List, Dict, Set
from urllib.parse import urljoin
from loguru import logger


class SecurityMisconfigurationScanner:
    """Advanced security misconfiguration scanner."""

    def __init__(self, async_scanner, config: Dict = None):
        self.scanner = async_scanner
        self.config = config or {}
        self.results = []

    async def scan(self, target: str, recon_data: Dict = None) -> List[Dict]:
        """Comprehensive security misconfiguration scan.
        
        Args:
            target: Target URL
            recon_data: Reconnaissance data
            
        Returns:
            List of vulnerability findings
        """
        logger.info("[A05] Starting Security Misconfiguration scan")
        
        await asyncio.gather(
            self._test_default_credentials(target),
            self._test_directory_listing(target),
            self._test_debug_mode(target),
            self._test_exposed_files(target),
            self._test_information_disclosure(target),
            self._test_server_info(target),
            self._test_unnecessary_methods(target)
        )
        
        logger.success(f"[A05] Scan complete: {len(self.results)} vulnerabilities found")
        return self.results

    async def _test_default_credentials(self, target: str):
        """Test for default credentials on common admin panels."""
        logger.info("[A05:DefaultCreds] Testing default credentials")
        
        # Common admin paths
        admin_paths = [
            '/admin',
            '/administrator',
            '/wp-admin',
            '/phpmyadmin',
            '/admin/login',
            '/manager/html',
            '/jenkins'
        ]
        
        # Common default credentials
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', ''),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('root', 'toor'),
            ('admin', '12345'),
            ('admin', 'admin123'),
            ('guest', 'guest'),
            ('test', 'test')
        ]
        
        for path in admin_paths:
            login_url = urljoin(target, path)
            
            for username, password in default_creds:
                # Try login
                response = await self.scanner.post(
                    login_url,
                    data={'username': username, 'password': password, 'user': username, 'pass': password}
                )
                
                if response:
                    # Check for successful login
                    success_indicators = [
                        'dashboard', 'welcome', 'logout', 'admin panel',
                        'successful', 'authenticated'
                    ]
                    
                    content_lower = response['content'].lower()
                    if any(indicator in content_lower for indicator in success_indicators):
                        # Avoid false positives - check we're not on login page
                        if 'login' not in content_lower or response['status'] in [302, 303]:
                            self.results.append({
                                'type': 'Default Credentials',
                                'url': login_url,
                                'severity': 'critical',
                                'evidence': f'Default credentials work: {username}:{password}',
                                'confidence': 0.75,
                                'cvss_score': 9.8,
                                'payload': f'{username}:{password}',
                                'remediation': 'Change all default credentials immediately'
                            })
                            logger.critical(f"[DefaultCreds] Working credentials found: {username}:{password}")
                            return  # Stop after first finding

    async def _test_directory_listing(self, target: str):
        """Test for directory listing vulnerabilities."""
        logger.info("[A05:DirList] Testing directory listing")
        
        # Common directories that might have listing enabled
        test_dirs = [
            '/images/',
            '/uploads/',
            '/files/',
            '/assets/',
            '/backup/',
            '/backups/',
            '/data/',
            '/includes/',
            '/js/',
            '/css/',
            '/tmp/',
            '/admin/',
            '/api/'
        ]
        
        # Directory listing signatures
        listing_signatures = [
            r'<title>Index of /',
            r'\[To Parent Directory\]',
            r'<h1>Index of',
            r'Directory Listing For',
            r'<TITLE>Directory listing for',
            r'Parent Directory',
            r'\[DIR\]',
            r'Last modified'
        ]
        
        for directory in test_dirs:
            test_url = urljoin(target, directory)
            response = await self.scanner.fetch(test_url)
            
            if response and response['status'] == 200:
                for signature in listing_signatures:
                    if re.search(signature, response['content'], re.IGNORECASE):
                        self.results.append({
                            'type': 'Directory Listing Enabled',
                            'url': test_url,
                            'severity': 'medium',
                            'evidence': f'Directory listing enabled at {directory}',
                            'confidence': 0.90,
                            'cvss_score': 5.3,
                            'remediation': 'Disable directory listing in web server configuration'
                        })
                        logger.warning(f"[DirList] Directory listing at {directory}")
                        break

    async def _test_debug_mode(self, target: str):
        """Test for debug mode and verbose error messages."""
        logger.info("[A05:Debug] Testing debug mode")
        
        # Trigger errors to check for debug output
        error_triggers = [
            '?debug=1',
            '?test=1',
            '?dev=1',
            '/debug',
            '/.env',
            '/phpinfo.php',
            '/info.php',
            '/test.php'
        ]
        
        debug_signatures = [
            r'stack trace',
            r'line \d+ in',
            r'call stack',
            r'thrown in.*?on line',
            r'Warning:.*?in.*?line',
            r'Fatal error:.*?in',
            r'Notice:.*?in.*?line',
            r'Exception.*?in.*?line',
            r'\[DEBUG\]',
            r'DEBUG MODE',
            r'var_dump\(',
            r'print_r\(',
            r'Traceback \(most recent call last\)',
            r'django.core.exceptions',
            r'File ".*?", line \d+',
            r'<h1>Server Error in',
            r'Detailed Error Information'
        ]
        
        for trigger in error_triggers:
            test_url = urljoin(target, trigger) if trigger.startswith('/') else target + trigger
            response = await self.scanner.fetch(test_url)
            
            if response and response['status'] in [200, 500]:
                for signature in debug_signatures:
                    if re.search(signature, response['content'], re.IGNORECASE):
                        self.results.append({
                            'type': 'Debug Mode Enabled',
                            'url': test_url,
                            'severity': 'medium',
                            'evidence': 'Debug information exposed in error messages',
                            'confidence': 0.85,
                            'cvss_score': 5.3,
                            'remediation': 'Disable debug mode and use generic error pages in production'
                        })
                        logger.warning(f"[Debug] Debug mode detected at {test_url}")
                        return  # One finding is enough

    async def _test_exposed_files(self, target: str):
        """Test for exposed sensitive configuration files."""
        logger.info("[A05:ExposedFiles] Testing for exposed files")
        
        sensitive_files = [
            # Git/Version Control
            '.git/config',
            '.git/HEAD',
            '.gitignore',
            '.svn/entries',
            '.svn/wc.db',
            '.hg/requires',
            
            # Configuration Files
            '.env',
            '.env.local',
            '.env.production',
            '.env.backup',
            'web.config',
            'Web.config',
            '.htaccess',
            '.htpasswd',
            'wp-config.php',
            'wp-config.php.bak',
            'config.php',
            'configuration.php',
            'settings.php',
            'database.yml',
            'database.php',
            'db.php',
            'connect.php',
            'config.inc.php',
            
            # Package Files
            'composer.json',
            'composer.lock',
            'package.json',
            'package-lock.json',
            'yarn.lock',
            'Gemfile',
            'Gemfile.lock',
            'requirements.txt',
            'pom.xml',
            
            # Docker
            'Dockerfile',
            'docker-compose.yml',
            '.dockerignore',
            
            # Backup Files
            'backup.sql',
            'dump.sql',
            'database.sql',
            'db.sql',
            'backup.zip',
            'backup.tar.gz',
            
            # Logs
            'error.log',
            'access.log',
            'debug.log',
            'app.log',
            'application.log',
            
            # PHP Info
            'phpinfo.php',
            'info.php',
            'test.php',
            
            # Other
            '.DS_Store',
            'README.md',
            'CHANGELOG.md',
            'TODO.txt',
            'robots.txt',
            'sitemap.xml',
            'crossdomain.xml',
            'clientaccesspolicy.xml'
        ]
        
        for file in sensitive_files:
            test_url = urljoin(target, file)
            response = await self.scanner.fetch(test_url)
            
            if response and response['status'] == 200:
                # Verify it's actually the file (not 404 page)
                if len(response['content']) > 0 and '404' not in response['content'][:200]:
                    severity = 'critical' if file in ['.env', '.git/config', 'wp-config.php', 'database.yml'] else 'high'
                    cvss = 9.1 if severity == 'critical' else 7.5
                    
                    self.results.append({
                        'type': 'Exposed Sensitive File',
                        'url': test_url,
                        'severity': severity,
                        'evidence': f'Sensitive file accessible: {file}',
                        'confidence': 0.90,
                        'cvss_score': cvss,
                        'remediation': f'Remove or restrict access to {file}'
                    })
                    logger.warning(f"[ExposedFiles] Found: {file}")

    async def _test_information_disclosure(self, target: str):
        """Test for information disclosure."""
        logger.info("[A05:InfoDisclosure] Testing information disclosure")
        
        response = await self.scanner.fetch(target)
        
        if not response:
            return
        
        content = response['content']
        headers = response.get('headers', {})
        
        # Check for technology disclosure in headers
        if 'X-Powered-By' in headers:
            self.results.append({
                'type': 'Server Technology Disclosure',
                'url': target,
                'severity': 'low',
                'evidence': f"X-Powered-By header reveals: {headers['X-Powered-By']}",
                'confidence': 0.95,
                'cvss_score': 3.7,
                'remediation': 'Remove or obfuscate server technology headers'
            })
        
        # Check for verbose error pages
        if response['status'] in [403, 404, 500]:
            if len(content) > 500:  # Verbose error page
                self.results.append({
                    'type': 'Verbose Error Pages',
                    'url': target,
                    'severity': 'low',
                    'evidence': f'Error page ({response["status"]}) reveals server information',
                    'confidence': 0.70,
                    'cvss_score': 3.7,
                    'remediation': 'Use custom, minimal error pages'
                })
        
        # Check for HTML comments with sensitive info
        comments = re.findall(r'<!--(.+?)-->', content, re.DOTALL)
        for comment in comments:
            if any(keyword in comment.lower() for keyword in 
                   ['todo', 'fixme', 'hack', 'password', 'api_key', 'secret', 'username']):
                self.results.append({
                    'type': 'Sensitive Information in Comments',
                    'url': target,
                    'severity': 'low',
                    'evidence': f'HTML comment contains: {comment[:100]}...',
                    'confidence': 0.75,
                    'cvss_score': 3.7,
                    'remediation': 'Remove sensitive comments from production code'
                })
                break

    async def _test_server_info(self, target: str):
        """Test for server information disclosure."""
        logger.info("[A05:ServerInfo] Testing server information")
        
        response = await self.scanner.fetch(target)
        
        if not response:
            return
        
        headers = response.get('headers', {})
        
        # Check Server header
        if 'Server' in headers:
            server = headers['Server']
            # Check for version numbers
            if re.search(r'[0-9]+\.[0-9]+', server):
                self.results.append({
                    'type': 'Server Version Disclosure',
                    'url': target,
                    'severity': 'low',
                    'evidence': f'Server header reveals version: {server}',
                    'confidence': 0.95,
                    'cvss_score': 3.7,
                    'remediation': 'Remove version information from Server header'
                })

    async def _test_unnecessary_methods(self, target: str):
        """Test for unnecessary HTTP methods enabled."""
        logger.info("[A05:HTTPMethods] Testing HTTP methods")
        
        # Test dangerous HTTP methods
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS']
        
        for method in dangerous_methods:
            response = await self.scanner.fetch(target, method=method)
            
            if response and response['status'] in [200, 204]:
                self.results.append({
                    'type': 'Unnecessary HTTP Method Enabled',
                    'url': target,
                    'severity': 'medium',
                    'evidence': f'{method} method enabled and responds with {response["status"]}',
                    'confidence': 0.80,
                    'cvss_score': 5.3,
                    'payload': method,
                    'remediation': f'Disable {method} method if not required'
                })
                logger.warning(f"[HTTPMethods] {method} enabled")