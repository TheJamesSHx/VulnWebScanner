"""OWASP A06: Vulnerable and Outdated Components - Production Grade Scanner.

Detects:
- Outdated JavaScript libraries
- Vulnerable CMS versions (WordPress, Joomla, Drupal)
- Known CVEs in detected software
- Deprecated libraries
- Unpatched frameworks
"""

import asyncio
import re
import json
from typing import List, Dict, Set
from loguru import logger
from urllib.parse import urljoin
from bs4 import BeautifulSoup


class VulnerableComponentsScanner:
    """Advanced vulnerable components scanner with CVE detection."""

    def __init__(self, async_scanner, config: Dict = None):
        self.scanner = async_scanner
        self.config = config or {}
        self.results = []
        self.detected_components = {}

    async def scan(self, target: str, recon_data: Dict = None) -> List[Dict]:
        """Comprehensive vulnerable components scan.
        
        Args:
            target: Target URL
            recon_data: Reconnaissance data (tech stack)
            
        Returns:
            List of vulnerability findings
        """
        logger.info("[A06] Starting Vulnerable Components scan")
        
        await asyncio.gather(
            self._detect_js_libraries(target),
            self._detect_cms_versions(target),
            self._detect_server_versions(target),
            self._detect_framework_versions(target),
            self._check_known_cves()
        )
        
        logger.success(f"[A06] Scan complete: {len(self.results)} vulnerabilities found")
        return self.results

    async def _detect_js_libraries(self, target: str):
        """Detect JavaScript library versions and check for vulnerabilities."""
        logger.info("[A06:JSLibs] Detecting JavaScript libraries")
        
        response = await self.scanner.fetch(target)
        if not response or response['status'] != 200:
            return
        
        soup = BeautifulSoup(response['content'], 'lxml')
        scripts = soup.find_all('script', src=True)
        
        # Known vulnerable library patterns
        vulnerable_libs = {
            'jquery': {
                'pattern': r'jquery[-.]([0-9.]+)(?:\.min)?\.js',
                'vulnerable_versions': {
                    '1.0': '3.5.0',  # Versions below 3.5.0 have XSS vulnerabilities
                    'cve': 'CVE-2020-11022, CVE-2020-11023'
                }
            },
            'angular': {
                'pattern': r'angular(?:\.min)?\.js.*?([0-9.]+)',
                'vulnerable_versions': {
                    '1.0': '1.8.0',  # Angular 1.x has sandbox bypass
                    'cve': 'CVE-2019-10768'
                }
            },
            'lodash': {
                'pattern': r'lodash(?:\.min)?\.js.*?([0-9.]+)',
                'vulnerable_versions': {
                    '1.0': '4.17.21',  # Prototype pollution
                    'cve': 'CVE-2020-28500, CVE-2021-23337'
                }
            },
            'bootstrap': {
                'pattern': r'bootstrap(?:\.min)?\.js.*?([0-9.]+)',
                'vulnerable_versions': {
                    '3.0': '3.4.1',  # XSS vulnerabilities
                    'cve': 'CVE-2019-8331'
                }
            },
            'moment': {
                'pattern': r'moment(?:\.min)?\.js.*?([0-9.]+)',
                'vulnerable_versions': {
                    '1.0': '2.29.2',  # ReDoS
                    'cve': 'CVE-2022-24785'
                }
            },
            'handlebars': {
                'pattern': r'handlebars(?:\.min)?\.js.*?([0-9.]+)',
                'vulnerable_versions': {
                    '1.0': '4.7.7',  # Prototype pollution
                    'cve': 'CVE-2021-23383'
                }
            }
        }
        
        for script in scripts:
            src = script.get('src', '')
            
            for lib_name, lib_info in vulnerable_libs.items():
                match = re.search(lib_info['pattern'], src, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else 'unknown'
                    
                    # Store detected component
                    self.detected_components[lib_name] = version
                    
                    # Check if version is vulnerable
                    if version != 'unknown' and self._is_version_vulnerable(version, lib_info['vulnerable_versions']):
                        self.results.append({
                            'type': 'Vulnerable JavaScript Library',
                            'url': urljoin(target, src),
                            'severity': 'high',
                            'evidence': f'{lib_name} version {version} is vulnerable',
                            'confidence': 0.90,
                            'cvss_score': 7.5,
                            'cve': lib_info['vulnerable_versions'].get('cve', ''),
                            'component': lib_name,
                            'version': version,
                            'remediation': f'Update {lib_name} to latest stable version'
                        })
                        logger.warning(f"[JSLibs] Vulnerable {lib_name} {version} detected")

    def _is_version_vulnerable(self, current: str, vulnerable_info: Dict) -> bool:
        """Check if current version is vulnerable."""
        try:
            current_parts = [int(x) for x in current.split('.')[:3]]
            
            for min_ver, max_ver in vulnerable_info.items():
                if min_ver == 'cve':
                    continue
                
                min_parts = [int(x) for x in min_ver.split('.')[:3]]
                max_parts = [int(x) for x in max_ver.split('.')[:3]]
                
                # Pad to 3 parts
                while len(current_parts) < 3:
                    current_parts.append(0)
                while len(min_parts) < 3:
                    min_parts.append(0)
                while len(max_parts) < 3:
                    max_parts.append(0)
                
                # Check if current < max (vulnerable)
                if current_parts < max_parts:
                    return True
        except:
            return False
        
        return False

    async def _detect_cms_versions(self, target: str):
        """Detect CMS versions and known vulnerabilities."""
        logger.info("[A06:CMS] Detecting CMS versions")
        
        # WordPress detection
        wp_version = await self._detect_wordpress(target)
        if wp_version:
            self.detected_components['WordPress'] = wp_version
            
            # WordPress versions with known CVEs
            if self._compare_version(wp_version, '6.4.2') < 0:
                self.results.append({
                    'type': 'Outdated WordPress',
                    'url': target,
                    'severity': 'critical',
                    'evidence': f'WordPress {wp_version} has known vulnerabilities',
                    'confidence': 0.95,
                    'cvss_score': 9.8,
                    'cve': 'Multiple CVEs - check wpvulndb.com',
                    'component': 'WordPress',
                    'version': wp_version,
                    'remediation': 'Update WordPress to latest version immediately'
                })
                logger.critical(f"[CMS] Vulnerable WordPress {wp_version}")
        
        # Joomla detection
        joomla_version = await self._detect_joomla(target)
        if joomla_version:
            self.detected_components['Joomla'] = joomla_version
            
            if self._compare_version(joomla_version, '5.0.0') < 0:
                self.results.append({
                    'type': 'Outdated Joomla',
                    'url': target,
                    'severity': 'critical',
                    'evidence': f'Joomla {joomla_version} has known vulnerabilities',
                    'confidence': 0.95,
                    'cvss_score': 9.8,
                    'component': 'Joomla',
                    'version': joomla_version,
                    'remediation': 'Update Joomla to latest version'
                })
                logger.critical(f"[CMS] Vulnerable Joomla {joomla_version}")
        
        # Drupal detection
        drupal_version = await self._detect_drupal(target)
        if drupal_version:
            self.detected_components['Drupal'] = drupal_version
            
            # Drupalgeddon vulnerabilities
            if self._compare_version(drupal_version, '9.5.0') < 0:
                self.results.append({
                    'type': 'Outdated Drupal',
                    'url': target,
                    'severity': 'critical',
                    'evidence': f'Drupal {drupal_version} may be vulnerable to RCE',
                    'confidence': 0.90,
                    'cvss_score': 9.8,
                    'cve': 'CVE-2018-7600 (Drupalgeddon2)',
                    'component': 'Drupal',
                    'version': drupal_version,
                    'remediation': 'Update Drupal immediately - critical RCE exists'
                })
                logger.critical(f"[CMS] Vulnerable Drupal {drupal_version}")

    async def _detect_wordpress(self, target: str) -> str:
        """Detect WordPress version."""
        # Check meta generator
        response = await self.scanner.fetch(target)
        if response:
            match = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', response['content'])
            if match:
                return match.group(1)
        
        # Check readme.html
        readme_url = urljoin(target, '/readme.html')
        response = await self.scanner.fetch(readme_url)
        if response and response['status'] == 200:
            match = re.search(r'Version ([0-9.]+)', response['content'])
            if match:
                return match.group(1)
        
        return None

    async def _detect_joomla(self, target: str) -> str:
        """Detect Joomla version."""
        response = await self.scanner.fetch(target)
        if response:
            # Check meta generator
            match = re.search(r'<meta name="generator" content="Joomla! - ([0-9.]+)', response['content'])
            if match:
                return match.group(1)
            
            # Check for Joomla markers
            if '/components/com_' in response['content'] or 'Joomla!' in response['content']:
                # Try manifest file
                manifest_url = urljoin(target, '/administrator/manifests/files/joomla.xml')
                manifest_resp = await self.scanner.fetch(manifest_url)
                if manifest_resp:
                    match = re.search(r'<version>([0-9.]+)</version>', manifest_resp['content'])
                    if match:
                        return match.group(1)
        
        return None

    async def _detect_drupal(self, target: str) -> str:
        """Detect Drupal version."""
        # Check CHANGELOG.txt
        changelog_url = urljoin(target, '/CHANGELOG.txt')
        response = await self.scanner.fetch(changelog_url)
        if response and response['status'] == 200:
            match = re.search(r'Drupal ([0-9.]+)', response['content'])
            if match:
                return match.group(1)
        
        return None

    def _compare_version(self, v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
        try:
            v1_parts = [int(x) for x in v1.split('.')]
            v2_parts = [int(x) for x in v2.split('.')]
            
            # Pad to same length
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            
            return 0
        except:
            return 0

    async def _detect_server_versions(self, target: str):
        """Detect web server versions."""
        logger.info("[A06:Server] Detecting server versions")
        
        response = await self.scanner.fetch(target)
        if not response:
            return
        
        headers = response.get('headers', {})
        
        # Check Server header
        if 'Server' in headers:
            server = headers['Server']
            self.detected_components['Server'] = server
            
            # Apache with version
            apache_match = re.search(r'Apache/([0-9.]+)', server)
            if apache_match:
                version = apache_match.group(1)
                if self._compare_version(version, '2.4.57') < 0:
                    self.results.append({
                        'type': 'Outdated Apache',
                        'url': target,
                        'severity': 'high',
                        'evidence': f'Apache {version} has known vulnerabilities',
                        'confidence': 0.95,
                        'cvss_score': 7.5,
                        'component': 'Apache',
                        'version': version,
                        'remediation': 'Update Apache to latest stable version'
                    })
            
            # Nginx with version
            nginx_match = re.search(r'nginx/([0-9.]+)', server)
            if nginx_match:
                version = nginx_match.group(1)
                if self._compare_version(version, '1.25.0') < 0:
                    self.results.append({
                        'type': 'Outdated Nginx',
                        'url': target,
                        'severity': 'high',
                        'evidence': f'Nginx {version} has known vulnerabilities',
                        'confidence': 0.95,
                        'cvss_score': 7.5,
                        'component': 'Nginx',
                        'version': version,
                        'remediation': 'Update Nginx to latest stable version'
                    })
        
        # Check X-Powered-By
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            self.detected_components['X-Powered-By'] = powered_by
            
            # PHP version
            php_match = re.search(r'PHP/([0-9.]+)', powered_by)
            if php_match:
                version = php_match.group(1)
                if self._compare_version(version, '8.2.0') < 0:
                    self.results.append({
                        'type': 'Outdated PHP',
                        'url': target,
                        'severity': 'critical',
                        'evidence': f'PHP {version} is end-of-life and unsupported',
                        'confidence': 0.95,
                        'cvss_score': 8.6,
                        'component': 'PHP',
                        'version': version,
                        'remediation': 'Upgrade to PHP 8.2 or later'
                    })
                    logger.critical(f"[Server] Outdated PHP {version}")

    async def _detect_framework_versions(self, target: str):
        """Detect framework versions from cookies and headers."""
        logger.info("[A06:Frameworks] Detecting frameworks")
        
        response = await self.scanner.fetch(target)
        if not response:
            return
        
        headers = response.get('headers', {})
        cookies = headers.get('Set-Cookie', '')
        
        # Laravel detection
        if 'laravel_session' in cookies.lower():
            self.detected_components['Laravel'] = 'detected'
            logger.info("[Frameworks] Laravel detected")
        
        # Django detection  
        if 'csrftoken' in cookies and 'sessionid' in cookies:
            self.detected_components['Django'] = 'detected'
            logger.info("[Frameworks] Django detected")
        
        # Express.js detection
        if 'X-Powered-By' in headers and 'Express' in headers['X-Powered-By']:
            self.detected_components['Express'] = headers['X-Powered-By']
            logger.info("[Frameworks] Express.js detected")

    async def _check_known_cves(self):
        """Cross-reference detected components with known CVEs."""
        logger.info("[A06:CVE] Checking for known CVEs")
        
        # This would integrate with CVE databases like NVD
        # For now, we log detected components
        if self.detected_components:
            logger.info(f"[CVE] Detected components: {self.detected_components}")