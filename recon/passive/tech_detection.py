"""Technology and framework detection (Wappalyzer-style)."""

import re
import json
from typing import Dict, List, Set
from loguru import logger
from bs4 import BeautifulSoup


class TechnologyDetector:
    """Detect web technologies, frameworks, and libraries."""

    def __init__(self, async_scanner):
        """Initialize technology detector.
        
        Args:
            async_scanner: AsyncScanner instance
        """
        self.scanner = async_scanner
        self.technologies = self._load_signatures()

    def _load_signatures(self) -> Dict:
        """Load technology detection signatures.
        
        Returns:
            Dictionary of technology signatures
        """
        # Simplified Wappalyzer-style signatures
        return {
            'WordPress': {
                'html': [r'wp-content', r'wp-includes'],
                'headers': {'X-Powered-By': r'WordPress'},
                'meta': {'generator': r'WordPress'},
                'cookies': ['wordpress_', 'wp-settings']
            },
            'Joomla': {
                'html': [r'/components/com_', r'Joomla!'],
                'meta': {'generator': r'Joomla'},
            },
            'Drupal': {
                'html': [r'Drupal'],
                'headers': {'X-Drupal-Cache': r'.*', 'X-Generator': r'Drupal'},
                'cookies': ['SESS[a-z0-9]+'],
                'meta': {'generator': r'Drupal'}
            },
            'React': {
                'html': [r'react', r'__REACT', r'data-reactroot'],
                'scripts': [r'react\..*\.js', r'react-dom']
            },
            'Vue.js': {
                'html': [r'v-if=', r'v-for=', r'v-model='],
                'scripts': [r'vue\.js', r'vue\.min\.js']
            },
            'Angular': {
                'html': [r'ng-app', r'ng-controller', r'ng-model'],
                'scripts': [r'angular\.js', r'angular\.min\.js']
            },
            'jQuery': {
                'scripts': [r'jquery[-.]([0-9.]+)\.(?:min\.)?js']
            },
            'Bootstrap': {
                'html': [r'bootstrap'],
                'scripts': [r'bootstrap\.(?:min\.)?js'],
                'css': [r'bootstrap\.(?:min\.)?css']
            },
            'Apache': {
                'headers': {'Server': r'Apache'}
            },
            'Nginx': {
                'headers': {'Server': r'nginx'}
            },
            'PHP': {
                'headers': {'X-Powered-By': r'PHP'},
                'cookies': ['PHPSESSID']
            },
            'ASP.NET': {
                'headers': {'X-AspNet-Version': r'.*', 'X-Powered-By': r'ASP\.NET'},
                'cookies': ['ASP.NET_SessionId']
            },
            'Express': {
                'headers': {'X-Powered-By': r'Express'}
            },
            'Django': {
                'cookies': ['csrftoken', 'sessionid']
            },
            'Flask': {
                'cookies': ['session']
            },
            'Laravel': {
                'cookies': ['laravel_session']
            },
            'Cloudflare': {
                'headers': {'Server': r'cloudflare', 'CF-Ray': r'.*'},
                'cookies': ['__cfduid', '__cf_bm']
            },
            'Amazon CloudFront': {
                'headers': {'X-Amz-Cf-Id': r'.*', 'Via': r'CloudFront'}
            },
            'Google Analytics': {
                'scripts': [r'google-analytics\.com/ga\.js', r'googletagmanager\.com']
            },
            'Google Tag Manager': {
                'scripts': [r'googletagmanager\.com/gtm\.js']
            },
            'Font Awesome': {
                'css': [r'font-awesome'],
                'html': [r'fa-']
            }
        }

    async def detect(self, url: str) -> Dict:
        """Detect technologies used by a website.
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary with detected technologies
        """
        logger.info(f"Detecting technologies for {url}")
        
        detected = {
            'url': url,
            'technologies': [],
            'server': None,
            'programming_languages': [],
            'frameworks': [],
            'cms': [],
            'javascript_libraries': [],
            'cdn': [],
            'analytics': []
        }
        
        # Fetch the page
        response = await self.scanner.fetch(url)
        
        if not response or response['status'] != 200:
            logger.warning(f"Failed to fetch {url} for technology detection")
            return detected
        
        html = response['content']
        headers = response['headers']
        
        # Parse HTML
        soup = BeautifulSoup(html, 'lxml')
        
        # Detect technologies
        for tech_name, signatures in self.technologies.items():
            confidence = 0
            matches = []
            
            # Check HTML content
            if 'html' in signatures:
                for pattern in signatures['html']:
                    if re.search(pattern, html, re.IGNORECASE):
                        confidence += 30
                        matches.append(f"HTML: {pattern}")
            
            # Check HTTP headers
            if 'headers' in signatures:
                for header, pattern in signatures['headers'].items():
                    if header in headers:
                        if re.search(pattern, headers[header], re.IGNORECASE):
                            confidence += 50
                            matches.append(f"Header: {header}")
            
            # Check cookies
            if 'cookies' in signatures:
                cookies = headers.get('Set-Cookie', '')
                for cookie_pattern in signatures['cookies']:
                    if re.search(cookie_pattern, cookies, re.IGNORECASE):
                        confidence += 40
                        matches.append(f"Cookie: {cookie_pattern}")
            
            # Check meta tags
            if 'meta' in signatures:
                for meta_name, pattern in signatures['meta'].items():
                    meta_tags = soup.find_all('meta', attrs={'name': meta_name})
                    for tag in meta_tags:
                        content = tag.get('content', '')
                        if re.search(pattern, content, re.IGNORECASE):
                            confidence += 50
                            matches.append(f"Meta: {meta_name}")
            
            # Check scripts
            if 'scripts' in signatures:
                scripts = soup.find_all('script', src=True)
                for script in scripts:
                    src = script.get('src', '')
                    for pattern in signatures['scripts']:
                        if re.search(pattern, src, re.IGNORECASE):
                            confidence += 30
                            matches.append(f"Script: {pattern}")
                            
                            # Extract version if possible
                            version_match = re.search(r'([0-9.]+)', src)
                            if version_match:
                                matches.append(f"Version: {version_match.group(1)}")
            
            # Check CSS
            if 'css' in signatures:
                links = soup.find_all('link', rel='stylesheet')
                for link in links:
                    href = link.get('href', '')
                    for pattern in signatures['css']:
                        if re.search(pattern, href, re.IGNORECASE):
                            confidence += 30
                            matches.append(f"CSS: {pattern}")
            
            # Add to detected if confidence threshold met
            if confidence >= 30:
                tech_info = {
                    'name': tech_name,
                    'confidence': min(confidence, 100),
                    'matches': matches
                }
                detected['technologies'].append(tech_info)
                
                # Categorize
                self._categorize_technology(tech_name, detected)
        
        # Extract server info
        if 'Server' in headers:
            detected['server'] = headers['Server']
        
        logger.success(f"Detected {len(detected['technologies'])} technologies for {url}")
        
        return detected

    def _categorize_technology(self, tech_name: str, detected: Dict):
        """Categorize detected technology.
        
        Args:
            tech_name: Name of technology
            detected: Detected technologies dictionary
        """
        cms_list = ['WordPress', 'Joomla', 'Drupal', 'Magento', 'Shopify']
        frameworks = ['React', 'Vue.js', 'Angular', 'Django', 'Laravel', 'Express', 'Flask']
        js_libs = ['jQuery', 'Bootstrap', 'Font Awesome']
        cdn_list = ['Cloudflare', 'Amazon CloudFront', 'Akamai']
        analytics_list = ['Google Analytics', 'Google Tag Manager']
        languages = ['PHP', 'ASP.NET', 'Python', 'Ruby', 'Node.js']
        
        if tech_name in cms_list and tech_name not in detected['cms']:
            detected['cms'].append(tech_name)
        
        if tech_name in frameworks and tech_name not in detected['frameworks']:
            detected['frameworks'].append(tech_name)
        
        if tech_name in js_libs and tech_name not in detected['javascript_libraries']:
            detected['javascript_libraries'].append(tech_name)
        
        if tech_name in cdn_list and tech_name not in detected['cdn']:
            detected['cdn'].append(tech_name)
        
        if tech_name in analytics_list and tech_name not in detected['analytics']:
            detected['analytics'].append(tech_name)
        
        if tech_name in languages and tech_name not in detected['programming_languages']:
            detected['programming_languages'].append(tech_name)

    async def detect_waf(self, url: str) -> Dict:
        """Detect Web Application Firewall.
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary with WAF detection results
        """
        logger.info(f"Detecting WAF for {url}")
        
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
            'AWS WAF': ['x-amzn-', 'awselb'],
            'Akamai': ['akamai', 'x-akamai'],
            'Imperva': ['incap_ses', 'visid_incap'],
            'F5 BIG-IP': ['bigip', 'f5'],
            'ModSecurity': ['mod_security', 'NOYB']
        }
        
        response = await self.scanner.fetch(url)
        
        if not response:
            return {'waf_detected': False}
        
        headers = response['headers']
        content = response['content']
        
        detected_waf = []
        
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                # Check headers
                for header, value in headers.items():
                    if re.search(sig, header + value, re.IGNORECASE):
                        detected_waf.append(waf_name)
                        break
                
                # Check content
                if re.search(sig, content, re.IGNORECASE):
                    if waf_name not in detected_waf:
                        detected_waf.append(waf_name)
        
        return {
            'waf_detected': len(detected_waf) > 0,
            'waf_products': detected_waf
        }