"""Web crawler for discovering URLs, forms, and parameters."""

import asyncio
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from loguru import logger
import re


class WebCrawler:
    """Intelligent web crawler with form and parameter extraction."""

    def __init__(self, async_scanner, config: Dict = None):
        """Initialize web crawler.
        
        Args:
            async_scanner: AsyncScanner instance
            config: Crawler configuration
        """
        self.scanner = async_scanner
        self.config = config or {}
        self.max_depth = self.config.get('max_depth', 3)
        self.max_urls = self.config.get('max_urls', 500)
        self.respect_robots = self.config.get('respect_robots', True)
        
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.forms: List[Dict] = []
        self.parameters: Set[str] = set()
        self.endpoints: Set[str] = set()
        self.external_links: Set[str] = set()

    async def crawl(self, start_url: str) -> Dict:
        """Crawl website starting from URL.
        
        Args:
            start_url: Starting URL
            
        Returns:
            Dictionary with crawl results
        """
        logger.info(f"Starting web crawl from {start_url}")
        
        # Parse base URL
        parsed = urlparse(start_url)
        base_domain = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check robots.txt if enabled
        if self.respect_robots:
            await self._check_robots(base_domain)
        
        # Start crawling
        await self._crawl_recursive(start_url, base_domain, depth=0)
        
        results = {
            'start_url': start_url,
            'urls_discovered': len(self.discovered_urls),
            'urls_crawled': len(self.visited_urls),
            'forms_found': len(self.forms),
            'parameters_found': len(self.parameters),
            'endpoints': sorted(list(self.endpoints)),
            'urls': sorted(list(self.discovered_urls)),
            'forms': self.forms,
            'parameters': sorted(list(self.parameters)),
            'external_links': sorted(list(self.external_links))[:50]  # Limit external links
        }
        
        logger.success(f"Crawl completed: {len(self.visited_urls)} URLs crawled, {len(self.forms)} forms found")
        
        return results

    async def _crawl_recursive(self, url: str, base_domain: str, depth: int):
        """Recursively crawl URLs.
        
        Args:
            url: Current URL to crawl
            base_domain: Base domain to stay within
            depth: Current crawl depth
        """
        # Check limits
        if depth > self.max_depth:
            return
        
        if len(self.visited_urls) >= self.max_urls:
            logger.info(f"Reached maximum URL limit ({self.max_urls})")
            return
        
        # Skip if already visited
        if url in self.visited_urls:
            return
        
        # Mark as visited
        self.visited_urls.add(url)
        
        # Fetch page
        response = await self.scanner.fetch(url)
        
        if not response or response['status'] != 200:
            return
        
        html = response['content']
        
        # Parse HTML
        soup = BeautifulSoup(html, 'lxml')
        
        # Extract links
        links = await self._extract_links(soup, url, base_domain)
        
        # Extract forms
        await self._extract_forms(soup, url)
        
        # Extract parameters from URL
        self._extract_url_parameters(url)
        
        # Extract API endpoints from JavaScript
        await self._extract_js_endpoints(soup, url)
        
        # Crawl discovered links
        for link in links:
            if len(self.visited_urls) < self.max_urls:
                await self._crawl_recursive(link, base_domain, depth + 1)

    async def _extract_links(self, soup: BeautifulSoup, current_url: str, base_domain: str) -> List[str]:
        """Extract links from HTML.
        
        Args:
            soup: BeautifulSoup object
            current_url: Current page URL
            base_domain: Base domain
            
        Returns:
            List of discovered links
        """
        links = []
        
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            
            # Normalize URL
            absolute_url = urljoin(current_url, href)
            
            # Parse URL
            parsed = urlparse(absolute_url)
            
            # Remove fragment
            url_without_fragment = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                url_without_fragment += f"?{parsed.query}"
            
            # Check if in scope
            if absolute_url.startswith(base_domain):
                if url_without_fragment not in self.discovered_urls:
                    self.discovered_urls.add(url_without_fragment)
                    links.append(url_without_fragment)
            else:
                # External link
                self.external_links.add(absolute_url)
        
        return links

    async def _extract_forms(self, soup: BeautifulSoup, url: str):
        """Extract forms and their fields.
        
        Args:
            soup: BeautifulSoup object
            url: Current page URL
        """
        for form in soup.find_all('form'):
            form_data = {
                'url': url,
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'fields': []
            }
            
            # Make action absolute
            if form_data['action']:
                form_data['action'] = urljoin(url, form_data['action'])
            else:
                form_data['action'] = url
            
            # Extract input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                field = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                
                if field['name']:
                    form_data['fields'].append(field)
                    self.parameters.add(field['name'])
            
            self.forms.append(form_data)

    def _extract_url_parameters(self, url: str):
        """Extract parameters from URL query string.
        
        Args:
            url: URL to extract parameters from
        """
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params.keys():
                self.parameters.add(param)

    async def _extract_js_endpoints(self, soup: BeautifulSoup, url: str):
        """Extract API endpoints from JavaScript files.
        
        Args:
            soup: BeautifulSoup object
            url: Current page URL
        """
        # Look for inline scripts and external JS files
        scripts = soup.find_all('script')
        
        for script in scripts:
            # External JS file
            if script.get('src'):
                js_url = urljoin(url, script['src'])
                js_response = await self.scanner.fetch(js_url)
                
                if js_response and js_response['status'] == 200:
                    self._parse_js_for_endpoints(js_response['content'])
            
            # Inline script
            elif script.string:
                self._parse_js_for_endpoints(script.string)

    def _parse_js_for_endpoints(self, js_content: str):
        """Parse JavaScript content for API endpoints.
        
        Args:
            js_content: JavaScript code
        """
        # Look for common API patterns
        patterns = [
            r'["\'](\/api\/[^"\'\'\s]+)["\']',
            r'["\'](\/v[0-9]+\/[^"\'\'\s]+)["\']',
            r'["\'](\/graphql[^"\'\'\s]*)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
            r'\.ajax\(\{[^}]*url:[\s]*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if match.startswith('/'):
                    self.endpoints.add(match)

    async def _check_robots(self, base_url: str):
        """Check and parse robots.txt.
        
        Args:
            base_url: Base URL of website
        """
        robots_url = urljoin(base_url, '/robots.txt')
        response = await self.scanner.fetch(robots_url)
        
        if response and response['status'] == 200:
            logger.info(f"Found robots.txt at {robots_url}")
            # Parse for interesting paths
            for line in response['content'].split('\n'):
                if line.startswith('Disallow:') or line.startswith('Allow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        full_url = urljoin(base_url, path)
                        self.discovered_urls.add(full_url)

    async def find_comments(self, url: str) -> List[str]:
        """Find HTML comments that might contain sensitive info.
        
        Args:
            url: URL to check
            
        Returns:
            List of comments
        """
        response = await self.scanner.fetch(url)
        
        if not response or response['status'] != 200:
            return []
        
        soup = BeautifulSoup(response['content'], 'lxml')
        comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in str(text))
        
        return [str(comment).strip() for comment in comments]

    async def discover_subdomains_from_js(self, url: str) -> Set[str]:
        """Discover subdomains mentioned in JavaScript files.
        
        Args:
            url: URL to check
            
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        response = await self.scanner.fetch(url)
        if not response:
            return subdomains
        
        soup = BeautifulSoup(response['content'], 'lxml')
        scripts = soup.find_all('script', src=True)
        
        for script in scripts:
            js_url = urljoin(url, script['src'])
            js_response = await self.scanner.fetch(js_url)
            
            if js_response and js_response['status'] == 200:
                # Look for domain patterns
                pattern = r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
                matches = re.findall(pattern, js_response['content'])
                subdomains.update(matches)
        
        return subdomains