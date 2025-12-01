"""Advanced Web Crawler - Extracts URLs, parameters, endpoints, APIs"""

import asyncio
import re
import json
from typing import Dict, Any, Set, List
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from modules.base_module import BaseModule
import aiohttp
from bs4 import BeautifulSoup

class AdvancedCrawler(BaseModule):
    """Advanced crawler with parameter extraction and API discovery"""
    
    def __init__(self, tool_manager):
        super().__init__(tool_manager)
        self.visited_urls = set()
        self.discovered_urls = set()
        self.endpoints = []
        self.parameters = {}
        self.api_endpoints = []
        self.forms = []
    
    async def scan(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Execute advanced crawling"""
        url = target["url"]
        
        self.log_info(f"Starting advanced crawl for {url}")
        
        # Crawl the site
        await self._crawl_recursive(url, max_depth=3, max_urls=100)
        
        # Extract JavaScript endpoints
        await self._extract_js_endpoints(url)
        
        results = {
            "urls": list(self.discovered_urls),
            "endpoints": self.endpoints,
            "parameters": self.parameters,
            "api_endpoints": self.api_endpoints,
            "forms": self.forms,
            "statistics": {
                "total_urls": len(self.discovered_urls),
                "total_endpoints": len(self.endpoints),
                "total_parameters": sum(len(params) for params in self.parameters.values()),
                "api_endpoints": len(self.api_endpoints),
                "forms": len(self.forms)
            }
        }
        
        self.log_info(f"Crawl complete: {len(self.discovered_urls)} URLs, {len(self.endpoints)} endpoints")
        
        return results
    
    async def _crawl_recursive(self, start_url: str, max_depth: int = 3, max_urls: int = 100):
        """Recursively crawl website"""
        to_visit = [(start_url, 0)]
        base_domain = urlparse(start_url).netloc
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            
            while to_visit and len(self.visited_urls) < max_urls:
                url, depth = to_visit.pop(0)
                
                if url in self.visited_urls or depth > max_depth:
                    continue
                
                # Only crawl same domain
                if urlparse(url).netloc != base_domain:
                    continue
                
                self.visited_urls.add(url)
                self.discovered_urls.add(url)
                
                try:
                    self.log_info(f"Crawling: {url} (depth: {depth})")
                    async with session.get(url, allow_redirects=True) as response:
                        if response.status != 200:
                            continue
                        
                        content_type = response.headers.get('Content-Type', '')
                        
                        # Handle HTML
                        if 'text/html' in content_type:
                            html = await response.text()
                            await self._parse_html(url, html, to_visit, depth, base_domain)
                        
                        # Handle JSON (API responses)
                        elif 'application/json' in content_type:
                            json_data = await response.text()
                            self._extract_api_endpoint(url, 'GET', json_data)
                        
                except asyncio.TimeoutError:
                    self.log_warning(f"Timeout crawling {url}")
                except Exception as e:
                    self.log_warning(f"Error crawling {url}: {str(e)}")
    
    async def _parse_html(self, url: str, html: str, to_visit: List, depth: int, base_domain: str):
        """Parse HTML and extract links, forms, parameters"""
        soup = BeautifulSoup(html, 'lxml')
        
        # Extract links
        for link in soup.find_all('a', href=True):
            href = link['href']
            absolute_url = urljoin(url, href)
            
            # Normalize URL (remove fragments)
            parsed = urlparse(absolute_url)
            normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ''))
            
            if urlparse(normalized).netloc == base_domain:
                self.discovered_urls.add(normalized)
                
                # Extract parameters from URL
                if parsed.query:
                    self._extract_url_parameters(normalized, parsed.query)
                
                # Add to crawl queue
                if normalized not in self.visited_urls:
                    to_visit.append((normalized, depth + 1))
        
        # Extract forms and their parameters
        for form in soup.find_all('form'):
            form_data = self._parse_form(url, form)
            self.forms.append(form_data)
            
            # Store form parameters
            form_action = form.get('action', url)
            form_url = urljoin(url, form_action)
            
            if form_url not in self.parameters:
                self.parameters[form_url] = []
            
            self.parameters[form_url].extend(form_data['parameters'])
        
        # Extract script sources (for JS analysis)
        for script in soup.find_all('script', src=True):
            script_url = urljoin(url, script['src'])
            self.discovered_urls.add(script_url)
    
    def _extract_url_parameters(self, url: str, query_string: str):
        """Extract parameters from URL query string"""
        parsed_params = parse_qs(query_string)
        
        endpoint_info = {
            "url": url,
            "method": "GET",
            "parameters": [
                {
                    "name": param,
                    "type": "query",
                    "example_value": values[0] if values else None
                }
                for param, values in parsed_params.items()
            ]
        }
        
        self.endpoints.append(endpoint_info)
        self.parameters[url] = endpoint_info['parameters']
    
    def _parse_form(self, page_url: str, form) -> Dict:
        """Parse HTML form and extract parameters"""
        form_action = form.get('action', '')
        form_method = form.get('method', 'GET').upper()
        form_url = urljoin(page_url, form_action) if form_action else page_url
        
        parameters = []
        
        # Extract input fields
        for input_field in form.find_all('input'):
            param_name = input_field.get('name')
            param_type = input_field.get('type', 'text')
            param_value = input_field.get('value', '')
            
            if param_name:
                parameters.append({
                    "name": param_name,
                    "type": param_type,
                    "default_value": param_value
                })
        
        # Extract textarea fields
        for textarea in form.find_all('textarea'):
            param_name = textarea.get('name')
            if param_name:
                parameters.append({
                    "name": param_name,
                    "type": "textarea",
                    "default_value": textarea.get_text()
                })
        
        # Extract select fields
        for select in form.find_all('select'):
            param_name = select.get('name')
            options = [opt.get('value', opt.get_text()) for opt in select.find_all('option')]
            
            if param_name:
                parameters.append({
                    "name": param_name,
                    "type": "select",
                    "options": options
                })
        
        return {
            "url": form_url,
            "method": form_method,
            "action": form_action,
            "parameters": parameters,
            "found_on": page_url
        }
    
    async def _extract_js_endpoints(self, base_url: str):
        """Extract API endpoints from JavaScript files"""
        self.log_info("Analyzing JavaScript for API endpoints...")
        
        js_urls = [url for url in self.discovered_urls if url.endswith('.js')]
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            
            for js_url in js_urls[:10]:  # Limit to first 10 JS files
                try:
                    async with session.get(js_url) as response:
                        if response.status == 200:
                            js_content = await response.text()
                            self._parse_js_for_endpoints(js_content, base_url)
                except Exception as e:
                    self.log_warning(f"Error analyzing {js_url}: {str(e)}")
    
    def _parse_js_for_endpoints(self, js_content: str, base_url: str):
        """Parse JavaScript content for API endpoints"""
        # Common API patterns
        patterns = [
            r'["\'](\/api\/[\w\/\-]+)["\']',  # /api/...
            r'["\'](\/v\d+\/[\w\/\-]+)["\']',  # /v1/...
            r'fetch\(["\']([^"\']+)["\']',  # fetch('...')
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',  # axios.get('...')
            r'\.get\(["\']([^"\']+)["\']',  # .get('...')
            r'\.post\(["\']([^"\']+)["\']',  # .post('...')
            r'url:\s*["\']([^"\']+)["\']',  # url: '...'
        ]
        
        found_endpoints = set()
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if match.startswith('/'):
                    endpoint = urljoin(base_url, match)
                    found_endpoints.add(endpoint)
        
        # Store as API endpoints
        for endpoint in found_endpoints:
            self.api_endpoints.append({
                "url": endpoint,
                "method": "UNKNOWN",
                "source": "javascript"
            })
            self.discovered_urls.add(endpoint)
    
    def _extract_api_endpoint(self, url: str, method: str, json_content: str):
        """Extract and store API endpoint information"""
        try:
            data = json.loads(json_content)
            
            # Extract parameters from JSON
            params = self._extract_json_keys(data)
            
            api_info = {
                "url": url,
                "method": method,
                "type": "json_api",
                "parameters": params
            }
            
            self.api_endpoints.append(api_info)
            self.parameters[url] = params
            
        except json.JSONDecodeError:
            pass
    
    def _extract_json_keys(self, data: Any, prefix: str = '') -> List[Dict]:
        """Recursively extract keys from JSON data"""
        params = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                param_name = f"{prefix}.{key}" if prefix else key
                param_type = type(value).__name__
                
                params.append({
                    "name": param_name,
                    "type": param_type,
                    "example_value": str(value)[:50] if not isinstance(value, (dict, list)) else None
                })
                
                # Recurse for nested objects (limit depth)
                if isinstance(value, dict) and prefix.count('.') < 2:
                    params.extend(self._extract_json_keys(value, param_name))
        
        elif isinstance(data, list) and data:
            # Analyze first item in list
            if isinstance(data[0], dict):
                params.extend(self._extract_json_keys(data[0], f"{prefix}[]"))
        
        return params
