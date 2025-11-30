"""Asset discovery using OSINT databases (Shodan, Censys, etc.)."""

import asyncio
from typing import Dict, List, Optional
from loguru import logger
import json


class AssetDiscovery:
    """Discover assets using public OSINT databases."""

    def __init__(self, async_scanner, config: Dict = None):
        """Initialize asset discovery.
        
        Args:
            async_scanner: AsyncScanner instance
            config: Configuration dictionary
        """
        self.scanner = async_scanner
        self.config = config or {}
        self.shodan_api_key = self.config.get('shodan_api_key')
        self.censys_api_id = self.config.get('censys_api_id')
        self.censys_api_secret = self.config.get('censys_api_secret')

    async def discover(self, domain: str, include_ips: List[str] = None) -> Dict:
        """Discover assets for a domain.
        
        Args:
            domain: Target domain
            include_ips: Additional IPs to scan
            
        Returns:
            Dictionary with discovered assets
        """
        logger.info(f"Starting asset discovery for {domain}")
        
        assets = {
            'domain': domain,
            'ip_addresses': set(),
            'open_ports': {},
            'services': [],
            'technologies': [],
            'ssl_certificates': [],
            'hostnames': set()
        }
        
        # Resolve domain to IPs
        ips = await self._resolve_domain(domain)
        assets['ip_addresses'].update(ips)
        
        if include_ips:
            assets['ip_addresses'].update(include_ips)
        
        # Query OSINT sources
        tasks = []
        
        if self.shodan_api_key:
            tasks.append(self._query_shodan(domain, list(assets['ip_addresses'])))
        
        if self.censys_api_id and self.censys_api_secret:
            tasks.append(self._query_censys(domain))
        
        # Query public sources
        tasks.append(self._query_public_sources(domain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Merge results
        for result in results:
            if isinstance(result, dict):
                if 'ip_addresses' in result:
                    assets['ip_addresses'].update(result['ip_addresses'])
                if 'ports' in result:
                    assets['open_ports'].update(result['ports'])
                if 'services' in result:
                    assets['services'].extend(result['services'])
                if 'technologies' in result:
                    assets['technologies'].extend(result['technologies'])
        
        # Convert sets to lists for JSON serialization
        assets['ip_addresses'] = sorted(list(assets['ip_addresses']))
        assets['hostnames'] = sorted(list(assets['hostnames']))
        
        logger.success(f"Asset discovery completed: {len(assets['ip_addresses'])} IPs, {len(assets['services'])} services")
        
        return assets

    async def _resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses.
        
        Args:
            domain: Domain to resolve
            
        Returns:
            List of IP addresses
        """
        import dns.resolver
        ips = []
        
        try:
            resolver = dns.resolver.Resolver()
            answers = await asyncio.to_thread(resolver.resolve, domain, 'A')
            for rdata in answers:
                ips.append(str(rdata))
            logger.debug(f"Resolved {domain} to {len(ips)} IP(s)")
        except Exception as e:
            logger.warning(f"Failed to resolve {domain}: {str(e)}")
        
        return ips

    async def _query_shodan(self, domain: str, ips: List[str]) -> Dict:
        """Query Shodan API for asset information.
        
        Args:
            domain: Target domain
            ips: List of IPs to query
            
        Returns:
            Dictionary with Shodan results
        """
        results = {
            'ip_addresses': set(),
            'ports': {},
            'services': [],
            'technologies': []
        }
        
        try:
            # Shodan domain search
            url = f"https://api.shodan.io/dns/domain/{domain}?key={self.shodan_api_key}"
            response = await self.scanner.fetch(url)
            
            if response and response['status'] == 200:
                data = json.loads(response['content'])
                # Parse Shodan data
                if 'data' in data:
                    for record in data.get('data', []):
                        if 'value' in record:
                            results['ip_addresses'].add(record['value'])
            
            # Query each IP
            for ip in ips[:5]:  # Limit to first 5 IPs to avoid rate limits
                url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_api_key}"
                response = await self.scanner.fetch(url)
                
                if response and response['status'] == 200:
                    data = json.loads(response['content'])
                    
                    if 'ports' in data:
                        results['ports'][ip] = data['ports']
                    
                    if 'data' in data:
                        for service in data['data']:
                            results['services'].append({
                                'ip': ip,
                                'port': service.get('port'),
                                'protocol': service.get('transport'),
                                'service': service.get('product'),
                                'version': service.get('version')
                            })
            
            logger.debug(f"Shodan: Found {len(results['services'])} services")
        
        except Exception as e:
            logger.warning(f"Shodan query failed: {str(e)}")
        
        return results

    async def _query_censys(self, domain: str) -> Dict:
        """Query Censys API for asset information.
        
        Args:
            domain: Target domain
            
        Returns:
            Dictionary with Censys results
        """
        results = {
            'ip_addresses': set(),
            'services': [],
            'technologies': []
        }
        
        try:
            # Censys search requires authentication
            import base64
            auth = base64.b64encode(f"{self.censys_api_id}:{self.censys_api_secret}".encode()).decode()
            
            url = f"https://search.censys.io/api/v2/hosts/search?q={domain}"
            headers = {'Authorization': f'Basic {auth}'}
            
            response = await self.scanner.fetch(url, headers=headers)
            
            if response and response['status'] == 200:
                data = json.loads(response['content'])
                # Parse Censys results
                for host in data.get('result', {}).get('hits', []):
                    if 'ip' in host:
                        results['ip_addresses'].add(host['ip'])
                    
                    if 'services' in host:
                        for service in host['services']:
                            results['services'].append({
                                'ip': host.get('ip'),
                                'port': service.get('port'),
                                'service': service.get('service_name'),
                                'protocol': service.get('transport_protocol')
                            })
            
            logger.debug(f"Censys: Found {len(results['ip_addresses'])} IPs")
        
        except Exception as e:
            logger.warning(f"Censys query failed: {str(e)}")
        
        return results

    async def _query_public_sources(self, domain: str) -> Dict:
        """Query free public sources for asset information.
        
        Args:
            domain: Target domain
            
        Returns:
            Dictionary with results
        """
        results = {
            'ip_addresses': set(),
            'technologies': []
        }
        
        try:
            # SecurityTrails (limited free tier)
            url = f"https://api.securitytrails.com/v1/domain/{domain}"
            response = await self.scanner.fetch(url)
            
            if response and response['status'] == 200:
                data = json.loads(response['content'])
                if 'current_dns' in data and 'a' in data['current_dns']:
                    for record in data['current_dns']['a']['values']:
                        if 'ip' in record:
                            results['ip_addresses'].add(record['ip'])
        
        except Exception as e:
            logger.debug(f"Public source query: {str(e)}")
        
        return results