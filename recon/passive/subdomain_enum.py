"""Subdomain enumeration using multiple passive sources."""

import asyncio
import aiohttp
import dns.resolver
from typing import List, Set, Dict
from loguru import logger
import re
import json
from urllib.parse import quote


class SubdomainEnumerator:
    """Enumerate subdomains using passive techniques."""

    def __init__(self, async_scanner):
        """Initialize subdomain enumerator.
        
        Args:
            async_scanner: AsyncScanner instance
        """
        self.scanner = async_scanner
        self.subdomains: Set[str] = set()

    async def enumerate(self, domain: str, sources: List[str] = None) -> Dict:
        """Enumerate subdomains from multiple sources.
        
        Args:
            domain: Target domain
            sources: List of sources to use (default: all)
            
        Returns:
            Dictionary with subdomains and metadata
        """
        logger.info(f"Starting subdomain enumeration for {domain}")
        
        if sources is None:
            sources = ['crtsh', 'virustotal', 'threatcrowd', 'hackertarget', 'dns']
        
        # Run all sources concurrently
        tasks = []
        if 'crtsh' in sources:
            tasks.append(self._crtsh(domain))
        if 'virustotal' in sources:
            tasks.append(self._virustotal(domain))
        if 'threatcrowd' in sources:
            tasks.append(self._threatcrowd(domain))
        if 'hackertarget' in sources:
            tasks.append(self._hackertarget(domain))
        if 'dns' in sources:
            tasks.append(self._dns_bruteforce(domain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Merge all subdomains
        for result in results:
            if isinstance(result, set):
                self.subdomains.update(result)
        
        # Validate subdomains
        valid_subdomains = await self._validate_subdomains(list(self.subdomains))
        
        logger.success(f"Found {len(valid_subdomains)} valid subdomains for {domain}")
        
        return {
            'domain': domain,
            'total_found': len(self.subdomains),
            'valid_subdomains': len(valid_subdomains),
            'subdomains': sorted(valid_subdomains),
            'sources_used': sources
        }

    async def _crtsh(self, domain: str) -> Set[str]:
        """Query crt.sh certificate transparency logs.
        
        Args:
            domain: Target domain
            
        Returns:
            Set of subdomains
        """
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = await self.scanner.fetch(url)
            
            if response and response['status'] == 200:
                try:
                    data = json.loads(response['content'])
                    for entry in data:
                        name = entry.get('name_value', '')
                        # Handle multiple subdomains in one entry
                        for subdomain in name.split('\n'):
                            subdomain = subdomain.strip()
                            if subdomain and domain in subdomain:
                                # Remove wildcards
                                subdomain = subdomain.replace('*.', '')
                                if self._is_valid_subdomain(subdomain, domain):
                                    subdomains.add(subdomain)
                    logger.debug(f"crt.sh: Found {len(subdomains)} subdomains")
                except json.JSONDecodeError:
                    logger.warning("Failed to parse crt.sh response")
        except Exception as e:
            logger.warning(f"crt.sh query failed: {str(e)}")
        
        return subdomains

    async def _virustotal(self, domain: str) -> Set[str]:
        """Query VirusTotal (requires API key for full access).
        
        Args:
            domain: Target domain
            
        Returns:
            Set of subdomains
        """
        subdomains = set()
        try:
            # Public endpoint (limited)
            url = f"https://www.virustotal.com/ui/domains/{domain}/subdomains?limit=40"
            response = await self.scanner.fetch(url)
            
            if response and response['status'] == 200:
                try:
                    data = json.loads(response['content'])
                    if 'data' in data:
                        for entry in data['data']:
                            subdomain = entry.get('id', '')
                            if subdomain and self._is_valid_subdomain(subdomain, domain):
                                subdomains.add(subdomain)
                    logger.debug(f"VirusTotal: Found {len(subdomains)} subdomains")
                except json.JSONDecodeError:
                    logger.warning("Failed to parse VirusTotal response")
        except Exception as e:
            logger.warning(f"VirusTotal query failed: {str(e)}")
        
        return subdomains

    async def _threatcrowd(self, domain: str) -> Set[str]:
        """Query ThreatCrowd API.
        
        Args:
            domain: Target domain
            
        Returns:
            Set of subdomains
        """
        subdomains = set()
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
            response = await self.scanner.fetch(url)
            
            if response and response['status'] == 200:
                try:
                    data = json.loads(response['content'])
                    if data.get('response_code') == '1' and 'subdomains' in data:
                        for subdomain in data['subdomains']:
                            if self._is_valid_subdomain(subdomain, domain):
                                subdomains.add(subdomain)
                    logger.debug(f"ThreatCrowd: Found {len(subdomains)} subdomains")
                except json.JSONDecodeError:
                    logger.warning("Failed to parse ThreatCrowd response")
        except Exception as e:
            logger.warning(f"ThreatCrowd query failed: {str(e)}")
        
        return subdomains

    async def _hackertarget(self, domain: str) -> Set[str]:
        """Query HackerTarget API.
        
        Args:
            domain: Target domain
            
        Returns:
            Set of subdomains
        """
        subdomains = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = await self.scanner.fetch(url)
            
            if response and response['status'] == 200:
                content = response['content']
                if 'error' not in content.lower():
                    for line in content.split('\n'):
                        if ',' in line:
                            subdomain = line.split(',')[0].strip()
                            if self._is_valid_subdomain(subdomain, domain):
                                subdomains.add(subdomain)
                    logger.debug(f"HackerTarget: Found {len(subdomains)} subdomains")
        except Exception as e:
            logger.warning(f"HackerTarget query failed: {str(e)}")
        
        return subdomains

    async def _dns_bruteforce(self, domain: str, wordlist: List[str] = None) -> Set[str]:
        """DNS bruteforce with common subdomain names.
        
        Args:
            domain: Target domain
            wordlist: List of subdomain names to try
            
        Returns:
            Set of valid subdomains
        """
        subdomains = set()
        
        if wordlist is None:
            # Common subdomain names
            wordlist = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
                'admin', 'api', 'dev', 'staging', 'test', 'portal', 'app', 'mobile',
                'vpn', 'remote', 'blog', 'shop', 'store', 'support', 'help', 'docs',
                'beta', 'demo', 'sandbox', 'cdn', 'static', 'assets', 'images', 'img'
            ]
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        for name in wordlist:
            subdomain = f"{name}.{domain}"
            try:
                await asyncio.to_thread(resolver.resolve, subdomain, 'A')
                subdomains.add(subdomain)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            except Exception:
                pass
        
        logger.debug(f"DNS Bruteforce: Found {len(subdomains)} subdomains")
        return subdomains

    async def _validate_subdomains(self, subdomains: List[str]) -> List[str]:
        """Validate subdomains by checking DNS resolution.
        
        Args:
            subdomains: List of subdomains to validate
            
        Returns:
            List of valid subdomains
        """
        valid = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        for subdomain in subdomains:
            try:
                await asyncio.to_thread(resolver.resolve, subdomain, 'A')
                valid.append(subdomain)
            except:
                pass
        
        return valid

    def _is_valid_subdomain(self, subdomain: str, domain: str) -> bool:
        """Check if subdomain is valid.
        
        Args:
            subdomain: Subdomain to check
            domain: Parent domain
            
        Returns:
            True if valid, False otherwise
        """
        if not subdomain or not domain:
            return False
        
        # Must contain parent domain
        if domain not in subdomain:
            return False
        
        # Basic format validation
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-\.]*[a-zA-Z0-9]\.' + re.escape(domain) + r'$|^' + re.escape(domain) + r'$'
        return bool(re.match(pattern, subdomain))