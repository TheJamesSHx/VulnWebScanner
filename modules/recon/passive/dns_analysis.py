"""DNS Analysis Module"""

import asyncio
import dns.resolver
import dns.zone
from typing import Dict, Any, List
from modules.base_module import BaseModule
from utils.validators import extract_domain

class DNSAnalysisModule(BaseModule):
    """DNS reconnaissance and analysis"""
    
    async def scan(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Execute DNS analysis"""
        url = target["url"]
        domain = extract_domain(url)
        
        self.log_info(f"Starting DNS analysis for {domain}")
        
        results = {
            "domain": domain,
            "records": {},
            "zone_transfer": None,
            "nameservers": []
        }
        
        # Query common DNS records
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = await asyncio.to_thread(self._query_dns, domain, record_type)
                if answers:
                    results["records"][record_type] = answers
            except Exception as e:
                self.log_warning(f"DNS query failed for {record_type}: {str(e)}")
        
        # Get nameservers
        if 'NS' in results["records"]:
            results["nameservers"] = results["records"]['NS']
            
            # Try zone transfer on each nameserver
            for ns in results["nameservers"]:
                zone_data = await self._try_zone_transfer(domain, ns)
                if zone_data:
                    results["zone_transfer"] = {
                        "vulnerable": True,
                        "nameserver": ns,
                        "records": zone_data
                    }
                    self.log_warning(f"Zone transfer successful on {ns}!")
                    break
        
        self.log_info("DNS analysis complete")
        return results
    
    def _query_dns(self, domain: str, record_type: str) -> List[str]:
        """Query DNS records (blocking)"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            answers = resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except Exception:
            return []
    
    async def _try_zone_transfer(self, domain: str, nameserver: str) -> List[str]:
        """Attempt DNS zone transfer"""
        try:
            self.log_info(f"Attempting zone transfer from {nameserver}")
            zone_data = await asyncio.to_thread(self._do_zone_transfer, domain, nameserver)
            return zone_data
        except Exception as e:
            self.log_info(f"Zone transfer failed: {str(e)}")
            return []
    
    def _do_zone_transfer(self, domain: str, nameserver: str) -> List[str]:
        """Perform zone transfer (blocking)"""
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=10))
            records = []
            for name, node in zone.nodes.items():
                records.append(str(name))
            return records
        except Exception:
            return []
