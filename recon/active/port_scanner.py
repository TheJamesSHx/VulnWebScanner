"""Port scanning using python-nmap."""

import asyncio
import nmap
from typing import Dict, List
from loguru import logger


class PortScanner:
    """Network port scanner for service discovery."""

    def __init__(self, config: Dict = None):
        """Initialize port scanner.
        
        Args:
            config: Scanner configuration
        """
        self.config = config or {}
        self.nm = nmap.PortScanner()

    async def scan(self, target: str, ports: str = None, scan_type: str = 'connect') -> Dict:
        """Scan ports on target.
        
        Args:
            target: Target IP or hostname
            ports: Port range (e.g., '80,443,8080' or '1-1000')
            scan_type: Type of scan (connect, syn, ack)
            
        Returns:
            Dictionary with scan results
        """
        logger.info(f"Starting port scan on {target}")
        
        if ports is None:
            ports = self.config.get('ports', '80,443,8080,8443,3000,5000,8000')
        
        # Map scan types to nmap arguments
        scan_args = {
            'connect': '-sT',  # TCP connect scan
            'syn': '-sS',      # SYN stealth scan (requires root)
            'ack': '-sA',      # ACK scan
            'udp': '-sU'       # UDP scan
        }
        
        nmap_args = f"{scan_args.get(scan_type, '-sT')} -p {ports} -sV --version-intensity 5"
        
        try:
            # Run scan in thread to avoid blocking
            await asyncio.to_thread(self.nm.scan, target, arguments=nmap_args)
            
            results = {
                'target': target,
                'scan_type': scan_type,
                'ports_scanned': ports,
                'hosts': {}
            }
            
            # Parse results
            for host in self.nm.all_hosts():
                host_info = {
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'protocols': {},
                    'open_ports': [],
                    'services': []
                }
                
                for proto in self.nm[host].all_protocols():
                    ports_list = sorted(self.nm[host][proto].keys())
                    host_info['protocols'][proto] = ports_list
                    
                    for port in ports_list:
                        port_info = self.nm[host][proto][port]
                        
                        if port_info['state'] == 'open':
                            host_info['open_ports'].append(port)
                            
                            service = {
                                'port': port,
                                'protocol': proto,
                                'state': port_info['state'],
                                'service': port_info.get('name', 'unknown'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'extrainfo': port_info.get('extrainfo', ''),
                                'cpe': port_info.get('cpe', '')
                            }
                            host_info['services'].append(service)
                
                results['hosts'][host] = host_info
            
            total_open = sum(len(h['open_ports']) for h in results['hosts'].values())
            logger.success(f"Port scan completed: {total_open} open ports found")
            
            return results
            
        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan error: {str(e)}")
            return {'error': str(e), 'target': target}
        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
            return {'error': str(e), 'target': target}

    async def quick_scan(self, target: str) -> Dict:
        """Quick scan of common ports.
        
        Args:
            target: Target to scan
            
        Returns:
            Scan results
        """
        common_ports = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080'
        return await self.scan(target, ports=common_ports, scan_type='connect')

    async def full_scan(self, target: str) -> Dict:
        """Full TCP port scan (1-65535).
        
        Args:
            target: Target to scan
            
        Returns:
            Scan results
        """
        logger.warning(f"Starting full port scan on {target} - this may take a while")
        return await self.scan(target, ports='1-65535', scan_type='connect')