"""Main scanning engine orchestrator."""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from loguru import logger
import yaml

from .async_scanner import AsyncScanner
from .database import Database, Scan, ScanResult


class ScanEngine:
    """Main scanning engine that coordinates all modules."""

    def __init__(self, config_path: str = "config/scanner_config.yaml"):
        """Initialize the scan engine.
        
        Args:
            config_path: Path to scanner configuration file
        """
        self.config = self._load_config(config_path)
        self.db = Database(self.config['database'])
        self.async_scanner = AsyncScanner(self.config)
        self.scan_id = None
        self.results = []
        
        logger.info(f"Scanner initialized: {self.config['general']['scanner_name']} v{self.config['general']['version']}")

    def _load_config(self, config_path: str) -> Dict:
        """Load scanner configuration from YAML file.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Configuration dictionary
        """
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.debug(f"Configuration loaded from {config_path}")
            return config
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_path}")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML configuration: {e}")
            raise

    async def start_scan(self, target: str, modules: Optional[List[str]] = None,
                        scan_type: str = "full") -> int:
        """Start a new vulnerability scan.
        
        Args:
            target: Target URL or domain
            modules: List of modules to run (None = all enabled modules)
            scan_type: Type of scan (full, recon, owasp)
            
        Returns:
            Scan ID
        """
        logger.info(f"Starting {scan_type} scan on target: {target}")
        
        # Create scan record in database
        scan = Scan(
            target=target,
            scan_type=scan_type,
            status="running",
            start_time=datetime.utcnow(),
            config=self.config
        )
        self.scan_id = self.db.create_scan(scan)
        logger.info(f"Scan created with ID: {self.scan_id}")
        
        try:
            # Determine which modules to run
            if modules is None:
                modules = self._get_enabled_modules(scan_type)
            
            logger.info(f"Running modules: {', '.join(modules)}")
            
            # Execute scan phases
            if scan_type in ["full", "recon"]:
                await self._run_reconnaissance(target)
            
            if scan_type in ["full", "owasp"]:
                await self._run_vulnerability_scan(target, modules)
            
            # Update scan status
            self.db.update_scan_status(self.scan_id, "completed")
            logger.success(f"Scan {self.scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            self.db.update_scan_status(self.scan_id, "failed", error=str(e))
            raise
        
        return self.scan_id

    def _get_enabled_modules(self, scan_type: str) -> List[str]:
        """Get list of enabled modules based on scan type and config.
        
        Args:
            scan_type: Type of scan
            
        Returns:
            List of enabled module names
        """
        modules = []
        
        if scan_type in ["full", "recon"]:
            if self.config['recon']['passive']['enabled']:
                modules.extend(['subdomain_enum', 'asset_discovery', 'tech_detection'])
            if self.config['recon']['active']['enabled']:
                modules.extend(['port_scanner', 'crawler', 'directory_brute'])
        
        if scan_type in ["full", "owasp"]:
            for key, value in self.config['owasp'].items():
                if value.get('enabled', False):
                    modules.append(key)
        
        return modules

    async def _run_reconnaissance(self, target: str):
        """Execute reconnaissance phase.
        
        Args:
            target: Target URL or domain
        """
        logger.info("Starting reconnaissance phase...")
        
        recon_results = {
            'subdomains': [],
            'assets': [],
            'technologies': [],
            'ports': [],
            'urls': [],
            'directories': []
        }
        
        # Passive reconnaissance
        if self.config['recon']['passive']['enabled']:
            logger.info("Running passive reconnaissance...")
            # Placeholder for actual module calls
            # recon_results['subdomains'] = await subdomain_enum.run(target)
            # recon_results['technologies'] = await tech_detection.run(target)
        
        # Active reconnaissance  
        if self.config['recon']['active']['enabled']:
            logger.info("Running active reconnaissance...")
            # Placeholder for actual module calls
            # recon_results['ports'] = await port_scanner.run(target)
            # recon_results['urls'] = await crawler.run(target)
        
        # Store recon results
        self._save_results("reconnaissance", recon_results)
        logger.success("Reconnaissance phase completed")

    async def _run_vulnerability_scan(self, target: str, modules: List[str]):
        """Execute vulnerability scanning phase.
        
        Args:
            target: Target URL or domain
            modules: List of vulnerability modules to run
        """
        logger.info("Starting vulnerability scanning phase...")
        
        # Run each enabled OWASP module
        for module in modules:
            if module.startswith('a0'):
                logger.info(f"Running module: {module}")
                # Placeholder for actual module execution
                # results = await owasp_module.run(target)
                # self._save_results(module, results)
        
        logger.success("Vulnerability scanning phase completed")

    def _save_results(self, module_name: str, results: Any):
        """Save scan results to database.
        
        Args:
            module_name: Name of the module that produced results
            results: Results data
        """
        if not results:
            return
            
        result = ScanResult(
            scan_id=self.scan_id,
            module=module_name,
            results=results,
            timestamp=datetime.utcnow()
        )
        self.db.save_result(result)
        logger.debug(f"Results saved for module: {module_name}")

    def get_scan_status(self, scan_id: int) -> Dict:
        """Get status of a scan.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            Scan status dictionary
        """
        return self.db.get_scan(scan_id)

    def get_scan_results(self, scan_id: int) -> List[Dict]:
        """Get all results for a scan.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            List of scan results
        """
        return self.db.get_results(scan_id)

    def list_scans(self, limit: int = 50) -> List[Dict]:
        """List recent scans.
        
        Args:
            limit: Maximum number of scans to return
            
        Returns:
            List of scan records
        """
        return self.db.list_scans(limit)

    async def stop_scan(self, scan_id: int):
        """Stop a running scan.
        
        Args:
            scan_id: Scan ID to stop
        """
        logger.warning(f"Stopping scan {scan_id}...")
        self.db.update_scan_status(scan_id, "stopped")
        # Additional cleanup logic here
        logger.info(f"Scan {scan_id} stopped")