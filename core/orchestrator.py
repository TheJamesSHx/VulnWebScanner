"""Scan Orchestrator - Coordinates all scanning modules and workflows"""

import asyncio
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from core.tool_manager import ToolManager
from modules.recon.passive.osint import OSINTModule
from modules.recon.passive.dns_analysis import DNSAnalysisModule
from modules.recon.active.port_scanner import PortScannerModule
from modules.recon.active.crawler import CrawlerModule
from modules.exploitation.owasp.a03_injection import InjectionScanner
from modules.exploitation.owasp.a03_xss import XSSScanner
from modules.exploitation.owasp.a05_misconfiguration import MisconfigurationScanner
from modules.exploitation.owasp.a07_auth_failures import AuthFailureScanner
from reporting.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

class ScanOrchestrator:
    """Orchestrates pentesting scans across multiple modules"""
    
    def __init__(self, output_dir: str, threads: int = 10, timeout: int = 300,
                 tools_config: Dict = None, report_format: str = "all"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.threads = threads
        self.timeout = timeout
        self.report_format = report_format
        
        # Initialize tool manager
        self.tool_manager = ToolManager(tools_config or {})
        
        # Initialize modules
        self.modules = {
            "passive_recon": [
                OSINTModule(self.tool_manager),
                DNSAnalysisModule(self.tool_manager)
            ],
            "active_recon": [
                PortScannerModule(self.tool_manager),
                CrawlerModule(self.tool_manager)
            ],
            "owasp_scanning": [
                InjectionScanner(self.tool_manager),
                XSSScanner(self.tool_manager),
                MisconfigurationScanner(self.tool_manager),
                AuthFailureScanner(self.tool_manager)
            ]
        }
        
        # Results storage
        self.results = {}
        
    async def run_scans(self, targets: List[Dict], enabled_modules: List[str]):
        """Execute scans for all targets"""
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        logger.info(f"Starting scan batch: {scan_id}")
        
        for target in targets:
            target_name = target.get("name", target["url"])
            logger.info(f"Scanning target: {target_name}")
            
            target_results = {
                "target": target,
                "scan_id": scan_id,
                "start_time": datetime.now().isoformat(),
                "modules": {}
            }
            
            # Run enabled module groups
            for module_group in enabled_modules:
                if module_group not in self.modules:
                    logger.warning(f"Unknown module group: {module_group}")
                    continue
                
                logger.info(f"Running {module_group} modules")
                group_results = await self._run_module_group(
                    self.modules[module_group],
                    target
                )
                target_results["modules"][module_group] = group_results
            
            target_results["end_time"] = datetime.now().isoformat()
            self.results[target_name] = target_results
            
            # Generate report for this target
            await self._generate_report(target_name, target_results)
        
        logger.info("All scans completed")
    
    async def _run_module_group(self, modules: List, target: Dict) -> Dict:
        """Run a group of modules concurrently"""
        tasks = []
        for module in modules:
            task = asyncio.create_task(self._run_module_safe(module, target))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine results
        combined = {}
        for module, result in zip(modules, results):
            module_name = module.__class__.__name__
            if isinstance(result, Exception):
                logger.error(f"Module {module_name} failed: {str(result)}")
                combined[module_name] = {"error": str(result)}
            else:
                combined[module_name] = result
        
        return combined
    
    async def _run_module_safe(self, module, target: Dict) -> Dict:
        """Run a single module with error handling"""
        try:
            logger.info(f"Executing {module.__class__.__name__}")
            result = await asyncio.wait_for(
                module.scan(target),
                timeout=self.timeout
            )
            return result
        except asyncio.TimeoutError:
            logger.error(f"{module.__class__.__name__} timed out")
            return {"error": "Scan timed out"}
        except Exception as e:
            logger.error(f"{module.__class__.__name__} error: {str(e)}")
            return {"error": str(e)}
    
    async def _generate_report(self, target_name: str, results: Dict):
        """Generate scan report"""
        report_gen = ReportGenerator(self.output_dir)
        
        formats = []
        if self.report_format == "all":
            formats = ["html", "json", "pdf"]
        else:
            formats = [self.report_format]
        
        for fmt in formats:
            try:
                output_path = await report_gen.generate(
                    results,
                    target_name,
                    fmt
                )
                logger.info(f"Report generated: {output_path}")
            except Exception as e:
                logger.error(f"Report generation failed ({fmt}): {str(e)}")
