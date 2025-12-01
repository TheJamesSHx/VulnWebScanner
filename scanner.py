#!/usr/bin/env python3
"""
VulnWebScanner - Professional Web Application Security Scanner
Main entry point for automated penetration testing
"""

import argparse
import sys
import asyncio
from pathlib import Path
from core.orchestrator import ScanOrchestrator
from core.config_loader import ConfigLoader
from utils.logger import setup_logger
from utils.validators import validate_target

VERSION = "2.0.0"

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description=f"VulnWebScanner v{VERSION} - Professional Web Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target scan
  python scanner.py -t https://example.com -o results/
  
  # Batch scan from config
  python scanner.py -c config/targets.yaml -o results/
  
  # Full scan with all modules
  python scanner.py -t https://example.com --full -o results/
  
  # Specific modules only
  python scanner.py -t https://example.com -m recon,owasp -o results/
        """
    )
    
    parser.add_argument("-t", "--target", help="Target URL or IP")
    parser.add_argument("-c", "--config", help="Path to targets configuration file")
    parser.add_argument("-o", "--output", required=True, help="Output directory for results")
    parser.add_argument("-m", "--modules", help="Comma-separated list of modules (recon,owasp,exploitation)")
    parser.add_argument("--full", action="store_true", help="Run full comprehensive scan")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=int, default=300, help="Scan timeout in seconds")
    parser.add_argument("--format", choices=["html", "json", "pdf", "all"], default="all", help="Report format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version=f"VulnWebScanner {VERSION}")
    
    return parser.parse_args()

async def main():
    """Main execution function"""
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logger(verbose=args.verbose)
    logger.info(f"VulnWebScanner v{VERSION} - Professional Penetration Testing Tool")
    
    # Validate inputs
    if not args.target and not args.config:
        logger.error("Either --target or --config must be specified")
        sys.exit(1)
    
    # Load configuration
    config_loader = ConfigLoader()
    
    if args.config:
        targets = config_loader.load_targets(args.config)
    else:
        if not validate_target(args.target):
            logger.error(f"Invalid target: {args.target}")
            sys.exit(1)
        targets = [{"url": args.target, "name": "single_target"}]
    
    tools_config = config_loader.load_tools_config("config/tools_config.yaml")
    
    # Initialize orchestrator
    orchestrator = ScanOrchestrator(
        output_dir=args.output,
        threads=args.threads,
        timeout=args.timeout,
        tools_config=tools_config,
        report_format=args.format
    )
    
    # Determine modules to run
    if args.full:
        modules = ["passive_recon", "active_recon", "owasp_scanning", "exploitation"]
    elif args.modules:
        modules = [m.strip() for m in args.modules.split(",")]
    else:
        modules = ["passive_recon", "active_recon", "owasp_scanning"]
    
    logger.info(f"Scanning {len(targets)} target(s) with modules: {', '.join(modules)}")
    
    # Execute scans
    try:
        await orchestrator.run_scans(targets, modules)
        logger.info("All scans completed successfully")
        logger.info(f"Reports generated in: {args.output}")
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)
