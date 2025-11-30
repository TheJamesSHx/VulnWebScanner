#!/usr/bin/env python3
"""Command-line interface for VulnWebScanner."""

import asyncio
import click
import sys
from pathlib import Path
from loguru import logger
from tabulate import tabulate
from datetime import datetime

from core import ScanEngine

# Configure logger
logger.remove()
logger.add(sys.stderr, format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")
logger.add("logs/scanner.log", rotation="10 MB", retention="30 days")


@click.group()
@click.version_option(version="1.0.0", prog_name="VulnWebScanner")
def cli():
    """VulnWebScanner - Advanced Web Vulnerability Scanner
    
    Built on bug bounty methodologies and OWASP Top 10 2021.
    """
    # Ensure required directories exist
    Path("logs").mkdir(exist_ok=True)
    Path("data").mkdir(exist_ok=True)
    Path("reports").mkdir(exist_ok=True)


@cli.command()
@click.option('--target', '-t', required=True, help='Target URL or domain')
@click.option('--scan-type', '-s', type=click.Choice(['full', 'recon', 'owasp']), 
              default='full', help='Type of scan to perform')
@click.option('--modules', '-m', multiple=True, help='Specific modules to run')
@click.option('--config', '-c', default='config/scanner_config.yaml', 
              help='Path to configuration file')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(target, scan_type, modules, config, verbose):
    """Start a new vulnerability scan.
    
    Examples:
        vulnscanner scan -t https://example.com
        vulnscanner scan -t example.com --scan-type recon
        vulnscanner scan -t https://api.example.com --modules a03_injection,a10_ssrf
    """
    if verbose:
        logger.level("DEBUG")
    
    click.echo(click.style("\n🔍 VulnWebScanner - Starting scan...", fg='cyan', bold=True))
    click.echo(f"Target: {target}")
    click.echo(f"Type: {scan_type}")
    
    try:
        # Initialize scan engine
        engine = ScanEngine(config)
        
        # Convert modules tuple to list or None
        module_list = list(modules) if modules else None
        
        # Run scan
        scan_id = asyncio.run(engine.start_scan(
            target=target,
            modules=module_list,
            scan_type=scan_type
        ))
        
        click.echo(click.style(f"\n✓ Scan completed successfully!", fg='green', bold=True))
        click.echo(f"Scan ID: {scan_id}")
        click.echo(f"\nView results: vulnscanner report --scan-id {scan_id}")
        
    except KeyboardInterrupt:
        click.echo(click.style("\n⚠ Scan interrupted by user", fg='yellow'))
        sys.exit(1)
    except Exception as e:
        click.echo(click.style(f"\n✗ Scan failed: {str(e)}", fg='red', bold=True))
        logger.exception("Scan error")
        sys.exit(1)


@cli.command()
@click.option('--target', '-t', required=True, help='Target domain')
@click.option('--passive', is_flag=True, help='Passive reconnaissance only')
@click.option('--active', is_flag=True, help='Active reconnaissance only')
@click.option('--config', '-c', default='config/scanner_config.yaml', help='Config file path')
def recon(target, passive, active, config):
    """Run reconnaissance on target.
    
    Examples:
        vulnscanner recon -t example.com
        vulnscanner recon -t example.com --passive
        vulnscanner recon -t example.com --active
    """
    click.echo(click.style("\n🔎 Starting reconnaissance...", fg='cyan', bold=True))
    click.echo(f"Target: {target}")
    
    try:
        engine = ScanEngine(config)
        
        # Determine scan type based on flags
        if not passive and not active:
            scan_type = 'recon'  # Both
        else:
            scan_type = 'recon'
        
        scan_id = asyncio.run(engine.start_scan(
            target=target,
            scan_type=scan_type
        ))
        
        click.echo(click.style(f"\n✓ Reconnaissance completed!", fg='green', bold=True))
        click.echo(f"Scan ID: {scan_id}")
        
    except Exception as e:
        click.echo(click.style(f"\n✗ Recon failed: {str(e)}", fg='red'))
        sys.exit(1)


@cli.command()
@click.option('--scan-id', '-i', type=int, required=True, help='Scan ID to generate report for')
@click.option('--format', '-f', type=click.Choice(['html', 'json', 'pdf', 'text']),
              multiple=True, default=['text'], help='Report format(s)')
@click.option('--output', '-o', help='Output file path')
def report(scan_id, format, output):
    """Generate report for a completed scan.
    
    Examples:
        vulnscanner report --scan-id 1
        vulnscanner report -i 1 --format html --format json
        vulnscanner report -i 1 -f pdf -o report.pdf
    """
    click.echo(click.style(f"\n📊 Generating report for scan {scan_id}...", fg='cyan', bold=True))
    
    try:
        engine = ScanEngine()
        scan = engine.get_scan_status(scan_id)
        
        if not scan:
            click.echo(click.style(f"✗ Scan {scan_id} not found", fg='red'))
            sys.exit(1)
        
        results = engine.get_scan_results(scan_id)
        
        if 'text' in format:
            _print_text_report(scan, results)
        
        # Placeholder for other formats
        if 'html' in format:
            click.echo("📄 HTML report: Coming soon")
        if 'json' in format:
            click.echo("📄 JSON report: Coming soon")
        if 'pdf' in format:
            click.echo("📄 PDF report: Coming soon")
        
    except Exception as e:
        click.echo(click.style(f"✗ Report generation failed: {str(e)}", fg='red'))
        sys.exit(1)


def _print_text_report(scan: dict, results: list):
    """Print text format report to console."""
    click.echo("\n" + "="*80)
    click.echo(click.style("SCAN REPORT", fg='cyan', bold=True).center(80))
    click.echo("="*80)
    
    # Scan information
    click.echo(f"\nScan ID: {scan['id']}")
    click.echo(f"Target: {scan['target']}")
    click.echo(f"Type: {scan['scan_type']}")
    click.echo(f"Status: {scan['status']}")
    click.echo(f"Started: {scan['start_time']}")
    click.echo(f"Ended: {scan['end_time'] or 'N/A'}")
    
    # Results summary
    click.echo(f"\n{click.style('Results', fg='yellow', bold=True)}")
    click.echo(f"Total findings: {len(results)}")
    
    if results:
        # Group by severity
        severity_counts = {}
        for r in results:
            sev = r.get('severity', 'info')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        if severity_counts:
            click.echo("\nBy severity:")
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                if sev in severity_counts:
                    color = {'critical': 'red', 'high': 'red', 'medium': 'yellow', 
                            'low': 'blue', 'info': 'white'}[sev]
                    click.echo(f"  {click.style(sev.upper(), fg=color)}: {severity_counts[sev]}")
    
    click.echo("\n" + "="*80 + "\n")


@cli.command()
@click.option('--limit', '-l', default=20, help='Number of scans to list')
def list(limit):
    """List recent scans.
    
    Example:
        vulnscanner list
        vulnscanner list --limit 50
    """
    try:
        engine = ScanEngine()
        scans = engine.list_scans(limit)
        
        if not scans:
            click.echo("No scans found.")
            return
        
        # Prepare table data
        headers = ['ID', 'Target', 'Type', 'Status', 'Started', 'Duration']
        rows = []
        
        for scan in scans:
            start = datetime.fromisoformat(scan['start_time']) if scan['start_time'] else None
            end = datetime.fromisoformat(scan['end_time']) if scan['end_time'] else None
            duration = str(end - start).split('.')[0] if start and end else 'N/A'
            
            rows.append([
                scan['id'],
                scan['target'][:40],
                scan['scan_type'],
                scan['status'],
                scan['start_time'][:19] if scan['start_time'] else 'N/A',
                duration
            ])
        
        click.echo("\n" + tabulate(rows, headers=headers, tablefmt='grid'))
        click.echo(f"\nTotal: {len(scans)} scan(s)\n")
        
    except Exception as e:
        click.echo(click.style(f"✗ Failed to list scans: {str(e)}", fg='red'))
        sys.exit(1)


@cli.command()
@click.option('--scan-id', '-i', type=int, required=True, help='Scan ID to check')
def status(scan_id):
    """Check status of a running scan.
    
    Example:
        vulnscanner status --scan-id 1
    """
    try:
        engine = ScanEngine()
        scan = engine.get_scan_status(scan_id)
        
        if not scan:
            click.echo(click.style(f"✗ Scan {scan_id} not found", fg='red'))
            sys.exit(1)
        
        click.echo(f"\nScan ID: {scan['id']}")
        click.echo(f"Target: {scan['target']}")
        click.echo(f"Status: {click.style(scan['status'], fg='green' if scan['status'] == 'completed' else 'yellow')}")
        click.echo(f"Started: {scan['start_time']}")
        
        if scan['status'] in ['completed', 'failed', 'stopped']:
            click.echo(f"Ended: {scan['end_time']}")
        
        if scan.get('error'):
            click.echo(click.style(f"\nError: {scan['error']}", fg='red'))
        
        click.echo()
        
    except Exception as e:
        click.echo(click.style(f"✗ Failed to get status: {str(e)}", fg='red'))
        sys.exit(1)


if __name__ == '__main__':
    cli()