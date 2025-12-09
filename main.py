#!/usr/bin/env python3
"""
AutoPenTest - Automated Penetration Testing Orchestrator
Main entry point for the assessment pipeline
"""

import asyncio
import sys
from pathlib import Path
from typing import List, Optional

import click
from loguru import logger

from core.orchestrator import PenTestOrchestrator
from core.config import Config
from core.models import AssessmentScope, AssessmentResult
from utils.banner import print_banner
from utils.validators import validate_target, validate_scope


@click.command()
@click.option('--target', '-t', required=True, help='Target IP, domain, or CIDR range')
@click.option('--scope', '-s', type=click.Path(exists=True), help='Scope configuration file (YAML)')
@click.option('--stages', '-st', help='Comma-separated stages to run (default: all)')
@click.option('--config', '-c', type=click.Path(exists=True), default='config/config.yaml', help='Configuration file')
@click.option('--output', '-o', default='reports', help='Output directory for reports')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--dry-run', is_flag=True, help='Simulate without actual exploitation')
@click.option('--stealth', is_flag=True, help='Enable stealth mode (slower, harder to detect)')
@click.option('--aggressive', is_flag=True, help='Aggressive mode (faster, more detectable)')
def main(
    target: str,
    scope: Optional[str],
    stages: Optional[str],
    config: str,
    output: str,
    verbose: bool,
    dry_run: bool,
    stealth: bool,
    aggressive: bool
):
    """AutoPenTest - Automated Penetration Testing Orchestrator"""
    
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    logger.remove()
    logger.add(sys.stderr, level=log_level, colorize=True)
    logger.add(f"{output}/autopent.log", level="DEBUG", rotation="10 MB")
    
    # Print banner
    print_banner()
    
    # Validate target
    if not validate_target(target):
        logger.error(f"Invalid target: {target}")
        sys.exit(1)
    
    # Load configuration
    try:
        cfg = Config.load(config)
        logger.info(f"Configuration loaded from {config}")
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    # Parse stages
    selected_stages = None
    if stages:
        selected_stages = [s.strip() for s in stages.split(',')]
        logger.info(f"Running stages: {', '.join(selected_stages)}")
    
    # Load scope
    assessment_scope = AssessmentScope(
        target=target,
        scope_file=scope,
        dry_run=dry_run,
        stealth_mode=stealth,
        aggressive_mode=aggressive
    )
    
    if scope and not validate_scope(scope):
        logger.error(f"Invalid scope file: {scope}")
        sys.exit(1)
    
    # Create output directory
    Path(output).mkdir(parents=True, exist_ok=True)
    
    # Run assessment
    try:
        logger.info(f"Starting assessment of target: {target}")
        orchestrator = PenTestOrchestrator(cfg, output)
        
        result = asyncio.run(
            orchestrator.run_assessment(assessment_scope, selected_stages)
        )
        
        logger.success(f"Assessment completed. Report saved to: {result.report_path}")
        
        # Print summary
        print_summary(result)
        
    except KeyboardInterrupt:
        logger.warning("Assessment interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Assessment failed: {e}")
        sys.exit(1)


def print_summary(result: AssessmentResult):
    """Print assessment summary"""
    print("\n" + "="*60)
    print("📊 ASSESSMENT SUMMARY")
    print("="*60)
    print(f"Target: {result.target}")
    print(f"Duration: {result.duration}")
    print(f"Hosts Discovered: {result.hosts_discovered}")
    print(f"Vulnerabilities Found: {result.total_vulnerabilities}")
    print(f"  - Critical: {result.critical_vulns}")
    print(f"  - High: {result.high_vulns}")
    print(f"  - Medium: {result.medium_vulns}")
    print(f"  - Low: {result.low_vulns}")
    print(f"Exploits Verified: {result.exploits_verified}")
    print(f"Report: {result.report_path}")
    print("="*60 + "\n")


if __name__ == '__main__':
    main()
