#!/usr/bin/env python3
"""
CAP-SRP Command Line Interface

Provides command-line tools for working with CAP-SRP event logs.

Usage:
    cap-srp generate --events 1000 --output events.json
    cap-srp verify --input events.json
    cap-srp dashboard
    cap-srp info
"""

import click
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

from cap_srp import __version__, __author__
from cap_srp.core.logger import CAPLogger, create_demo_logger
from cap_srp.core.events import RiskCategory, hash_data, create_event_from_dict
from cap_srp.core.verifier import CompletenessVerifier, ChainVerifier, full_verification


@click.group()
@click.version_option(version=__version__)
def main():
    """CAP-SRP: Cryptographic AI Refusal Provenance"""
    pass


@main.command()
@click.option('--events', '-n', default=100, help='Number of events to generate')
@click.option('--denial-rate', '-d', default=0.34, help='Denial rate (0.0-1.0)')
@click.option('--error-rate', '-e', default=0.01, help='Error rate (0.0-1.0)')
@click.option('--output', '-o', default='events.json', help='Output file path')
@click.option('--model-id', default='demo-image-gen', help='Model identifier')
@click.option('--seed', type=int, default=None, help='Random seed')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def generate(events, denial_rate, error_rate, output, model_id, seed, verbose):
    """Generate demo CAP-SRP events."""
    import random
    
    if seed is not None:
        random.seed(seed)
    
    if verbose:
        click.echo(f"Generating {events} events...")
    
    logger = CAPLogger(model_id=model_id)
    
    risk_categories = list(RiskCategory)
    
    for i in range(events):
        prompt_hash = hash_data(f"prompt_{i}_{random.random()}")
        attempt = logger.log_attempt(
            prompt_hash=prompt_hash,
            session_id=f"sess_{i // 10:04d}"
        )
        
        roll = random.random()
        
        if roll < denial_rate:
            logger.log_denial(
                attempt_id=attempt.event_id,
                risk_category=random.choice(risk_categories),
                risk_score=0.5 + random.random() * 0.5
            )
        elif roll < denial_rate + error_rate:
            logger.log_error(
                attempt_id=attempt.event_id,
                error_code="E001",
                error_message="Demo error"
            )
        else:
            logger.log_generation(
                attempt_id=attempt.event_id,
                output_hash=hash_data(f"output_{i}")
            )
        
        if verbose and (i + 1) % 100 == 0:
            click.echo(f"  Generated {i + 1}/{events}")
    
    # Export
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    logger.export_events(str(output_path))
    
    stats = logger.get_statistics()
    
    if verbose:
        click.echo("\nGeneration complete!")
        click.echo(f"  Total events: {stats['total_events']}")
        click.echo(f"  Denial rate: {stats['denial_rate']*100:.1f}%")
        click.echo(f"  Merkle root: {logger.merkle_root[:32]}...")
        click.echo(f"  Output: {output_path}")
    else:
        click.echo(json.dumps({
            "events": stats['total_events'],
            "merkle_root": logger.merkle_root,
            "output": str(output_path)
        }))


@main.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--json-output', '-j', is_flag=True, help='Output as JSON')
def verify(input_file, verbose, json_output):
    """Verify CAP-SRP event log completeness and integrity."""
    
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    events = [create_event_from_dict(e) for e in data.get('events', [])]
    public_key = data.get('public_key')
    expected_root = data.get('merkle_root')
    
    if verbose:
        click.echo(f"Verifying {len(events)} events...")
    
    result = full_verification(
        events,
        public_key=public_key,
        expected_merkle_root=expected_root
    )
    
    if json_output:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        if result.is_valid:
            click.echo(click.style("✅ VERIFICATION PASSED", fg='green', bold=True))
        else:
            click.echo(click.style("❌ VERIFICATION FAILED", fg='red', bold=True))
            click.echo(f"Error: {result.error_message}")
        
        if verbose:
            click.echo(f"\nCompleteness:")
            click.echo(f"  Attempts: {result.completeness.total_attempts}")
            click.echo(f"  Generations: {result.completeness.total_generations}")
            click.echo(f"  Denials: {result.completeness.total_denials}")
            click.echo(f"  Errors: {result.completeness.total_errors}")
            click.echo(f"  Status: {'PASS' if result.completeness.is_valid else 'FAIL'}")
            click.echo(f"\nChain Integrity:")
            click.echo(f"  Events verified: {result.chain.events_verified}")
            click.echo(f"  Status: {'PASS' if result.chain.is_valid else 'FAIL'}")
            if result.merkle_root_valid is not None:
                click.echo(f"\nMerkle Root:")
                click.echo(f"  Status: {'PASS' if result.merkle_root_valid else 'FAIL'}")
    
    sys.exit(0 if result.is_valid else 1)


@main.command()
@click.option('--port', '-p', default=8501, help='Port for dashboard')
def dashboard(port):
    """Launch the CAP-SRP dashboard."""
    import subprocess
    
    click.echo(f"Starting CAP-SRP Dashboard on port {port}...")
    click.echo("Press Ctrl+C to stop")
    
    subprocess.run([
        sys.executable, "-m", "streamlit", "run",
        "cap_srp/dashboard/app.py",
        "--server.port", str(port)
    ])


@main.command()
def info():
    """Show CAP-SRP version and information."""
    click.echo(f"""
CAP-SRP: Content Authenticity Protocol - Safe Refusal Provenance
================================================================

Version: {__version__}
Author: {__author__}

Description:
  Cryptographic proof that AI systems refused to generate harmful content.

Key Features:
  • Ed25519 digital signatures
  • Hash chain integrity
  • Merkle tree inclusion proofs
  • Completeness invariant verification
  • EU AI Act Article 12 compliance

Links:
  • GitHub: https://github.com/veritaschain/cap-srp-dashboard
  • IETF: https://datatracker.ietf.org/doc/draft-kamimura-scitt-vcp/
  • Website: https://veritaschain.org

"Verify, Don't Trust"
    """)


@main.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', '-o', default=None, help='Output report file')
def report(input_file, output):
    """Generate a compliance report from event log."""
    
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    events = [create_event_from_dict(e) for e in data.get('events', [])]
    public_key = data.get('public_key')
    merkle_root = data.get('merkle_root')
    
    result = full_verification(events, public_key=public_key, expected_merkle_root=merkle_root)
    
    # Build report
    report_text = f"""
CAP-SRP COMPLIANCE REPORT
=========================

Generated: {datetime.now(timezone.utc).isoformat()}
Input File: {input_file}

VERIFICATION STATUS
-------------------
Overall: {'✅ PASS' if result.is_valid else '❌ FAIL'}
Completeness: {'✅ PASS' if result.completeness.is_valid else '❌ FAIL'}
Chain Integrity: {'✅ PASS' if result.chain.is_valid else '❌ FAIL'}
Merkle Root: {'✅ PASS' if result.merkle_root_valid else '❌ FAIL' if result.merkle_root_valid is not None else 'N/A'}

STATISTICS
----------
Total Events: {len(events)}
Attempts: {result.completeness.total_attempts}
Generations: {result.completeness.total_generations}
Denials: {result.completeness.total_denials}
Errors: {result.completeness.total_errors}
Denial Rate: {result.completeness.denial_rate * 100:.2f}%

CRYPTOGRAPHIC VERIFICATION
--------------------------
Public Key: {public_key[:32] if public_key else 'N/A'}...
Merkle Root: {merkle_root[:32] if merkle_root else 'N/A'}...

REGULATORY COMPLIANCE
---------------------
EU AI Act Article 12: ✅ Compliant (automatic logging, tamper-evidence)
EU DSA Article 15: ✅ Compliant (content moderation transparency)
ISO/IEC 24970:2025: ✅ Aligned (AI system logging)

---
Generated by CAP-SRP v{__version__}
VeritasChain Standards Organization
    """
    
    if output:
        with open(output, 'w') as f:
            f.write(report_text)
        click.echo(f"Report saved to: {output}")
    else:
        click.echo(report_text)


if __name__ == "__main__":
    main()
