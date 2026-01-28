#!/usr/bin/env python3
"""
CAP-SRP Demo: Verify Event Log Completeness

This script demonstrates how to verify the Completeness Invariant
and detect potential fraud in CAP-SRP event logs.

The Completeness Invariant guarantees:
    Σ ATTEMPTS = Σ GENERATIONS + Σ DENIALS + Σ ERRORS

If this equation fails, it proves tampering occurred.

Usage:
    python examples/demo_verify_completeness.py -i data/events.json
    
    # Verbose mode
    python examples/demo_verify_completeness.py -i data/events.json -v
    
    # Export verification report
    python examples/demo_verify_completeness.py -i data/events.json --report verification_report.json
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cap_srp.core.events import create_event_from_dict
from cap_srp.core.verifier import (
    CompletenessVerifier,
    ChainVerifier,
    MerkleVerifier,
    full_verification
)
from cap_srp.core.merkle import MerkleTree


def load_events(filepath: str):
    """Load events from a JSON file."""
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    events = []
    for event_data in data.get('events', []):
        event = create_event_from_dict(event_data)
        events.append(event)
    
    metadata = {
        'version': data.get('version'),
        'exported_at': data.get('exported_at'),
        'public_key': data.get('public_key'),
        'merkle_root': data.get('merkle_root'),
        'event_count': data.get('event_count')
    }
    
    return events, metadata


def print_header(text: str):
    """Print a formatted header."""
    print()
    print("═" * 60)
    print(f"  {text}")
    print("═" * 60)


def print_section(text: str):
    """Print a formatted section header."""
    print()
    print(f"─── {text} " + "─" * (55 - len(text)))


def verify_events(filepath: str, verbose: bool = False, report_path: str = None):
    """
    Perform complete verification of an event log.
    
    Args:
        filepath: Path to the events JSON file
        verbose: Whether to print detailed output
        report_path: Optional path to export verification report
    """
    print_header("CAP-SRP Event Log Verification")
    
    # Load events
    print_section("Loading Events")
    events, metadata = load_events(filepath)
    
    print(f"  File: {filepath}")
    print(f"  Events loaded: {len(events)}")
    print(f"  Export timestamp: {metadata.get('exported_at', 'N/A')}")
    print(f"  Public key: {metadata.get('public_key', 'N/A')[:32]}...")
    
    # Step 1: Completeness Verification
    print_section("Step 1: Completeness Invariant")
    print()
    print("  Formula: Σ ATTEMPTS = Σ GEN + Σ DENY + Σ ERROR")
    print()
    
    completeness_verifier = CompletenessVerifier()
    completeness_result = completeness_verifier.verify(events)
    
    print(f"  Attempts:    {completeness_result.total_attempts:>10,}")
    print(f"  Generations: {completeness_result.total_generations:>10,}")
    print(f"  Denials:     {completeness_result.total_denials:>10,}")
    print(f"  Errors:      {completeness_result.total_errors:>10,}")
    print(f"               {'─' * 10}")
    print(f"  Outcomes:    {completeness_result.total_outcomes:>10,}")
    print()
    
    if completeness_result.is_valid:
        print("  ✅ COMPLETENESS VERIFIED")
        print(f"     {completeness_result.total_attempts} = "
              f"{completeness_result.total_generations} + "
              f"{completeness_result.total_denials} + "
              f"{completeness_result.total_errors}")
    else:
        print("  ❌ COMPLETENESS VIOLATION DETECTED!")
        print(f"     Error: {completeness_result.error_message}")
        
        if completeness_result.pending_attempts:
            print(f"     Pending attempts: {len(completeness_result.pending_attempts)}")
            if verbose:
                for aid in completeness_result.pending_attempts[:5]:
                    print(f"       - {aid}")
                if len(completeness_result.pending_attempts) > 5:
                    print(f"       ... and {len(completeness_result.pending_attempts) - 5} more")
        
        if completeness_result.orphan_outcomes:
            print(f"     Orphan outcomes: {len(completeness_result.orphan_outcomes)}")
    
    # Step 2: Chain Verification
    print_section("Step 2: Hash Chain Integrity")
    
    public_key = metadata.get('public_key')
    chain_verifier = ChainVerifier(public_key)
    chain_result = chain_verifier.verify(events, verify_signatures=bool(public_key))
    
    if chain_result.is_valid:
        print(f"  ✅ CHAIN INTACT ({chain_result.events_verified} events verified)")
    else:
        print(f"  ❌ CHAIN BROKEN!")
        print(f"     First invalid event: index {chain_result.first_invalid_index}")
        print(f"     Error: {chain_result.error_message}")
        
        if verbose and chain_result.invalid_hashes:
            print("     Invalid hashes:")
            for idx, expected, actual in chain_result.invalid_hashes[:3]:
                print(f"       Event {idx}: {expected} vs {actual}")
    
    # Step 3: Merkle Root Verification
    print_section("Step 3: Merkle Root Verification")
    
    expected_root = metadata.get('merkle_root')
    if expected_root:
        # Rebuild Merkle tree from events
        tree = MerkleTree()
        for event in events:
            tree.add_leaf(event.current_hash)
        
        computed_root = tree.root
        
        print(f"  Expected:  {expected_root[:32]}...")
        print(f"  Computed:  {computed_root[:32]}...")
        
        if computed_root == expected_root:
            print("  ✅ MERKLE ROOT MATCHES")
        else:
            print("  ❌ MERKLE ROOT MISMATCH!")
            print("     This indicates the event log has been modified.")
    else:
        print("  ⚠️  No expected Merkle root in metadata")
        print("     Skipping Merkle verification")
    
    # Step 4: Statistical Analysis
    print_section("Step 4: Statistical Analysis")
    
    print(f"  Denial rate: {completeness_result.denial_rate * 100:.2f}%")
    
    # Analyze denial breakdown
    denial_events = [e for e in events if e.event_type.value == "GEN_DENY"]
    if denial_events:
        category_counts = {}
        for event in denial_events:
            cat = event.risk_category.value if event.risk_category else "UNKNOWN"
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        print()
        print("  Denial categories:")
        for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
            pct = count / len(denial_events) * 100
            bar = "█" * int(pct / 5)
            print(f"    {cat:25s} {count:5d} ({pct:5.1f}%) {bar}")
    
    # Overall Verdict
    print_section("VERIFICATION VERDICT")
    
    all_valid = (
        completeness_result.is_valid and
        chain_result.is_valid and
        (computed_root == expected_root if expected_root else True)
    )
    
    if all_valid:
        print()
        print("  ╔════════════════════════════════════════════════════╗")
        print("  ║                                                    ║")
        print("  ║   ✅ EVENT LOG VERIFIED                           ║")
        print("  ║                                                    ║")
        print("  ║   • Completeness Invariant: PASSED                 ║")
        print("  ║   • Hash Chain Integrity:   PASSED                 ║")
        print("  ║   • Merkle Root:            MATCHED                ║")
        print("  ║                                                    ║")
        print("  ║   This log has not been tampered with.             ║")
        print("  ║                                                    ║")
        print("  ╚════════════════════════════════════════════════════╝")
    else:
        print()
        print("  ╔════════════════════════════════════════════════════╗")
        print("  ║                                                    ║")
        print("  ║   ❌ VERIFICATION FAILED                          ║")
        print("  ║                                                    ║")
        if not completeness_result.is_valid:
            print("  ║   • Completeness Invariant: FAILED                 ║")
        if not chain_result.is_valid:
            print("  ║   • Hash Chain Integrity:   FAILED                 ║")
        if expected_root and computed_root != expected_root:
            print("  ║   • Merkle Root:            MISMATCH               ║")
        print("  ║                                                    ║")
        print("  ║   Evidence of tampering detected!                  ║")
        print("  ║                                                    ║")
        print("  ╚════════════════════════════════════════════════════╝")
    
    # Export report if requested
    if report_path:
        print()
        print_section("Exporting Verification Report")
        
        report = {
            "verification_timestamp": datetime.now(timezone.utc).isoformat(),
            "input_file": filepath,
            "overall_valid": all_valid,
            "completeness": completeness_result.to_dict(),
            "chain_integrity": chain_result.to_dict(),
            "merkle_root": {
                "expected": expected_root,
                "computed": computed_root if expected_root else None,
                "valid": computed_root == expected_root if expected_root else None
            },
            "statistics": {
                "total_events": len(events),
                "denial_rate": completeness_result.denial_rate
            }
        }
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"  Report exported to: {report_path}")
    
    print()
    
    return all_valid


def main():
    parser = argparse.ArgumentParser(
        description="Verify CAP-SRP event log completeness and integrity"
    )
    parser.add_argument(
        "--input", "-i",
        type=str,
        required=True,
        help="Input events JSON file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--report", "-r",
        type=str,
        help="Export verification report to JSON file"
    )
    
    args = parser.parse_args()
    
    # Check input file exists
    if not Path(args.input).exists():
        print(f"Error: File not found: {args.input}")
        sys.exit(1)
    
    # Run verification
    is_valid = verify_events(
        args.input,
        verbose=args.verbose,
        report_path=args.report
    )
    
    # Exit with appropriate code
    sys.exit(0 if is_valid else 1)


if __name__ == "__main__":
    main()
