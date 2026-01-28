#!/usr/bin/env python3
"""
CAP-SRP Demo: Generate Sample Events

This script demonstrates how to use CAP-SRP to log AI generation events
with cryptographic proofs.

Usage:
    python examples/demo_generate_events.py --events 100 --output data/events.json
    
    # With custom denial rate
    python examples/demo_generate_events.py --events 500 --denial-rate 40 --output data/events.json
"""

import argparse
import json
import random
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cap_srp.core.logger import CAPLogger
from cap_srp.core.events import RiskCategory, hash_data
from cap_srp.core.verifier import CompletenessVerifier


def simulate_ai_generation_system(
    num_events: int,
    denial_rate: float,
    error_rate: float = 0.01
) -> CAPLogger:
    """
    Simulate an AI image generation system with CAP-SRP logging.
    
    This demonstrates the core CAP-SRP workflow:
    1. Log GEN_ATTEMPT before safety evaluation (Commitment Point)
    2. Evaluate request safety
    3. Log outcome (GEN, GEN_DENY, or GEN_ERROR)
    
    Args:
        num_events: Number of generation requests to simulate
        denial_rate: Fraction of requests to deny (0.0 to 1.0)
        error_rate: Fraction of requests that error (0.0 to 1.0)
    
    Returns:
        CAPLogger: Logger with all events
    """
    print(f"\n🚀 Starting CAP-SRP simulation")
    print(f"   Events: {num_events}")
    print(f"   Target denial rate: {denial_rate*100:.1f}%")
    print(f"   Target error rate: {error_rate*100:.1f}%")
    
    # Initialize logger with a fresh key pair
    logger = CAPLogger(
        model_id="demo-image-gen-v3",
        policy_version="v2.3.1"
    )
    
    print(f"   Public key: {logger.public_key[:32]}...")
    print()
    
    # Risk category distribution (realistic for NCII-focused system)
    risk_distribution = [
        (RiskCategory.NCII_RISK, 0.45),
        (RiskCategory.CSAM_RISK, 0.22),
        (RiskCategory.REAL_PERSON_DEEPFAKE, 0.17),
        (RiskCategory.VIOLENCE_GRAPHIC, 0.10),
        (RiskCategory.HATE_CONTENT, 0.03),
        (RiskCategory.OTHER, 0.03),
    ]
    
    def select_risk_category():
        """Select risk category based on distribution."""
        r = random.random()
        cumulative = 0
        for category, weight in risk_distribution:
            cumulative += weight
            if r < cumulative:
                return category
        return RiskCategory.OTHER
    
    # Progress tracking
    generations = 0
    denials = 0
    errors = 0
    
    for i in range(num_events):
        # Simulate user request
        session_id = f"sess_{i // 10:04d}"
        prompt_hash = hash_data(f"user_prompt_{i}_{random.random()}")
        user_context_hash = hash_data(f"user_{i % 100}")
        
        # ═══════════════════════════════════════════════════════════════
        # STEP 1: Log GEN_ATTEMPT (Commitment Point)
        # This MUST happen BEFORE safety evaluation
        # ═══════════════════════════════════════════════════════════════
        attempt = logger.log_attempt(
            prompt_hash=prompt_hash,
            session_id=session_id,
            user_context_hash=user_context_hash
        )
        
        # ═══════════════════════════════════════════════════════════════
        # STEP 2: Safety Evaluation (simulated)
        # In real system: run through safety classifiers
        # ═══════════════════════════════════════════════════════════════
        outcome_roll = random.random()
        
        # ═══════════════════════════════════════════════════════════════
        # STEP 3: Log Outcome
        # ═══════════════════════════════════════════════════════════════
        if outcome_roll < error_rate:
            # Technical error (rare)
            logger.log_error(
                attempt_id=attempt.event_id,
                error_code="E001",
                error_message="GPU memory exceeded during generation",
                session_id=session_id
            )
            errors += 1
            
        elif outcome_roll < error_rate + denial_rate:
            # Safety filter triggered - DENY
            risk_category = select_risk_category()
            risk_score = 0.7 + random.random() * 0.3  # 0.7 to 1.0
            
            logger.log_denial(
                attempt_id=attempt.event_id,
                risk_category=risk_category,
                risk_score=risk_score,
                denial_reason=f"POLICY_VIOLATION_{risk_category.value}",
                session_id=session_id
            )
            denials += 1
            
        else:
            # Safe to generate
            output_hash = hash_data(f"generated_image_{i}_{random.random()}")
            
            logger.log_generation(
                attempt_id=attempt.event_id,
                output_hash=output_hash,
                c2pa_manifest_id=f"c2pa:manifest_{i:08d}",
                session_id=session_id
            )
            generations += 1
        
        # Progress indicator
        if (i + 1) % 100 == 0 or (i + 1) == num_events:
            print(f"   Progress: {i+1}/{num_events} events "
                  f"(✓ {generations} | ✗ {denials} | ⚠ {errors})")
    
    print()
    return logger


def main():
    parser = argparse.ArgumentParser(
        description="Generate CAP-SRP demo events"
    )
    parser.add_argument(
        "--events", "-n",
        type=int,
        default=100,
        help="Number of events to generate (default: 100)"
    )
    parser.add_argument(
        "--denial-rate", "-d",
        type=float,
        default=0.34,
        help="Denial rate as percentage (default: 34)"
    )
    parser.add_argument(
        "--error-rate", "-e",
        type=float,
        default=1.0,
        help="Error rate as percentage (default: 1)"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="data/demo_events.json",
        help="Output file path (default: data/demo_events.json)"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run verification after generation"
    )
    
    args = parser.parse_args()
    
    # Generate events
    logger = simulate_ai_generation_system(
        num_events=args.events,
        denial_rate=args.denial_rate / 100,
        error_rate=args.error_rate / 100
    )
    
    # Get statistics
    stats = logger.get_statistics()
    
    print("📊 Event Statistics")
    print("═" * 50)
    print(f"   Total Events: {stats['total_events']}")
    print(f"   Attempts:     {stats['attempts']}")
    print(f"   Generations:  {stats['generations']}")
    print(f"   Denials:      {stats['denials']}")
    print(f"   Errors:       {stats['errors']}")
    print(f"   Denial Rate:  {stats['denial_rate']*100:.2f}%")
    print()
    
    print("📊 Denial Categories")
    print("─" * 50)
    for category, count in sorted(
        stats['denial_categories'].items(),
        key=lambda x: -x[1]
    ):
        pct = count / stats['denials'] * 100 if stats['denials'] > 0 else 0
        bar = "█" * int(pct / 5)
        print(f"   {category:25s} {count:5d} ({pct:5.1f}%) {bar}")
    print()
    
    # Verify if requested
    if args.verify:
        print("🔍 Running Verification")
        print("─" * 50)
        
        verifier = CompletenessVerifier()
        result = verifier.verify(logger.events)
        
        if result.is_valid:
            print("   ✅ Completeness Invariant: VERIFIED")
        else:
            print("   ❌ Completeness Invariant: VIOLATION")
            print(f"   Error: {result.error_message}")
        
        print(f"   Merkle Root: {logger.merkle_root[:32]}...")
        print()
    
    # Export events
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    logger.export_events(str(output_path))
    print(f"💾 Events exported to: {output_path}")
    print()
    
    print("✨ Demo complete!")
    print()
    print("Next steps:")
    print(f"  1. View events: cat {output_path} | jq '.events | length'")
    print(f"  2. Verify: python examples/demo_verify_completeness.py -i {output_path}")
    print(f"  3. Dashboard: python -m cap_srp.dashboard.app")


if __name__ == "__main__":
    main()
