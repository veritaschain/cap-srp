"""
CAP-SRP Refusal Provenance Dashboard

A Streamlit-based dashboard for visualizing and verifying CAP-SRP event logs.

Features:
    - Real-time completeness verification
    - Event stream visualization
    - Denial breakdown by category
    - Chain integrity status
    - Merkle proof export
    - Regulatory report generation

Usage:
    python -m cap_srp.dashboard.app
    
    or
    
    streamlit run cap_srp/dashboard/app.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from cap_srp.core.logger import CAPLogger, create_demo_logger
from cap_srp.core.verifier import CompletenessVerifier, ChainVerifier, full_verification
from cap_srp.core.events import EventType, RiskCategory

# Page configuration
st.set_page_config(
    page_title="CAP-SRP Refusal Provenance Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1E88E5;
        margin-bottom: 0;
    }
    .sub-header {
        font-size: 1rem;
        color: #666;
        margin-top: 0;
    }
    .metric-card {
        background-color: #f8f9fa;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
    }
    .status-valid {
        color: #28a745;
        font-weight: bold;
    }
    .status-invalid {
        color: #dc3545;
        font-weight: bold;
    }
    .completeness-box {
        border: 2px solid #1E88E5;
        border-radius: 10px;
        padding: 15px;
        margin: 10px 0;
        background-color: #E3F2FD;
    }
</style>
""", unsafe_allow_html=True)


def init_session_state():
    """Initialize session state variables."""
    if 'logger' not in st.session_state:
        st.session_state.logger = create_demo_logger()
    if 'verification_result' not in st.session_state:
        st.session_state.verification_result = None


def render_header():
    """Render the main header."""
    st.markdown('<p class="main-header">🛡️ CAP-SRP Refusal Provenance Dashboard</p>', 
                unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Cryptographic proof that AI systems refused to generate harmful content</p>', 
                unsafe_allow_html=True)
    st.markdown("---")


def render_system_status():
    """Render the system status overview."""
    logger = st.session_state.logger
    stats = logger.get_statistics()
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="System Status",
            value="✅ COMPLIANT" if stats['completeness']['is_complete'] else "❌ VIOLATION"
        )
    
    with col2:
        st.metric(
            label="Total Events",
            value=f"{stats['total_events']:,}"
        )
    
    with col3:
        st.metric(
            label="Denial Rate",
            value=f"{stats['denial_rate']*100:.1f}%"
        )
    
    with col4:
        st.metric(
            label="Merkle Size",
            value=f"{stats['merkle_size']:,}"
        )


def render_completeness_verification():
    """Render the completeness verification section."""
    st.subheader("📊 Completeness Verification")
    
    logger = st.session_state.logger
    verifier = CompletenessVerifier()
    result = verifier.verify(logger.events)
    
    # Main completeness display
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        <div class="completeness-box">
            <h4 style="margin-top:0;">Completeness Invariant</h4>
            <p style="font-family: monospace; font-size: 1.2rem;">
                Σ ATTEMPTS = Σ GEN + Σ DENY + Σ ERROR
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # Progress bars
        total = result.total_attempts if result.total_attempts > 0 else 1
        
        st.markdown(f"**Total Attempts:** {result.total_attempts:,}")
        st.progress(1.0)
        
        gen_pct = result.total_generations / total
        st.markdown(f"**Generated:** {result.total_generations:,} ({gen_pct*100:.1f}%)")
        st.progress(gen_pct)
        
        deny_pct = result.total_denials / total
        st.markdown(f"**Denied:** {result.total_denials:,} ({deny_pct*100:.1f}%)")
        st.progress(deny_pct)
        
        error_pct = result.total_errors / total
        st.markdown(f"**Errors:** {result.total_errors:,} ({error_pct*100:.1f}%)")
        st.progress(error_pct)
    
    with col2:
        # Verification status
        if result.is_valid:
            st.success("✅ **VERIFIED**")
            st.markdown(f"Σ = {result.total_attempts:,}")
            st.markdown("All events accounted for")
        else:
            st.error("❌ **VIOLATION DETECTED**")
            st.markdown(result.error_message)
            if result.pending_attempts:
                st.warning(f"{len(result.pending_attempts)} pending attempts")
            if result.orphan_outcomes:
                st.warning(f"{len(result.orphan_outcomes)} orphan outcomes")


def render_denial_breakdown():
    """Render the denial breakdown by risk category."""
    st.subheader("🚫 Denial Breakdown by Risk Category")
    
    logger = st.session_state.logger
    stats = logger.get_statistics()
    
    denial_data = stats.get('denial_categories', {})
    
    if not denial_data:
        st.info("No denials recorded yet.")
        return
    
    # Create DataFrame for visualization
    df = pd.DataFrame([
        {"Category": cat, "Count": count}
        for cat, count in denial_data.items()
    ])
    df = df.sort_values('Count', ascending=True)
    
    # Horizontal bar chart
    fig = px.bar(
        df,
        x='Count',
        y='Category',
        orientation='h',
        color='Count',
        color_continuous_scale='Reds',
        title='Denials by Risk Category'
    )
    fig.update_layout(
        showlegend=False,
        height=400,
        yaxis_title="",
        xaxis_title="Number of Denials"
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Table view
    with st.expander("📋 Detailed Breakdown"):
        total_denials = sum(denial_data.values())
        table_data = []
        for cat, count in sorted(denial_data.items(), key=lambda x: -x[1]):
            pct = (count / total_denials * 100) if total_denials > 0 else 0
            table_data.append({
                "Risk Category": cat,
                "Count": count,
                "Percentage": f"{pct:.1f}%"
            })
        st.table(pd.DataFrame(table_data))


def render_integrity_verification():
    """Render the chain and Merkle integrity verification."""
    st.subheader("🔗 Integrity Verification")
    
    logger = st.session_state.logger
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Hash Chain Integrity**")
        chain_verifier = ChainVerifier(logger.public_key)
        chain_result = chain_verifier.verify(logger.events, verify_signatures=True)
        
        if chain_result.is_valid:
            st.success(f"✅ Chain Valid ({chain_result.events_verified} events)")
        else:
            st.error(f"❌ Chain Broken at event {chain_result.first_invalid_index}")
            st.markdown(chain_result.error_message)
    
    with col2:
        st.markdown("**Merkle Root**")
        if logger.merkle_root:
            st.code(logger.merkle_root[:32] + "...", language=None)
            st.caption(f"Full root: {logger.merkle_root}")
        else:
            st.info("No Merkle root (empty log)")


def render_event_explorer():
    """Render the event explorer section."""
    st.subheader("🔍 Event Explorer")
    
    logger = st.session_state.logger
    events = logger.events
    
    if not events:
        st.info("No events to display.")
        return
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        event_types = st.multiselect(
            "Event Types",
            options=[e.value for e in EventType],
            default=[e.value for e in EventType]
        )
    
    with col2:
        risk_categories = st.multiselect(
            "Risk Categories (for denials)",
            options=[r.value for r in RiskCategory],
            default=[]
        )
    
    with col3:
        num_events = st.slider("Show last N events", 10, 100, 20)
    
    # Filter events
    filtered_events = []
    for event in events:
        if event.event_type.value in event_types:
            if event.event_type == EventType.GEN_DENY:
                if not risk_categories or (event.risk_category and event.risk_category.value in risk_categories):
                    filtered_events.append(event)
            else:
                filtered_events.append(event)
    
    # Show last N events
    display_events = filtered_events[-num_events:]
    
    # Display as cards
    for i, event in enumerate(reversed(display_events)):
        with st.expander(
            f"📌 {event.event_type.value} | {event.event_id[:8]}... | {event.timestamp[:19]}",
            expanded=(i < 3)
        ):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.json(event.to_dict())
            
            with col2:
                st.markdown("**Quick Info**")
                st.markdown(f"- Type: `{event.event_type.value}`")
                st.markdown(f"- Session: `{event.session_id or 'N/A'}`")
                
                if event.event_type == EventType.GEN_DENY:
                    st.markdown(f"- Risk: `{event.risk_category.value if event.risk_category else 'N/A'}`")
                    st.markdown(f"- Score: `{event.risk_score:.2f}`")
                
                # Generate proof button
                try:
                    event_index = events.index(event)
                    if st.button(f"Generate Proof #{i}", key=f"proof_{i}"):
                        proof = logger.get_inclusion_proof(event_index)
                        st.json(proof.to_dict())
                except:
                    pass


def render_export_section():
    """Render the export and report section."""
    st.subheader("📤 Export & Reports")
    
    logger = st.session_state.logger
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**Export Events**")
        if st.button("📄 Export as JSON"):
            export_data = {
                "version": "1.0.0",
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "public_key": logger.public_key,
                "merkle_root": logger.merkle_root,
                "event_count": logger.event_count,
                "events": [e.to_dict() for e in logger.events]
            }
            st.download_button(
                "⬇️ Download JSON",
                data=json.dumps(export_data, indent=2),
                file_name=f"cap_srp_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with col2:
        st.markdown("**Compliance Report**")
        if st.button("📊 Generate Report"):
            stats = logger.get_statistics()
            verifier = CompletenessVerifier()
            result = verifier.verify(logger.events)
            
            report = f"""
# CAP-SRP Compliance Report

**Generated:** {datetime.now(timezone.utc).isoformat()}
**System:** demo-image-gen-v3
**Public Key:** {logger.public_key[:32]}...

## Completeness Verification

- **Status:** {"✅ VERIFIED" if result.is_valid else "❌ VIOLATION"}
- **Total Attempts:** {result.total_attempts:,}
- **Total Generations:** {result.total_generations:,}
- **Total Denials:** {result.total_denials:,}
- **Total Errors:** {result.total_errors:,}
- **Denial Rate:** {result.denial_rate*100:.2f}%

## Merkle Root

```
{logger.merkle_root}
```

## Denial Categories

"""
            for cat, count in stats.get('denial_categories', {}).items():
                report += f"- {cat}: {count:,}\n"
            
            st.download_button(
                "⬇️ Download Report",
                data=report,
                file_name=f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown"
            )
    
    with col3:
        st.markdown("**Merkle Proofs**")
        if st.button("🌳 Export All Proofs"):
            proofs = []
            for i in range(logger.event_count):
                proof = logger.get_inclusion_proof(i)
                proofs.append(proof.to_dict())
            
            st.download_button(
                "⬇️ Download Proofs",
                data=json.dumps(proofs, indent=2),
                file_name=f"merkle_proofs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )


def render_sidebar():
    """Render the sidebar."""
    st.sidebar.title("🔧 Controls")
    
    st.sidebar.markdown("---")
    st.sidebar.subheader("Demo Data")
    
    if st.sidebar.button("🔄 Generate New Demo Data"):
        st.session_state.logger = create_demo_logger()
        st.rerun()
    
    event_count = st.sidebar.slider("Events to Generate", 50, 500, 100)
    denial_rate = st.sidebar.slider("Denial Rate %", 10, 70, 34)
    
    if st.sidebar.button("🎲 Custom Demo"):
        from cap_srp.core.events import hash_data
        import random
        
        logger = CAPLogger(model_id="custom-demo", policy_version="v1.0.0")
        
        risk_categories = list(RiskCategory)
        
        for i in range(event_count):
            prompt_hash = hash_data(f"custom_prompt_{i}_{random.random()}")
            attempt = logger.log_attempt(
                prompt_hash=prompt_hash,
                session_id=f"sess_{i // 10:03d}"
            )
            
            if random.random() * 100 < denial_rate:
                logger.log_denial(
                    attempt_id=attempt.event_id,
                    risk_category=random.choice(risk_categories),
                    risk_score=0.5 + random.random() * 0.5
                )
            elif random.random() > 0.02:
                logger.log_generation(
                    attempt_id=attempt.event_id,
                    output_hash=hash_data(f"output_{i}")
                )
            else:
                logger.log_error(
                    attempt_id=attempt.event_id,
                    error_code="E001",
                    error_message="Random error"
                )
        
        st.session_state.logger = logger
        st.rerun()
    
    st.sidebar.markdown("---")
    st.sidebar.subheader("About")
    st.sidebar.markdown("""
    **CAP-SRP Dashboard**
    
    Part of the VeritasChain Protocol ecosystem
    for cryptographic AI audit trails.
    
    - [GitHub](https://github.com/veritaschain/cap-srp-dashboard)
    - [Documentation](https://veritaschain.org)
    - [IETF Draft](https://datatracker.ietf.org/doc/draft-kamimura-scitt-vcp/)
    """)
    
    st.sidebar.markdown("---")
    st.sidebar.caption("© 2026 VeritasChain Standards Organization")


def main():
    """Main dashboard entry point."""
    init_session_state()
    render_sidebar()
    render_header()
    render_system_status()
    
    st.markdown("---")
    
    # Main content in tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "📊 Completeness",
        "🚫 Denials",
        "🔗 Integrity",
        "🔍 Events"
    ])
    
    with tab1:
        render_completeness_verification()
    
    with tab2:
        render_denial_breakdown()
    
    with tab3:
        render_integrity_verification()
    
    with tab4:
        render_event_explorer()
    
    st.markdown("---")
    render_export_section()
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666; font-size: 0.9rem;">
        <p><strong>"Verify, Don't Trust"</strong></p>
        <p>CAP-SRP: Cryptographic proof of AI refusal provenance</p>
        <p>VeritasChain Standards Organization | info@veritaschain.org</p>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
