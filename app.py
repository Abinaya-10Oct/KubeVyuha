"""KubeVyuha — Provenance-Guided Split Recovery for Kubernetes.

Developer Security Console.
Core method: Authority-Split Restore.
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st
import yaml

from authsplit.audit_parser import parse_audit_log_file
from authsplit.backup_manager import BackupManager
from authsplit.backup_reader import read_backup_manifests
from authsplit.evaluator import BaselineEvaluator
from authsplit.executor import GuardedExecutor
from authsplit.models import ProvenanceState
from authsplit.plan_writer import PlanWriter
from authsplit.planner import AuthoritySplitPlanner
from authsplit.provenance import (
    ApprovedActorsConfig,
    ProvenanceEngine,
    TrustPolicy,
)
from authsplit.settings import AppSettings
from authsplit.verifier import PostRecoveryVerifier
from ui.components import (
    render_animation_engine,
    render_callout,
    render_metric_card,
    render_navbar,
    render_prerequisite_diagnostics,
    render_top_header,
)
from ui.theme import get_custom_css

# Page Configuration
st.set_page_config(
    page_title="KubeVyuha — Authority-Split Recovery",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Inject dark-first DevSecOps styling & client-side pointer animation engine
st.markdown(get_custom_css(), unsafe_allow_html=True)
render_animation_engine()


def init_session_state(settings: AppSettings) -> None:
    """Initialize persistent Streamlit session state variables."""
    if "settings" not in st.session_state:
        st.session_state.settings = settings

    if "backup_mgr" not in st.session_state:
        st.session_state.backup_mgr = BackupManager(settings)

    if "policy" not in st.session_state:
        st.session_state.policy = TrustPolicy.load_from_yaml(settings.trust_policy_path)

    if "actors_config" not in st.session_state:
        st.session_state.actors_config = ApprovedActorsConfig.load_from_yaml(settings.approved_actors_path)

    if "scenario_id" not in st.session_state:
        st.session_state.scenario_id = "scenario_1_unauthorized_cluster_admin"

    if "active_page" not in st.session_state:
        st.session_state.active_page = "Overview"

    if "current_plan" not in st.session_state:
        st.session_state.current_plan = None

    if "exec_result" not in st.session_state:
        st.session_state.exec_result = None

    if "verification_report" not in st.session_state:
        st.session_state.verification_report = None

    if "benchmark_result" not in st.session_state:
        st.session_state.benchmark_result = None


def load_active_scenario_data():
    """Load backup snapshots and audit stream for the currently selected scenario."""
    scenarios_dir = Path("lab/scenarios") / st.session_state.scenario_id
    baseline_path = scenarios_dir / "backup_01_baseline.yaml"
    poisoned_path = list(scenarios_dir.glob("backup_02_*.yaml"))[0]
    audit_path = scenarios_dir / "audit_stream.jsonl"

    clean_objs, _ = read_backup_manifests(baseline_path, backup_name=f"{st.session_state.scenario_id}-01-clean")
    poisoned_objs, _ = read_backup_manifests(poisoned_path, backup_name=f"{st.session_state.scenario_id}-02-latest")
    audit_res = parse_audit_log_file(audit_path)

    snapshots = {
        clean_objs[0].backup_name: clean_objs,
        poisoned_objs[0].backup_name: poisoned_objs,
    }
    return snapshots, audit_res


def main() -> None:
    """Main application loop."""
    settings = AppSettings.from_env()
    init_session_state(settings)

    effective_mode = settings.resolve_effective_mode()
    tools = settings.check_live_tools_available()
    cluster_connected = tools["kubectl"] and effective_mode == "live"

    # Top Cyber Header Bar
    render_top_header(
        mode=effective_mode,
        cluster_connected=cluster_connected,
        cluster_context=settings.allowed_context if cluster_connected else None,
    )

    if effective_mode == "demo":
        render_callout(
            "<strong>Operating in Offline Demo Mode:</strong> Live Kubernetes CLI tools "
            f"(kubectl: {tools['kubectl']}, velero: {tools['velero']}) are not detected in the environment. "
            "KubeVyuha is safely evaluating verified synthetic scenarios from <code>lab/scenarios/</code>.",
            level="warn",
        )

    # Polished Horizontal Top Navigation Bar
    selected_page = render_navbar(st.session_state.active_page)
    if selected_page != st.session_state.active_page:
        st.session_state.active_page = selected_page
        st.rerun()

    active_page = st.session_state.active_page

    snapshots, audit_res = load_active_scenario_data()
    engine = ProvenanceEngine(st.session_state.policy, st.session_state.actors_config)

    # Classify latest snapshot objects for baseline state
    latest_snap_name = list(snapshots.keys())[-1]
    latest_objects = engine.classify_inventory(snapshots[latest_snap_name], audit_res.events)

    verified_count = sum(1 for o in latest_objects if o.provenance_state == ProvenanceState.VERIFIED)
    suspicious_count = sum(1 for o in latest_objects if o.provenance_state == ProvenanceState.SUSPICIOUS)
    unknown_count = sum(1 for o in latest_objects if o.provenance_state == ProvenanceState.UNKNOWN)

    # =========================================================================
    # PAGE 1: OVERVIEW (DASHBOARD)
    # =========================================================================
    if active_page == "Overview":
        st.markdown("### 📊 Threat Posture & System Overview")
        st.caption("Real-time authority assurance and Kubernetes backup recovery posture.")

        # Interactive 3D Tilt Metric Cards
        m_col1, m_col2, m_col3, m_col4, m_col5, m_col6 = st.columns(6)
        with m_col1:
            render_metric_card("Recovery Points", len(snapshots), subtitle="Available Backups", color_hex="#06b6d4")
        with m_col2:
            render_metric_card("Authority Objects", len(latest_objects), subtitle="RBAC Resources", color_hex="#38bdf8")
        with m_col3:
            render_metric_card("Verified", verified_count, subtitle="Policy Compliant", color_hex="#10b981")
        with m_col4:
            render_metric_card("Suspicious", suspicious_count, subtitle="Poisoned / Rogue", color_hex="#ef4444")
        with m_col5:
            render_metric_card("Unknown", unknown_count, subtitle="Missing Evidence", color_hex="#f59e0b")
        with m_col6:
            plan_status = "READY" if st.session_state.current_plan else "NONE"
            render_metric_card("Recovery Plan", plan_status, subtitle="Authority-Split", color_hex="#8b5cf6")

        st.markdown("---")

        d_col1, d_col2 = st.columns([3, 2])
        with d_col1:
            st.markdown("#### 💾 Recent Backup Recovery-Point Timeline")
            backup_list = st.session_state.backup_mgr.list_backups()
            b_data = []
            for b in backup_list:
                b_data.append({
                    "Backup Name": b.name,
                    "Status": b.status,
                    "Created At (UTC)": b.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "Namespaces": ", ".join(b.namespaces),
                    "Data Volume PV": "Protected" if b.pv_included else "Metadata Only",
                    "Items": b.total_items,
                    "Type": "Synthetic Lab" if b.is_synthetic else "Live Cluster",
                })
            st.dataframe(b_data, use_container_width=True, hide_index=True)

        with d_col2:
            st.markdown("#### 🎯 Active Evaluation Scenario")
            scenario_choice = st.selectbox(
                "Select Lab Attack Scenario",
                options=[
                    "scenario_1_unauthorized_cluster_admin",
                    "scenario_2_stealth_role_modification",
                    "scenario_3_trusted_addition_and_deletion",
                ],
                index=0 if st.session_state.scenario_id == "scenario_1_unauthorized_cluster_admin" else (
                    1 if st.session_state.scenario_id == "scenario_2_stealth_role_modification" else 2
                ),
            )
            if scenario_choice != st.session_state.scenario_id:
                st.session_state.scenario_id = scenario_choice
                st.session_state.current_plan = None
                st.session_state.exec_result = None
                st.session_state.verification_report = None
                st.rerun()

            st.markdown(
                f"""
                <div class="kv-interactive-card" style="margin-top: 0.5rem;">
                    <p style="margin: 0.2rem 0;"><span class="kv-badge kv-badge-verified">VERIFIED</span> <strong>{verified_count} objects</strong> satisfy trust policy.</p>
                    <p style="margin: 0.2rem 0;"><span class="kv-badge kv-badge-suspicious">SUSPICIOUS</span> <strong>{suspicious_count} objects</strong> flagged as compromised.</p>
                    <p style="margin: 0.2rem 0;"><span class="kv-badge kv-badge-unknown">UNKNOWN</span> <strong>{unknown_count} objects</strong> lack audit evidence.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("---")
        # Prerequisite Diagnostics Section
        render_prerequisite_diagnostics(tools, settings)

    # =========================================================================
    # PAGE 2: BACKUPS
    # =========================================================================
    elif active_page == "Backups":
        st.markdown("### 💾 Backup Manager & Inventory Inspector")
        st.caption("Inspect Kubernetes backups captured by Velero and verify persistent data volume coverage.")

        backups = st.session_state.backup_mgr.list_backups()
        selected_backup_name = st.selectbox(
            "Select Recovery Point to Inspect",
            options=[b.name for b in backups],
            index=1 if len(backups) > 1 else 0,
        )

        selected_b = next(b for b in backups if b.name == selected_backup_name)

        col_b1, col_b2, col_b3 = st.columns(3)
        with col_b1:
            st.metric("Backup Status", selected_b.status)
        with col_b2:
            st.metric("Created Timestamp (UTC)", selected_b.created_at.strftime("%Y-%m-%d %H:%M:%S"))
        with col_b3:
            st.metric("Data Volume Protection", "PVC Covered" if selected_b.pv_included else "Excluded")

        st.markdown("#### Captured Authority Objects Inventory")
        objs = st.session_state.backup_mgr.load_backup_objects(selected_backup_name)
        obj_table = []
        for o in objs:
            obj_table.append({
                "Kind": o.kind,
                "Namespace": o.namespace or "(cluster-scoped)",
                "Name": o.name,
                "Rules Count": len(o.rules),
                "Subjects Count": len(o.subjects),
                "Canonical SHA-256 Digest": f"{o.canonical_hash[:16]}...",
            })
        st.dataframe(obj_table, use_container_width=True, hide_index=True)

        st.markdown("---")
        st.markdown("#### Initiate Live Backup (Velero)")
        with st.form("create_backup_form"):
            new_b_name = st.text_input("New Backup Name", value="backup-payments-manual")
            new_b_ns = st.text_input("Target Namespaces (comma-separated)", value="payments-production")
            include_pvs = st.checkbox("Include Persistent Volume Snapshots", value=True)
            submit_backup = st.form_submit_button("Create Backup")

            if submit_backup:
                ns_list = [n.strip() for n in new_b_ns.split(",") if n.strip()]
                success, msg = st.session_state.backup_mgr.create_backup(new_b_name, ns_list, include_pvs)
                if success:
                    st.success(msg)
                else:
                    st.error(msg)

    # =========================================================================
    # PAGE 3: PROVENANCE
    # =========================================================================
    elif active_page == "Provenance":
        st.markdown("### 🔍 Provenance Classification Engine")
        st.caption("Reconstructed temporal history correlating Kubernetes API audit events with trust policy.")

        f_col1, f_col2 = st.columns([1, 2])
        with f_col1:
            state_filter = st.selectbox(
                "Filter by Classification State",
                options=["ALL", "VERIFIED", "SUSPICIOUS", "UNKNOWN"],
                index=0,
            )
        with f_col2:
            search_query = st.text_input("Search by Name or Kind", value="")

        filtered_objs = latest_objects
        if state_filter != "ALL":
            filtered_objs = [o for o in filtered_objs if o.provenance_state.value == state_filter]
        if search_query:
            filtered_objs = [
                o for o in filtered_objs
                if search_query.lower() in o.name.lower() or search_query.lower() in o.kind.lower()
            ]

        for obj in filtered_objs:
            state_class = f"kv-badge-{obj.provenance_state.value.lower()}"
            with st.expander(f"{obj.kind} / {obj.namespace or 'cluster'} / {obj.name} — {obj.provenance_state.value}"):
                st.markdown(
                    f"""
                    <span class="kv-badge {state_class}">● {obj.provenance_state.value}</span>
                    <strong style="margin-left: 0.5rem; font-family: monospace;">{obj.qualified_name}</strong>
                    """,
                    unsafe_allow_html=True,
                )
                if obj.evidence:
                    st.write(f"**Actor**: `{obj.evidence.actor}`")
                    st.write(f"**Timestamp**: `{obj.evidence.timestamp.isoformat() if obj.evidence.timestamp else 'Not in audit window'}`")
                    st.write(f"**Evidence Strength**: `{obj.evidence.strength.value}`")
                    st.write(f"**Classification Rationale**: {obj.evidence.reason}")
                    if obj.evidence.warnings:
                        for w in obj.evidence.warnings:
                            st.warning(w)

                st.markdown("**Canonical SHA-256 Digest:**")
                st.code(obj.canonical_hash, language="text")

                st.markdown("**Normalized Resource Manifest:**")
                st.code(yaml.dump(obj.raw_manifest, sort_keys=False), language="yaml")

    # =========================================================================
    # PAGE 4: RECOVERY PLANNER
    # =========================================================================
    elif active_page == "Recovery Planner":
        st.markdown("### ⚖️ Authority-Split Recovery Planner")
        st.caption("Synthesizes application data recovery with a verified, defensible authorization frontier.")

        p_col1, p_col2 = st.columns(2)
        with p_col1:
            app_backup_choice = st.selectbox(
                "Application Recovery Point (Data Plane)",
                options=list(snapshots.keys()),
                index=len(snapshots) - 1,
                help="Newest snapshot containing application database records and persistent volumes.",
            )
        with p_col2:
            st.info(
                "**Target Authority Frontier (Authority Plane):** Auto-discovered by KubeVyuha "
                "by verifying audit provenance backwards until a defensible state with 0 unmitigated threats is proven."
            )

        if st.button("⚖️ Generate Recovery Plan", type="primary"):
            planner = AuthoritySplitPlanner(st.session_state.policy, st.session_state.actors_config)
            try:
                plan = planner.generate_plan(snapshots, audit_res.events, application_backup_name=app_backup_choice)
                st.session_state.current_plan = plan
                st.session_state.exec_result = None
                st.session_state.verification_report = None
                st.success(f"Generated recovery plan: {plan.plan_id}")
            except Exception as e:
                st.error(f"Planning failed: {e}")

        plan = st.session_state.current_plan
        if plan:
            st.markdown("---")
            st.markdown(f"#### Plan Details: `{plan.plan_id}`")

            # Metrics
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                render_metric_card("Data Plane Snapshot", plan.application_backup_name, subtitle="Workloads & PVs", color_hex="#06b6d4")
            with c2:
                render_metric_card("Authority Frontier", plan.authority_frontier_backup_name, subtitle="Verified Base", color_hex="#10b981")
            with c3:
                render_metric_card("Excluded Suspicious", plan.excluded_objects_count, subtitle="Poisoned Objects", color_hex="#ef4444")
            with c4:
                render_metric_card("Held for Review", plan.held_objects_count, subtitle="Operator Review", color_hex="#f59e0b")

            # Warnings
            if plan.warnings:
                for w in plan.warnings:
                    render_callout(w, level="warn")

            # Permission Delta
            st.markdown("#### Effective Permission Delta")
            delta = plan.permission_delta
            d1, d2 = st.columns(2)
            with d1:
                st.markdown(f"**Revoked Attacker Grants ({len(delta.removed_permissions)}):**")
                if delta.removed_permissions:
                    for r in delta.removed_permissions:
                        st.markdown(f"- ❌ `{r.to_string()}`")
                else:
                    st.write("*(No permissions revoked)*")
            with d2:
                st.markdown(f"**Preserved Verified Grants ({len(delta.preserved_permissions)}):**")
                for p in delta.preserved_permissions[:8]:
                    st.markdown(f"- ✅ `{p.to_string()}`")
                if len(delta.preserved_permissions) > 8:
                    st.caption(f"...and {len(delta.preserved_permissions) - 8} more verified grants.")

            # Actions Table
            st.markdown("#### Prescribed Actions per Resource")
            actions_table = []
            for a in plan.actions:
                actions_table.append({
                    "Resource": a.object_identifier,
                    "Action": a.action.value,
                    "State": a.provenance_state.value,
                    "Approval Required": "YES" if a.requires_human_approval else "NO",
                    "Rationale": a.reason,
                })
            st.dataframe(actions_table, use_container_width=True, hide_index=True)

            # Execution Gate
            st.markdown("---")
            st.markdown("#### Execution Approval Gate")
            confirmed = st.checkbox(
                "I have reviewed the permission delta and confirm the execution of this recovery plan.",
                value=plan.is_approved,
            )

            if confirmed and not plan.is_approved:
                plan.is_approved = True
                st.session_state.current_plan = plan
                st.rerun()

            if plan.is_approved:
                st.success("Plan is APPROVED for execution.")
                if st.button("🚀 Apply Recovery Plan", type="primary"):
                    executor = GuardedExecutor(st.session_state.settings)
                    exec_result = executor.execute_plan(plan, human_confirmed=True)
                    st.session_state.exec_result = exec_result

                    # Automatically run post-recovery verification
                    verifier = PostRecoveryVerifier(st.session_state.settings)
                    st.session_state.verification_report = verifier.verify_plan(plan)
                    st.rerun()

        if st.session_state.exec_result:
            res = st.session_state.exec_result
            st.markdown("---")
            st.markdown("#### Execution Results")
            if res.success:
                mode_label = "SIMULATION (OFFLINE DEMO)" if res.is_simulation else "LIVE CLUSTER APPLY"
                st.success(f"Execution Completed Successfully [{mode_label}]: Applied {res.applied_resources_count} objects, purged {res.purged_resources_count} objects.")
            else:
                st.error("Execution failed.")
                for err in res.errors:
                    st.error(err)

            with st.expander("View Execution Diagnostic Logs"):
                for log_line in res.logs:
                    st.text(log_line)

    # =========================================================================
    # PAGE 5: VERIFICATION
    # =========================================================================
    elif active_page == "Verification":
        st.markdown("### ✅ Post-Recovery Verification")
        st.caption("Verifies actual cluster state and confirms neutralization of unauthorized authority.")

        if st.session_state.verification_report:
            rep = st.session_state.verification_report
            v1, v2, v3 = st.columns(3)
            with v1:
                st.metric("Overall Post-Recovery Status", rep.overall_status)
            with v2:
                st.metric("Security & Health Checks Passed", f"{rep.passed_checks} / {rep.total_checks}")
            with v3:
                st.metric("Verification Mode", "Live kubectl" if rep.is_live_verification else "Offline Verification")

            st.markdown("#### Verification Check Suite")
            check_table = []
            for c in rep.checks:
                check_table.append({
                    "Check Name": c.name,
                    "Target Identity": c.target_identity,
                    "Expected": c.expected_result,
                    "Actual": c.actual_result,
                    "Result": "PASSED ✅" if c.passed else "FAILED ❌",
                    "Details": c.details,
                })
            st.dataframe(check_table, use_container_width=True, hide_index=True)

            if rep.unresolved_risks:
                st.markdown("#### Outstanding Unresolved Risks")
                for u in rep.unresolved_risks:
                    st.warning(u)
        else:
            st.info("No active recovery plan executed yet. Generate and approve a plan in the 'Recovery Planner' tab to view post-recovery verification.")

    # =========================================================================
    # PAGE 6: REPORTS & EVALUATION
    # =========================================================================
    elif active_page == "Reports":
        st.markdown("### 📄 Export & Comparative Evaluation")
        st.caption("Export machine-readable plans and view empirical comparison across recovery baselines.")

        if st.session_state.current_plan:
            plan = st.session_state.current_plan
            writer = PlanWriter(st.session_state.settings.report_dir)
            json_file = writer.export_json(plan)
            md_file = writer.export_markdown_report(plan)
            yaml_file = writer.export_yaml_manifests(plan)

            e1, e2, e3 = st.columns(3)
            with e1:
                st.download_button(
                    "📥 Download Plan JSON",
                    data=json_file.read_text(encoding="utf-8"),
                    file_name=json_file.name,
                    mime="application/json",
                )
            with e2:
                st.download_button(
                    "📄 Download Markdown Report",
                    data=md_file.read_text(encoding="utf-8"),
                    file_name=md_file.name,
                    mime="text/markdown",
                )
            with e3:
                st.download_button(
                    "📦 Download YAML Manifests",
                    data=yaml_file.read_text(encoding="utf-8"),
                    file_name=yaml_file.name,
                    mime="application/x-yaml",
                )

        st.markdown("---")
        st.markdown("#### 🧪 Empirical Baseline Strategy Comparison")
        st.caption("Compares KubeVyuha against common alternative Kubernetes disaster recovery approaches.")

        if st.button("🧪 Run Comparative Benchmark"):
            evaluator = BaselineEvaluator()
            st.session_state.benchmark_result = evaluator.run_benchmark_on_scenario(
                scenario_dir=f"lab/scenarios/{st.session_state.scenario_id}"
            )

        if st.session_state.benchmark_result:
            bench = st.session_state.benchmark_result
            b_rows = []
            for r in bench.results:
                b_rows.append({
                    "Strategy": r.strategy_name,
                    "Attacker Privileges Remaining": f"{r.attacker_privileges_remaining} ⚠️" if r.attacker_privileges_remaining > 0 else "0 (Clean) ✅",
                    "Legitimate Grants Preserved": r.legitimate_permissions_preserved,
                    "Workload Health": "PASSED ✅" if r.workload_health_passed else "FAILED ❌",
                    "App Data Recovered": "YES ✅" if r.application_data_recovered else "NO ❌",
                    "Manual Reviews Needed": r.objects_requiring_manual_review,
                    "Evidence Coverage": f"{r.evidence_coverage_percent}%",
                    "Execution Time": f"{r.execution_time_ms} ms",
                })
            st.dataframe(b_rows, use_container_width=True, hide_index=True)

    # =========================================================================
    # PAGE 7: SETTINGS & LIVE LAB
    # =========================================================================
    elif active_page == "Settings":
        st.markdown("### ⚙️ Settings & Live Kubernetes Lab Integration")
        st.caption("Configure trust policies, approved actors, and review Windows local lab setup instructions.")

        # Prerequisite Diagnostics Section
        render_prerequisite_diagnostics(tools, settings)

        st.markdown("---")
        st.markdown("#### 🛠️ Windows Setup Guide for Live Kubernetes Lab")
        st.markdown(
            """
            To run KubeVyuha against a live cluster on your Windows machine:

            1. **Enable Windows Virtualization & WSL 2**:
               - Ensure Virtualization is enabled in your BIOS/UEFI.
               - In PowerShell (Run as Administrator):
                 ```powershell
                 wsl --install
                 ```
            2. **Install Docker Desktop**:
               - Download and install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/).
               - In Docker Desktop settings, select **Use the WSL 2 based engine**.
            3. **Install Kubernetes CLI Tools**:
               - In PowerShell:
                 ```powershell
                 winget install Kubernetes.kubectl
                 winget install Kubernetes.kind
                 winget install VMware.Velero
                 ```
            4. **Create the Lab Cluster with API Audit Logging**:
               - From the KubeVyuha directory:
                 ```powershell
                 kind create cluster --name kubevyuha-lab --config lab/kind-config.yaml
                 ```
            5. **Deploy the Payments Microservice**:
                 ```powershell
                 kubectl apply -f lab/payments-app/manifests.yaml
                 ```
            """
        )

        st.markdown("---")
        st.markdown("#### 📜 Active Trust Policy")
        st.json(st.session_state.policy.model_dump())

        st.markdown("#### 👥 Configured Approved Actors & Compromised Identities")
        st.json(st.session_state.actors_config.model_dump())


if __name__ == "__main__":
    main()
