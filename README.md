# KubeVyuha (🛡️)

> **Recover the data. Verify the authority.**  
> *Provenance-Guided Split Recovery for Kubernetes*

---

## 1. Overview

**KubeVyuha** is a Kubernetes backup recovery security and authorization assurance system. 

Kubernetes backups created by tools like Velero capture both application state (deployments, statefulsets, databases, persistent volumes) and authorization resources (**Roles, ClusterRoles, RoleBindings, ClusterRoleBindings, and ServiceAccounts**).

If an attacker introduces an unauthorized permission escalation or compromises an administrative account, that malicious privilege is captured in subsequent backups. Restoring a naive backup restores the attacker's persistent backdoor.

### The Problem with Traditional Restore Strategies
1. **Latest Backup Restore**: Restores the latest application data, but reintroduces dangerous or compromised authorization objects.
2. **Excluding All RBAC**: Avoids poisoned roles, but strips away legitimate permission updates required by upgraded workloads, causing application outages.
3. **Restoring Old Backup**: Reverts to an uncompromised RBAC state, but loses all recent application transactions and data.
4. **Static Security Scans**: Flags broad permissions (e.g., wildcards) but lacks temporal provenance—unable to distinguish an approved emergency patch from an attacker's injected binding.

### The Solution: Authority-Split Restore
KubeVyuha introduces **Authority-Split Restore**:
- Reconstructs the historical provenance of every authority object from Kubernetes audit logs and backup inventories.
- Classifies object versions into **Verified**, **Suspicious**, or **Unknown**.
- Selects the newest valid **Application Recovery Point** (restoring application workloads and data).
- Identifies an independent **Verified Authority Frontier** (restoring only trusted, evidenced authorization states).
- Produces an explainable, deterministic recovery plan with permission deltas and human approval gates before execution.

---

## 2. Architecture & Directory Structure

```
kubevyuha/
├── app.py                      # Streamlit application entrypoint (Top navigation)
├── pyproject.toml              # Project configuration and tool settings
├── requirements.txt            # Dependency definitions
├── .env.example                # Configuration template
├── config/
│   ├── approved_actors.example.yaml  # Trusted administrators and CI/CD identities
│   └── trust_policy.example.yaml     # Verification rules and compromise windows
├── authsplit/                  # Core Authority-Split Engine
│   ├── settings.py             # Configuration and tool detection
│   ├── models.py               # Data models for RBAC, Audit, and Recovery
│   ├── normalizer.py           # Canonicalization and SHA-256 object hasher
│   ├── audit_parser.py         # Streaming JSON-lines Kubernetes audit log parser
│   ├── backup_reader.py        # Backup manifest & inventory parser
│   ├── provenance.py           # Provenance classification engine (Verified/Suspicious/Unknown)
│   ├── authority_graph.py      # RBAC subject-binding-role resolution & permission calculator
│   ├── planner.py              # Authority-Split recovery planner
│   ├── plan_writer.py          # Plan serialization (JSON, YAML manifests, Markdown reports)
│   ├── command_runner.py       # Safe subprocess execution with strict argument isolation
│   ├── executor.py             # Human-approved execution engine with safety gates
│   └── verifier.py             # Post-recovery cluster authorization verifier
├── ui/
│   ├── theme.py                # High-contrast DevSecOps console theme & CSS
│   └── components.py           # Navigation bars, metric cards, and status badges
├── lab/                        # Disposable local Kubernetes lab environment
│   ├── README.md               # Lab setup instructions (kind + Velero + MinIO)
│   ├── kind-config.yaml        # Local kind cluster configuration with audit logging
│   └── audit-policy.yaml       # Kubernetes audit logging policy
├── tests/
│   ├── unit/                   # Deterministic unit tests (parsers, normalizer, planner)
│   ├── integration/            # Multi-component workflow tests
│   └── fixtures/               # Synthetic audit logs and backup manifests
├── docs/                       # Technical documentation
│   ├── ARCHITECTURE.md         # Component design and data flow
│   ├── THREAT_MODEL.md         # In-scope and out-of-scope threat boundaries
│   ├── METHODOLOGY.md          # Formal Authority-Split algorithm description
│   ├── TESTING.md              # Test execution and scenario validation
│   ├── TROUBLESHOOTING.md      # Common failure recovery steps
│   └── LIMITATIONS.md          # Research prototype scope and non-guarantees
└── reports/                    # Generated recovery plans and audit dossiers
```

---

## 3. Quickstart & Installation

### Prerequisites
- **Python 3.12+**
- **Git**
- *(Optional for Live Cluster Mode)*: Docker, `kind`, `kubectl`, and `velero`

### 1. Clone & Set Up Environment
```bash
git clone <repository_url>
cd kubevyuha

# Create and activate virtual environment (optional but recommended)
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
# Copy example environment configuration
cp .env.example .env
```

### 3. Launch KubeVyuha Console
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 4. Operational Modes

KubeVyuha operates under two distinct modes:

1. **Offline Demo & Evaluation Mode (Default when cluster tools are absent)**:
   - Uses synthetic, deterministic Kubernetes audit streams and multi-point backup inventories.
   - Evaluates real attack scenarios (compromised CI token, unauthorized ClusterRoleBinding, stealth Role modification).
   - Never fakes cluster success; clearly labeled with an **OFFLINE DEMO** status banner.

2. **Live Cluster Mode (When `kubectl` and `velero` are installed)**:
   - Interacts with a local test cluster (`kind`).
   - Reads live Velero backup manifests and cluster audit streams.
   - Strictly enforces safe defaults: read-only planning mode, context verification, and explicit human confirmation before any mutation.

---

## 5. Running Automated Tests

Run the comprehensive unit test suite:
```bash
pytest
```

Run code formatting and linting:
```bash
ruff check .
```

---

## 6. Safety Notice

> **Important**: KubeVyuha is a research prototype evaluating the Authority-Split recovery methodology. It starts in **read-only planning mode**. It will never execute cluster modifications without an explicit plan, an authorized target context, and a human confirmation step.
