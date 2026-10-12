# CodeMender Continuous Multi-Repository Security Monitoring

Centralized, automated reference architecture and control plane for continuously monitoring **100+ enterprise repositories** with **CodeMender (`cm` v0.12+)** on a recurring **daily or weekly schedule** on Google Cloud.

📄 **Full Architectural Design Document:** [`docs/codemender_fleet_scanning_design_doc.md`](docs/codemender_fleet_scanning_design_doc.md)

---

## Key Capabilities

1. **Zero-Token Pre-Flight Remote SHA Filter**: Polls remote `HEAD` SHAs (`git ls-remote`) in parallel before cloning, skipping unchanged repositories (~70%–80% daily) at **zero compute and zero token cost**.
2. **Blocking Concurrency Control (Cloud Tasks + Cloud Workflows)**: Enforces strict concurrency limits (`15` delta workers / `8` deep workers) by bridging Cloud Tasks with blocking **Cloud Workflows** (`cm-job-runner`) that poll **Cloud Run Jobs** until completion.
3. **Adaptive Two-Mode Daily Delta Engine**:
   * **Mode A — PR-Granular `--diff` Replay (1–8 Merged PRs)**: Replays `cm find . --diff=<parent_sha>` per surviving merged PR along the first-parent commit graph, preventing neighbor truncation (`--diff-max-neighbors=15`) and preserving exact PR/author attribution.
   * **Mode B — Coalesced File-Scoped `--deep` (>8 Merged PRs)**: Extracts extant modified source files (`--diff-filter=ACMR`) and runs `cm find <changed_files...> --deep` across the modified files and their 1-hop dependency closure (automatically promoting to full `--deep` if $\ge 20\%$ of repository files changed).
4. **Noise-Resistant 4-Trigger Repository Drift Evaluator**: Automatically promotes drifted repositories to a full `cm find . --deep` re-baseline based on:
   * **Trigger 1**: Source-only file ($\ge 20\%$) or LOC ($\ge 25\%$) churn (excluding lockfiles, vendor directories, and unit tests).
   * **Trigger 2**: Immediate promotion on security sentinel code changes (`**/auth/**`, `**/crypto/**`, `**/security/**`) and a **14-day cooldown gate** on dependency manifest bumps (`go.mod`, `package.json`, `requirements.txt`, `pom.xml`).
   * **Trigger 3**: Accumulated 1-hop neighbor truncation debt ($\ge 15$ truncated files).
   * **Trigger 4**: Maximum baseline age TTL (`30 days` for Tier-1 / `60 days` for Tier-2/3), staggered via `crc32(repo_id)` to cap daily deep scans at 10% of the fleet.
5. **Single-Writer GCS State Hydration & Closed-Loop Remediation**:
   * Hydrates `$CM_HOME/state.db` and `.cm_project` from a per-repository GCS archive (`cm_state.tar.zst`) using a **prefix-downscoped GCS token**.
   * Syncs rejected Fix PRs (`false-positive` / `wontfix`) via `cm triage --status=dismissed` prior to scanning.
   * Runs `cm find`, `cm verify`, and `cm fix` sequentially inside a single per-repository job (`--if-generation-match` on upload), eliminating SQLite split-brain race conditions.
6. **Turnkey Multi-Customer Terraform Blueprint (`terraform/`)**: Deploys the entire control plane, queues, workflows, Cloud SQL registry, GCS state store, and Cloud Run Jobs into any customer GCP project via `terraform apply`.

---

## Repository Structure

```text
codemender_multi_repo_daily_scanning/
├── docs/
│   └── codemender_fleet_scanning_design_doc.md   # Architectural Design Document
├── sql/
│   └── 001_init_schema.sql                       # Cloud SQL PostgreSQL DDL (Stage 1)
├── workflows/
│   └── cm_job_runner.yaml                        # Blocking Cloud Workflow for Cloud Run Jobs (Stage 6)
├── src/
│   ├── common/                                   # Models, DB abstraction & manifest loader (Stage 1)
│   ├── dispatcher/                               # Pre-flight SHA filter & 4-Trigger Drift Evaluator (Stage 2)
│   └── worker/                                   # State manager, Mode A/B delta engine & inline verify/fix (Stages 3-5)
├── terraform/                                    # Multi-customer GCP Terraform blueprint (Stage 6)
└── tests/                                        # Unit test suite
```

---

## Implementation Stages

* **Stage 0**: Repository Bootstrap & Design Documentation *(Current)*
* **Stage 1**: Core Data Models, Database Schema & Manifest Loader (`src/common/`, `sql/`)
* **Stage 2**: Pre-Flight SHA Filter & 4-Trigger Drift Evaluator (`src/dispatcher/`)
* **Stage 3**: Single-Writer GCS State Hydration & Closed-Loop PR Triage Sync (`src/worker/state_manager.py`, `src/worker/triage_sync.py`)
* **Stage 4**: Adaptive Two-Mode Delta Engine & Full Deep Scan Runner (`src/worker/git_ops.py`, `src/worker/scanner.py`)
* **Stage 5**: Inline Verify/Fix, Tiered Patch Delivery & BigQuery FinOps Telemetry (`src/worker/remediation.py`, `src/worker/telemetry.py`, `Dockerfile`)
* **Stage 6**: Turnkey Multi-Customer Terraform Blueprint (`terraform/`, `workflows/`)
