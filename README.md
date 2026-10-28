# CodeMender Continuous Multi-Repository Security Monitoring

Centralized reference architecture and control plane for scanning **100–500 enterprise repositories** with **CodeMender (`cm` v0.16.0+)** on a daily or weekly schedule on Google Cloud.

📄 **Architectural Design Document:** [`docs/codemender_fleet_scanning_design_doc.md`](docs/codemender_fleet_scanning_design_doc.md)

---

## Core Design Highlights

1. **Pre-Flight Remote SHA Filter**: Runs parallel `git ls-remote` checks before launching worker containers, skipping repositories whose `HEAD` SHA matches `last_scanned_sha`.
2. **Concurrency Control (Cloud Tasks + Cloud Workflows)**: Enforces concurrency limits (`15` delta workers / `8` deep workers) by bridging Cloud Tasks with a blocking **Cloud Workflow** (`cm-job-runner`) that polls **Cloud Run Jobs** until completion.
3. **Two-Mode Delta Engine (Cutoff at 5 Merged PRs)**:
   * **Mode A — Per-Commit `--diff` Replay (1–5 Merged PRs)**: Replays `cm find . --diff=<parent_sha>` per surviving merged PR along the first-parent commit graph (skipping commits whose touched lines were completely overwritten at `HEAD`), keeping each run within the 15-file 1-hop neighbor limit and attributing findings to the introducing commit.
   * **Mode B — Coalesced File-Scoped `--deep` via `--context` (>5 Merged PRs)**: Extracts extant modified source files (`--diff-filter=ACMR`) as a markdown bullet list (`- <path>`) and passes them via `cm find . --deep --context ...`, invoking CodeMender's native `scopeToProvidedFiles` engine across the modified files and their 1-hop dependency closure (promoting to full `--deep` if $\ge 20\%$ of repository files changed).
4. **4-Trigger Repository Drift Promotion**: Promotes drifted repositories to a full `cm find . --deep` re-baseline based on:
   * **Trigger 1**: First-party source file ($\ge 20\%$) or LOC ($\ge 25\%$) churn (excluding lockfiles, vendor directories, and unit tests).
   * **Trigger 2**: Immediate promotion on security sentinel code changes (`**/auth/**`, `**/crypto/**`, `**/security/**`, `**/middleware/**`) and a **14-day cooldown gate** on dependency manifest updates (`go.mod`, `package.json`, `requirements.txt`, `pom.xml`).
   * **Trigger 3**: Accumulated 1-hop neighbor truncation debt ($\ge 15$ skipped files).
   * **Trigger 4**: Maximum baseline age TTL (`30 days` for Tier-1 / `60 days` for Tier-2/3), staggered via `crc32(repo_id)` to cap daily deep scans at 10% of the fleet.
5. **Per-Repository State Locking & GCS Hydration**:
   * Acquires a per-repository lease in Cloud SQL and hydrates `$CM_HOME/state.db` and `.cm_project` from `cm_state.tar.zst` in GCS using a **prefix-downscoped GCS token**.
   * Syncs rejected Fix PRs (`false-positive` / `wontfix`) into `$CM_HOME/state.db` (`status = 'DISMISSED'`) prior to scanning, and uploads updated state with `--if-generation-match`.
6. **Customer Pipeline Controls, Reporting & Visualization**:
   * **4 Control Surfaces**: Fleet Manifest (`repos.yaml`), in-repo `.cm/config.yaml` & `.cmignore`, Terraform variables (`customer.tfvars`), and on-demand CLI/HTTP triggers & PR dismissal labels.
   * **3 Reporting Channels**: Looker Studio / BigQuery Fleet Dashboard (`cm stats --json`), native GitHub/GitLab SARIF + Draft Fix PRs (`cm report --format=sarif` & `cm --sandbox=false fix --yes`), and self-contained HTML compliance archives in GCS (`cm report --patches --artifacts --format=html`).
7. **Multi-Customer Terraform Module (`terraform/`)**: Deploys the control plane, queues, workflows, Cloud SQL registry, GCS state store, and Cloud Run Jobs via `terraform apply`.

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
│   └── worker/                                   # State manager, Mode A/B delta engine & verify/fix (Stages 3-5)
├── terraform/                                    # Multi-customer GCP Terraform module (Stage 6)
└── tests/                                        # Unit test suite
```
