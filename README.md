# HackerRank Orchestrate - October 2026

## Ghost Data Still Exists

Build an AI agent that audits whether a user's personal data was actually deleted.

A deletion workflow may report **Complete** while data still exists in databases, logs, support attachments, exports, search indexes, archives, or backups. Sync and restore processes may also bring deleted data back.

For each request, the agent must first determine whether deletion was actually requested. It then returns `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`, reports any remaining data or recreation risk, and produces the ordered remediation and verification steps required to finish an authorized deletion safely.

Read [`problem_statement.md`](./problem_statement.md) for the complete challenge contract.

---

## Quick Start

Clone the repository and move into the project directory:

```bash
git clone https://github.com/interviewstreet/hackerrank-orchestrate-october26.git
cd hackerrank-orchestrate-october26
```

Start your AI coding tool from the **repository root** so it automatically reads [`AGENTS.md`](./AGENTS.md) and logs your session turns to `log.txt` in the root directory.

Build your solution in `code/main.py`, or use another language and document its setup and run command clearly in your README.

Your solution must:

- Read the input files from `dataset/`
- Generate one prediction row for every request in `dataset/deletion_requests.csv`
- Write the final predictions to `output.csv` in the repository root

Run the starter Python entry point with:

```bash
python3 code/main.py
```

The blank template at `dataset/output.csv` is provided as a reference. Your final generated file for submission must be the root-level `output.csv`.

---

## System Architecture & Approach Overview

Our deletion-audit agent implements an enterprise-grade compliance pipeline designed to detect "ghost data", replication drift, and data resurrection risks across heterogeneous infrastructure.

```
                      ┌──────────────────────────────────────────────┐
                      │          Deletion Request Ingestion          │
                      │  (Intent Classification: Delete vs Non-Del)  │
                      └──────────────────────┬───────────────────────┘
                                             │
                      ┌──────────────────────▼───────────────────────┐
                      │     Bidirectional Identity Lineage Graph     │
                      │  (Current Snapshot + Historical Audit Log:    │
                      │   Emails, Phones, Names, SHA-256 Hashes)     │
                      └──────────────────────┬───────────────────────┘
                                             │
                      ┌──────────────────────▼───────────────────────┐
                      │    Temporal Multi-Modal Evidence Grounding   │
                      │   (Cutoff <= audit_at: SQLite DB Replicas,   │
                      │    JSON SRE Exports, Logs, PDFs & Images)    │
                      └──────────────────────┬───────────────────────┘
                                             │
                      ┌──────────────────────▼───────────────────────┐
                      │       GDPR & Policy Compliance Engine        │
                      │  (deletion_rules.csv: Delete vs Anonymize vs │
                      │   Redact vs Preserve Account Tombstone)      │
                      └──────────────────────┬───────────────────────┘
                                             │
                      ┌──────────────────────▼───────────────────────┐
                      │  Dependency-Ordered Remediation & Proving    │
                      │  1. Disable flows & block restores           │
                      │  2. Delete downstream search / support data  │
                      │  3. Redact / Anonymize retained tombstones   │
                      │  4. Emit evidence-backed verification checks │
                      └──────────────────────────────────────────────┘
```

### Core Pipeline Pillars

1. **Intent Disambiguation (`NOT_APPLICABLE` Classification)**:
   - Evaluates `request_text` across multiple languages.
   - Distinguishes Article 17 Right to Erasure requests from Article 15 Subject Access Requests (SAR), data portability inquiries, marketing opt-outs, or account credentials resets.
   - Returns `NOT_APPLICABLE` with `steps_json = []` for non-deletion requests.

2. **Bidirectional Identity Resolution Graph**:
   - Resolves both current identities (`user_identities.csv`) and historical state changes (`user_audit_log.csv`).
   - Normalizes and matches historical email updates, former phone numbers, previous legal names, and historical SHA-256 email hashes used across obfuscated analytics profiles.

3. **Temporal Grounding & Multi-Modal Evidence Inspection**:
   - Strictly obeys the temporal contract: uses only evidence files and activity timestamps with `captured_at <= audit_at`.
   - **SQL Snapshots**: Executes schema-agnostic SQLite introspection (`PRAGMA table_info`) across primary, regional, and reporting replicas to detect un-synchronized records and JSON document tables (`record_json`).
   - **JSON & Structured Logs**: Parses service resource exports (`service_resource_export`, `records_assurance_snapshot_bundle`) and readback logs for active connectors.
   - **PDF & Image Documents**: Integrates local document extractors (PyMuPDF / Pillow) and grounded catalog cross-referencing to extract invoice and ticket data without relying on external cloud models.

4. **Account Tombstone & Retention Policy Enforcement**:
   - Complies with `deletion_rules.csv` without blindly deleting data subject to legal or security holds.
   - For `ACCOUNT_TOMBSTONE`, applies `REDACT_RECORD`: strips prohibited direct PII (name, email, phone, hash) while retaining the internal stable reference (`user_id`) to preserve referential integrity for retained security audit records (`security_service`).

5. **Race Condition Prevention & Dependency-Ordered Remediation**:
   - Enforces strict operational precedence: `FINDING` -> `REMEDIATION` -> `VERIFICATION`.
   - Prevents data resurrection by disabling active ETL/sync pipelines (`DISABLE_DATA_FLOW`) and blocking backup restore paths (`BLOCK_RESTORE`) *before* modifying records.
   - Within each phase, operations follow canonical precedence:
     - **Findings**: `REPORT_REMAINING_RECORD` -> `REPORT_EXPOSED_PII` -> `REPORT_ACTIVE_DATA_FLOW` -> `REPORT_RESTORE_RISK`
     - **Remediation**: `DISABLE_DATA_FLOW` -> `BLOCK_RESTORE` -> `DELETE_RECORD` -> `REDACT_RECORD` -> `ANONYMIZE_RECORD`
     - **Verification**: `VERIFY_RECORD_ABSENT` -> `VERIFY_RECORD_PRESENT` -> `VERIFY_RECORD_REDACTED` -> `VERIFY_RECORD_ANONYMIZED` -> `VERIFY_DATA_FLOW_DISABLED` -> `VERIFY_RESTORE_BLOCKED`

---

## Setup & Execution Instructions

### Prerequisites
- Python 3.10+ (tested on Python 3.12)
- Dependencies: `pandas`, `pymupdf` (fitz), `pillow`

```bash
pip install pandas pymupdf pillow
```

### Running the Audit Pipeline
To process all 518 production cases and generate the root `output.csv`:

```bash
python3 code/main.py
```

### Running the Evaluation Workflow
To run the automated evaluator and verify benchmark metrics:

```bash
python3 code/evaluation/main.py
```


## Dataset

All participant-facing files are in `dataset/`:

| File | Contents |
| --- | --- |
| `deletion_requests.csv` | 518 requests |
| `sample_deletion_requests.csv` | 32 sample requests |
| `sample_output.csv` | Correct sample answers |
| `user_identities.csv` | Current user identities |
| `user_audit_log.csv` | Historical identity changes |
| `system_activity.csv` | Activity across services and data processes |
| `deletion_rules.csv` | Required treatment for each data category |
| `evidence_files.csv` | Manifest of supplied evidence files |
| `output.csv` | Blank output template |

Evidence is stored under `dataset/evidence/` and may include PDFs, images, logs, JSON, plain text, or SQL snapshot exports. SQL captures may contain a primary database, regional replicas, a reporting replica, or a failover replica so replication drift can be investigated directly. The `.sql` files are readable as text and executable with SQLite.

Only `deletion_requests.csv` requires answers. The other files provide evidence and context.

---

## Output

Create `output.csv` with these columns in this exact order:

```text
case_id,deletion_status,steps_json
```

Produce exactly one row per request. `deletion_status` is `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`. `steps_json` is an ordered JSON array containing findings, remediation actions, and verification checks. Use an empty array (`[]`) for `NOT_APPLICABLE`. Evidence references may be a `file_id`, `activity_id`, or `audit_id`. Determine the resource state at `audit_at` from the available evidence; reported workflow statuses and operation results are claims. Use `dataset/sample_output.csv` as the format reference.

The final file must contain 518 data rows sorted by `case_id` (plus the header row). The grader parses `steps_json` as JSON, so object-key order and whitespace do not matter; array order does. Order findings, remediation, and verification in that phase order. Within a phase, follow the operation order in the problem statement, then sort by `system_id` and `resource_id`.

---

## Evaluation

`output.csv` will be compared with hidden canonical answers. Scoring considers:

- deletion assessment accuracy;
- current and historical identity resolution;
- discovery of remaining data and recreation risks;
- correct policy application and evidence references; and
- completeness and ordering of remediation and verification steps.

Your `code.zip` must include:

```text
code/evaluation/evaluation_report.md
code/evaluation/usage_report.md
```

- `evaluation_report.md` must cover case, row, field, and sequence accuracy, at least three additional evaluation cases created by you, failures found, and improvements made.
- `usage_report.md` must cover the final full-dataset run, including model providers and names, model calls, input and output tokens, total and average tokens per request, and estimated total and per-request cost. Include per-model and overall totals when using multiple models.

**Important:** Place `evaluation_report.md` and `usage_report.md` inside `code/evaluation/` (matching `code/evaluation/main.py` in this starter layout), write your complete evaluation metrics, custom evaluation test cases, and token/cost breakdowns directly inside those Markdown files, and keep prompts in source code or Markdown files. Automated code evaluation ignores raw data files (`.csv`, `.tsv`, `.json`, `.jsonl`, `.sql`, `.log`), so content stored only in those formats will not be visible to the code judge or AI interviewer.

---

## Chat Transcript

This repository includes [`AGENTS.md`](./AGENTS.md), which instructs compatible AI coding tools to append conversation summaries to `log.txt` in the repository root:

| Platform | Path |
| --- | --- |
| macOS / Linux | `<repo root>/log.txt` |
| Windows | `<repo root>\log.txt` |

- Always launch your AI coding agent from the repository root (or explicitly ask it to read `./AGENTS.md` first) so every turn is logged to `log.txt` with the required `User Prompt`, `Agent Response Summary`, `Actions`, and `Context` sections.
- Upload `log.txt` directly as your `chat_transcript` submission on HackerRank.
- Do not include API keys, tokens, credentials, or secrets in prompts, code, configuration, or `log.txt`.

---

## Packaging `code.zip` and Submission

| Item | Description |
| --- | --- |
| `code.zip` | Runnable solution, prompts, configuration, `README.md`, and `evaluation/` reports |
| `output.csv` | One answer row for each of the 518 requests in `dataset/deletion_requests.csv` |
| `chat_transcript` | The root `log.txt` file generated by your coding agent |
| AI interview | Live explanation of your architecture, approach, and evaluation |

You may use any programming language, model, framework, or retrieval approach. Include clear setup and execution instructions in `README.md` inside `code.zip`.

To package `code.zip` from the repository root without bundling the dataset:

**macOS / Linux:**

```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
```

**Windows (PowerShell):**

```powershell
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```

When packaging `code.zip`:

- Keep your evaluation reports in `code/evaluation/` so they are bundled automatically with `code` (or add `evaluation` to the archive command above if you placed them in a top-level `evaluation/` directory).
- Do **not** include `dataset/`, virtual environments (`.venv`, `venv`, `node_modules`), or build caches (`__pycache__`). On Windows, keep `.venv` at the repository root (outside `code/`) and remove any `code/__pycache__` folders before running `Compress-Archive`.
- Do **not** include nested archives (`.zip`, `.tar`, `.gz`, `.tgz`, `.7z`, `.rar`) inside `code.zip` — submissions containing nested archive files will be rejected.

Before submitting, confirm that:

- `output.csv` has the exact header `case_id,deletion_status,steps_json` and contains all 518 data rows sorted by `case_id`;
- every `steps_json` value is a valid JSON array with consecutive step numbers starting at `1`;
- findings cite valid evidence IDs, and `COMPLETE` verification steps cite evidence proving the current state;
- proposed remediation and future verification steps use an empty `evidence_id` (`""`);
- `code.zip` includes your runnable code, `README.md`, `code/evaluation/evaluation_report.md`, and `code/evaluation/usage_report.md`;
- `log.txt` follows the `AGENTS.md` turn format and is uploaded to the `chat_transcript` slot; and
- no API keys, credentials, real personal data, or sensitive configuration values are included.
