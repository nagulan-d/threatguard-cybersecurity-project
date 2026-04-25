# Experiment Execution Kit

## Purpose
This kit defines a complete execution protocol for thesis-grade and publication-grade experiments on the CTI response system. It includes run controls, data-capture sheets, statistical reporting rules, and appendices for ethics, reproducibility, and dataset declaration.

## 1. Pre-Run Controls

### 1.1 Environment Integrity
1. Confirm backend dependencies and services are operational.
2. Confirm frontend client can reach backend API.
3. Confirm database schema is current for test run.
4. Confirm host firewall commands execute with required privileges.
5. Confirm VM agent enforcement permissions are active.

### 1.2 Configuration Integrity
1. Explicitly set regime: simulation or live.
2. Record threshold, max blocks per cycle, and delay parameters.
3. Record synchronization enable or disable status.
4. Record notification path enable or disable status.
5. Save full environment variable snapshot for this run.

### 1.3 Safety Controls
1. Use isolated and authorized test network only.
2. Verify unblock rollback path before every run.
3. Restrict blocked targets to approved test indicators.
4. Define and document abort conditions.

## 2. Experimental Matrix

| Run ID | Regime | Scenario | Threshold | Sync | VM Status | Notification | Repetitions |
|---|---|---|---:|---|---|---|---:|
| R01 | Simulation | Manual Only | 75 | Off | Up | Off | 5 |
| R02 | Simulation | Auto Conservative | 75 | On | Up | Off | 5 |
| R03 | Simulation | Auto Aggressive | 60 | On | Up | Off | 5 |
| R04 | Live | Auto Conservative | 75 | On | Up | On | 5 |
| R05 | Live | Sync Disabled Baseline | 75 | Off | Up | On | 5 |
| R06 | Live | Degraded VM | 75 | On | Down | On | 5 |

## 3. Standard Run Procedure
1. Initialize run ID and metadata sheet.
2. Start required services for selected scenario.
3. Confirm health status of host and VM components.
4. Execute scenario input batch.
5. Capture event-level logs and synchronization states.
6. Perform controlled cleanup and unblock verification.
7. Export raw and aggregated data artifacts.
8. Mark run status as completed, partial, or failed.

## 4. Metadata Capture Sheet

| Field | Value |
|---|---|
| Run ID |  |
| Timestamp Start (UTC) |  |
| Timestamp End (UTC) |  |
| Operator |  |
| Regime |  |
| Scenario |  |
| Threshold |  |
| Max Blocks Per Cycle |  |
| Delay Between Blocks |  |
| Sync Enabled |  |
| Notification Enabled |  |
| Backend Build or Commit |  |
| VM Agent Version |  |
| Notes |  |

## 5. Event-Level Data Sheet

| Event ID | T Start | T End | Event Type | Threat ID | Indicator | Score | Action | Host Result | VM Result | Final Sync State | Error |
|---|---|---|---|---|---|---:|---|---|---|---|---|
|  |  |  | detect_to_block |  |  |  | block |  |  |  |  |

## 6. Aggregated Metrics Sheet

| Run ID | Mean D2B ms | Median D2B ms | P95 D2B ms | Sync Complete % | Sync Partial % | Sync Fail % | Mean Recovery s | Duplicates Prevented % | False Positives | Notification Success % |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
|  |  |  |  |  |  |  |  |  |  |  |

## 7. Statistical Analysis Rules
1. Compute descriptive statistics per run.
2. Aggregate by regime and scenario separately.
3. Compare key pairs:
   1. conservative vs aggressive threshold.
   2. sync on vs sync off.
   3. VM up vs VM down.
4. Report confidence intervals where sample size allows.
5. Report effect size for major comparisons.

## 8. Quality Gates Before Publication
1. No cross-regime metric mixing.
2. Failed and partial runs retained in dataset.
3. Outlier policy documented before analysis.
4. Missing-data policy documented before analysis.
5. Every chart traceable to raw event logs.

## 9. Failure Taxonomy

| Class | Description | Example | Severity |
|---|---|---|---|
| F1 Auth | Authorization failure | role or token rejection | High |
| F2 Host Enforce | Host firewall failure | command execution error | High |
| F3 VM Enforce | VM rule failure | iptables or ufw rejection | High |
| F4 Sync | State divergence | partial completion | Medium |
| F5 Notify | Notification failure | send or delivery failure | Medium |
| F6 Data | Input quality issue | malformed indicator | Low |

## 10. Reproducibility Bundle Checklist
1. Metadata sheet.
2. Event-level sheet.
3. Aggregated metrics sheet.
4. Run-specific logs.
5. Configuration snapshot.
6. Dependency versions.
7. Analysis script or notebook.
8. Figure export set.

## 11. Figure Generation Plan
1. Boxplot: D2B latency by scenario.
2. Stacked bars: sync completion outcomes.
3. Line chart: false positives vs threshold.
4. Scatter: score vs enforcement outcome.
5. Bar chart: notification success and user action delay.

## 12. Final Reporting Checklist
1. Every claim linked to a metric table or figure.
2. Every table and figure labeled by regime.
3. Validity threats and limitations explicitly listed.
4. No unverifiable runtime claim in conclusion.
5. Appendix includes ethics and dataset declaration.

## Appendix A. Ethics Statement (Fillable)
1. Scope of authorized infrastructure:
2. Confirmation no third-party systems were targeted:
3. Data minimization and redaction policy:
4. Operator oversight policy for auto-enforcement:
5. Incident rollback and safety protocol:

## Appendix B. Reproducibility Statement (Fillable)
1. Code snapshot identifier:
2. Environment and OS details:
3. Dependency versions:
4. Configuration archive location:
5. Raw log archive location:
6. Analysis scripts location:
7. Re-run instructions reference:

## Appendix C. Dataset Declaration (Fillable)
1. Synthetic dataset source and generation rules:
2. Live-feed source and acquisition window:
3. Inclusion and exclusion criteria:
4. Sensitive field handling:
5. Retention policy:
6. Data access controls:

## Appendix D. Data Dictionary Template

| Field | Type | Description | Source | Notes |
|---|---|---|---|---|
| run_id | string | unique run identifier | experiment controller | required |
| threat_id | string | event identifier | feed or generator | may be null |
| indicator | string | actionable indicator | feed or generator | sanitized |
| score | number | risk score | scoring module | 0 to 100 |
| action | string | block or unblock | orchestrator | required |
| host_result | string | host enforcement outcome | host control | enum |
| vm_result | string | VM enforcement outcome | VM agent | enum |
| sync_state | string | final sync status | sync manager | enum |
| error | string | failure detail | any component | optional |

## Appendix E. Run Sign-Off Template
Run ID:

Operator:

Regime:

Scenario:

All required artifacts collected: Yes or No

Quality gates passed: Yes or No

Comments:
