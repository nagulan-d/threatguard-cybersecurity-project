# 15-Slide Defense Script with Timing and Speaker Notes

## Timing Strategy
Total target: 14 to 16 minutes + Q and A.
Target pacing: 45 to 60 seconds per slide.

## Slide 1. Title and Context (45s)
### On Slide
Hybrid CTI Response and Synchronized Multi-Host IP Blocking

Presenter name, institution, date

### Speaker Script
This presentation describes a cyber defense system that closes the gap between threat detection and actual enforcement. The core focus is coordinated, low-latency blocking across Windows host and Linux VM environments, with both human-approved and automated response paths.

## Slide 2. Why This Problem Matters (50s)
### On Slide
1. Detection volume is high.
2. Containment remains delayed.
3. Multi-host consistency is difficult.

### Speaker Script
Security teams often know about threats quickly, but enforcement is fragmented across tools and systems. This creates avoidable exposure windows. Our work treats response orchestration as a measurable security problem.

## Slide 3. Problem Statement (50s)
### On Slide
A practical response system must be:
1. Fast.
2. Consistent.
3. Auditable.
4. Safely automated.

### Speaker Script
We define the problem as achieving these four properties simultaneously. Most real deployments satisfy only one or two, leading to partial policy enforcement and weak incident traceability.

## Slide 4. Research Questions (55s)
### On Slide
RQ1 latency impact

RQ2 synchronization reliability

RQ3 automation threshold tradeoff

RQ4 user action path effectiveness

### Speaker Script
Our evaluation is anchored on these four questions to ensure results are decision-relevant for SOC operations, not only academically descriptive.

## Slide 5. Architecture Overview (55s)
### On Slide
Threat Source -> Processing -> Dashboard and Email -> Block Orchestrator -> Windows and VM Enforcement -> Audit

### Speaker Script
The architecture transforms a threat event into an enforceable decision and then verifies completion across host and VM. Every action is logged to support post-incident analysis.

## Slide 6. Core Components (50s)
### On Slide
1. Threat scoring and categorization.
2. Role-aware user and admin workflow.
3. Tokenized email actions.
4. Threshold-based auto-blocking.
5. Real-time synchronization status.

### Speaker Script
The novelty is integration. These components are not isolated features; they form one operational control-plane from detection to containment.

## Slide 7. Threat Model (55s)
### On Slide
Assets, trust boundaries, adversary goals, controls, residual risk

### Speaker Script
We model unauthorized action, replay, sync tampering, and secret leakage as primary risks. The system applies role checks and token controls, but residual risk remains if deployment hardening is incomplete.

## Slide 8. Methodology and Regimes (60s)
### On Slide
Two regimes:
1. Simulation regime.
2. Live-feed regime.

### Speaker Script
Mode separation is mandatory for validity. Simulation and live feeds have different variance and behavior characteristics, so we report results per regime only.

## Slide 9. Scenarios and Metrics (60s)
### On Slide
Scenarios: manual, auto-conservative, auto-aggressive, sync-on, sync-off, degraded VM, notification-enabled

Metrics: D2B latency, sync completion, failure recovery, false positives, duplicate suppression, notification-action delay

### Speaker Script
These metrics evaluate practical response quality under realistic constraints. We care about consistency and recovery, not just average speed.

## Slide 10. Experimental Setup (50s)
### On Slide
Windows host, Linux/Kali VM, backend and frontend stack, isolated network, structured telemetry

### Speaker Script
Administrative firewall privileges are required on host. VM-side enforcement uses iptables or ufw. All runs use synchronized clocks and structured logs.

## Slide 11. Results Slide A: Latency (55s)
### On Slide
Table or boxplot of detection-to-block latency by scenario and regime

### Speaker Script
Highlight median and P95 values. Emphasize the difference between average speed and tail behavior under load or degraded sync conditions.

## Slide 12. Results Slide B: Reliability and Quality (60s)
### On Slide
Stacked bars for complete, partial, failed sync

Table for false positives and duplicate suppression

### Speaker Script
Show that synchronization quality changes final security posture. Partial enforcement can preserve attack surface despite successful detection.

## Slide 13. Findings and Interpretation (60s)
### On Slide
1. Automation improves speed.
2. Aggressive thresholds increase false-positive burden.
3. Synchronization improves consistency.
4. Real-time status improves triage.

### Speaker Script
Tie each finding directly to one research question and one observable metric trend.

## Slide 14. Limitations and Validity (50s)
### On Slide
Mode dependence, environment sensitivity, component overlap, hardening requirements

### Speaker Script
Limitations are explicit and scoped. This increases credibility and defines clear boundaries for claim strength.

## Slide 15. Conclusion and Next Steps (55s)
### On Slide
Synchronized response design is a decisive factor in actionable cyber defense.

Next: consolidation, signed commands, adaptive thresholds, formal sync verification

### Speaker Script
The key conclusion is that response architecture quality materially affects practical defense outcomes. Future work focuses on hardening and formal reliability improvements.

---

## Backup Q and A Script

### Q1. What is the main novelty?
A1. A unified response control-plane combining scoring, role workflows, automation policy, and synchronized multi-host enforcement with measurable consistency outcomes.

### Q2. Why not evaluate only live data?
A2. Controlled simulation is needed for repeatability and fair scenario comparison; live runs are used for external-validity checks, and both are reported separately.

### Q3. Which metric matters most operationally?
A3. Detection-to-consistent-enforcement latency, because detection without consistent enforcement still leaves exploitable exposure.

### Q4. What is the biggest practical risk?
A4. Over-blocking under aggressive thresholds. We mitigate with threshold tuning, cooldown limits, rollback support, and action auditing.

### Q5. What is required for production readiness?
A5. Consolidated orchestrator paths, stronger secret lifecycle controls, signed inter-service commands, and full integration test coverage of block and sync workflows.
