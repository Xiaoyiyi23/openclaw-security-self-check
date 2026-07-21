---
name: openclaw-security-self-check
description: "Perform a strict, evidence-based, read-only security assessment of the current OpenClaw host, review each NOT_TESTED item through targeted OpenClaw Agent investigation, and merge structured review evidence into a formal audit report. Also use this Skill to generate reports offline from existing baseline JSON and manual-review JSON files."
metadata: { "openclaw": { "requires": { "bins": ["node", "openclaw"] } } }
---

# OpenClaw Security Self-Check

Assess only facts that can be verified from read-only configuration, CLI output, process information, and file metadata on the current host. First use deterministic scripts to collect routine evidence, then have the OpenClaw Agent perform targeted read-only review of `NOT_TESTED` observations, and finally use the report script to validate and merge the structured review evidence.

## Mandatory Rules

- Do not return `PASS` without the machine evidence required by `references/evidence-rules.md`.
- Do not print or persist credential values, SecretRef contents, private messages, or real personal data.
- Do not modify OpenClaw configuration, firewall rules, packages, services, users, or permissions.
- Do not create canaries or perform unauthorized access, path traversal, high-risk test commands, or active Agent probes.
- Do not write to the assessed host state except for report output files explicitly requested by the user.
- Mark checks as `NOT_TESTED` or `ERROR` when required read-only evidence cannot be obtained. Never guess `PASS`.
- When `NOT_TESTED` appears, the OpenClaw Agent must perform each `manualReview.requiredAction` and record sanitized facts, source, time, and conclusion in a structured manual-review file.
- Agent inference, source-code contracts, or explanations cannot produce `PASS` by themselves. `PASS` requires reviewable machine evidence from the current target host.
- A manual review may address only a `reviewId` already present in the current baseline. It must not override a check that has no pending evidence gap.
- This Skill does not validate public network reachability, real unauthorized third-party IM accounts, or remote SIEM delivery.
- Do not automatically remediate findings. Remediation must be a separate task with explicit user authorization.
- Even sanitized reports contain host security-posture information. Remind the user to handle them as internal security material.

## Loading Reference Material

Read `references/check-matrix.md` before selecting checks. Read `references/evidence-rules.md` before assigning statuses. Read `references/manual-review-evidence.md` before processing `manualReview`. Read `references/openclaw-contracts.md` whenever OpenClaw CLI output, configuration structure, or version behavior is unclear.

## Modes

- `baseline`: Read configuration, CLI output, and host metadata from the current OpenClaw host; have the OpenClaw Agent perform targeted read-only review of `NOT_TESTED` observations; generate the merged formal report. This is the default mode.
- `report-only`: Read an existing baseline JSON file and optionally merge an existing manual-review JSON file. Do not run OpenClaw or host assessment commands.

There is no active-validation mode. Do not create temporary files or elevate privileges to supplement dynamic evidence.

## Baseline Workflow

1. Confirm that the target is the current OpenClaw host and state which OpenClaw profile or state directory will be assessed.
2. Run:

   ```bash
   node {baseDir}/scripts/host-baseline.mjs --json --output <baseline.json>
   ```

3. Add `--openclaw-bin <path>`, `--openclaw-arg <arg>`, `--state-dir <path>`, or `--config-path <path>` only in non-default runtime environments.
4. Generate the initial report and manual-review template:

   ```bash
   node {baseDir}/scripts/report-merge.mjs \
     --baseline <baseline.json> \
     --review-template-out <manual-review.json> \
     --json-out <report.json> \
     --markdown-out <report.md>
   ```

5. Inspect `fatal`, `ERROR`, `FAIL`, `WARN`, every `NOT_TESTED` observation, and `manualReview`. Do not hide unavailable evidence.
6. When `manualReview.required=true`, read `references/manual-review-evidence.md` and perform each `requiredAction`:
   - Run only the OpenClaw CLI, source-code lookup, and read-only host commands directly related to that evidence gap.
   - Do not perform broad host enumeration or active attack probes.
   - Record sanitized evidence and the conclusion in the `observation` for the corresponding `reviewId` in `<manual-review.json>`.
   - If the result is still indeterminate, use `NOT_TESTED` and record the read-only checks performed and the specific blocker.

7. If the actual log file can be located, let the baseline script collect file-permission evidence directly:

   ```bash
   node {baseDir}/scripts/host-baseline.mjs \
     --json \
     --log-path <actual-log-file> \
     --output <baseline.json>
   ```

   Regenerate the manual-review template after the baseline changes. The report script must reject an old template that no longer matches the new baseline.

8. Merge the OpenClaw Agent's structured review evidence and generate the final outputs:

   ```bash
   node {baseDir}/scripts/report-merge.mjs \
     --baseline <baseline.json> \
     --manual-review <manual-review.json> \
     --json-out <report.json> \
     --markdown-out <report.md>
   ```

9. Inspect `agentReview` and the remaining `manualReview`. Retain `NOT_TESTED` only for items that still lack machine evidence.

## Report-Only Workflow

1. Do not run any OpenClaw or host assessment commands.
2. Read the baseline JSON supplied by the user. If the user also supplies a manual-review JSON file, merge only that file and do not independently perform its host-review actions.
3. Run:

   ```bash
   node {baseDir}/scripts/report-merge.mjs \
     --baseline <baseline.json> \
     --json-out <report.json> \
     --markdown-out <report.md>
   ```

   Add the following when merging existing structured review evidence:

   ```bash
   --manual-review <manual-review.json>
   ```

4. Return `ERROR` for invalid report input. Do not invent missing evidence.
5. If the report still contains `manualReview`, clearly tell the user to return to the target OpenClaw host and perform the listed read-only reviews. `report-only` must not run those commands itself.

## Deliverables

Return:

- Overall status and counts.
- Every `FAIL`, `ERROR`, `WARN`, and `NOT_TESTED` item with concise evidence.
- Every merged `agentReview`, pending `manualReview`, and remaining evidence blocker.
- Exact paths to the JSON and Markdown reports.
- The exact path to the manual-review JSON file when used.
- The selected mode, profile, or state directory.
- The assurance boundary: only read-only evidence from the local host is covered.
- A report-sensitivity notice and non-executing remediation guidance for non-PASS items.

Do not automatically remediate findings. If the user requests remediation, provide a separate, staged remediation plan and wait for explicit authorization.
