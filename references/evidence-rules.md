# Evidence and Status Rules

## Status Vocabulary

- `PASS`: Every required read-only subcheck was performed and affirmative machine evidence was obtained.
- `WARN`: Evidence is available, but the setting is weak, ambiguous, or depends on an operator-controlled exception.
- `FAIL`: Evidence shows that a required control is missing or the configuration is clearly insecure.
- `NOT_TESTED`: The target is not running or required read-only evidence cannot be obtained.
- `ERROR`: Evidence collection, parsing, or version compatibility failed.
- `NOT_APPLICABLE`: Evidence proves that the relevant component is absent from the current host, for example when no IM Channel is enabled.

Aggregate severity in this order:

```text
ERROR > FAIL > NOT_TESTED > WARN > PASS > NOT_APPLICABLE
```

Use `NOT_APPLICABLE` only when effective configuration proves that the component is absent. Missing configuration or collection failure does not prove absence.

## Required Evidence

Every observation must contain, either directly or through report metadata:

- Check ID.
- Method: `static` or `runtime`.
- Timestamp.
- Sanitized fact or command result.
- Source command, file metadata source, or OpenClaw audit finding ID.

Do not store:

- Tokens, passwords, API keys, cookies, or SecretRef values.
- Raw private messages or model transcripts.
- Complete environment-variable dumps.
- Approval socket tokens.
- Any secret or sensitive sample created to validate a control.

## PASS Threshold

- A check may receive `PASS` when read-only configuration and runtime state are sufficient to prove the control defined in the check matrix.
- Current-host CLI output, process/listener facts, and file metadata collected through targeted OpenClaw Agent review are machine evidence, but they must be written to the manual-review file in the sanitized structure defined by `references/manual-review-evidence.md` and pass report-script validation.
- Source-code contracts and Agent reasoning may explain current-host machine evidence but cannot produce `PASS` by themselves.
- `PASS` means only that the observed configuration and state comply. It does not mean that penetration testing or behavioral bypass testing was performed.
- OpenClaw exec `mode=auto` means automatic review, not evidence of human approval.
- An enabled allowlist containing `*` is open access and cannot receive an allowlist `PASS`.
- A disabled Channel ignores inbound traffic. Wildcard entries left under a disabled policy do not make it open.
- When an environment variable overrides a configuration value, evaluate the effective value.
- POSIX permissions must verify the expected object type and exact mode. On Windows, ACL evidence is required; otherwise return `NOT_TESTED`.
- Do not infer runtime facts from configuration when the target process, listener, or log file cannot be found.

## Read-Only Constraints

- Do not create canaries, test sessions, test users, or temporary Agents.
- Do not perform anonymous Gateway requests, unauthorized reads, directory traversal, commands outside an allowlist, or fake-secret writes.
- Do not modify configuration, permissions, services, firewall rules, packages, users, or databases.
- Do not write to the assessed host state except for report output files explicitly requested by the user.
- `report-only` reads existing reports only and does not invoke OpenClaw or host assessment commands.

## Targeted Review of NOT_TESTED

- Every `NOT_TESTED` observation must generate a `manualReview` item with a stable `reviewId`, check ID, evidence gap, and required read-only review action.
- In baseline mode, the OpenClaw Agent must perform a minimal, targeted, read-only investigation for each item and write the result to a manual-review JSON file bound to the current baseline.
- After a manual-review observation passes validation, it replaces the corresponding `NOT_TESTED` observation. Recalculate the check status from all remaining observations.
- A manual review may address only a `reviewId` listed in the current baseline. Reject the merge when the baseline time, version, state directory, or configuration path does not match.
- Report-only mode may merge a manual-review JSON file supplied by the user, but it must not run host commands independently.
- Agent reasoning cannot replace machine evidence. If evidence remains unavailable, write a new `NOT_TESTED` observation that records the checks performed and the specific blocker.
- When the log path is derived at runtime, locate the actual log file using read-only methods and record structured file metadata, or rerun the permission check with `host-baseline.mjs --log-path <actual-path>`. Regenerate the manual-review template after rerunning the baseline.

## Report Metadata

Reports must include:

- Schema version.
- Checklist version.
- Skill name and version.
- OpenClaw version.
- Host operating system and architecture.
- State directory and configuration path.
- Mode.
- Start and finish times.
- Generated report paths.
- Manual-review input or template path and counts of merged and pending items.
- Excluded external-validation scope.
