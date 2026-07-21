# OpenClaw Security Self-Check

`openclaw-security-self-check` performs an evidence-based, read-only security assessment of the current OpenClaw host. It does not modify OpenClaw configuration, file permissions, services, firewall rules, packages, or users, and it does not create canaries or run active attack probes.

## Use Cases

- Assess the baseline security posture of an OpenClaw host before deployment.
- Periodically review Gateway exposure, authentication, sandboxing, exec controls, tool permissions, logging, update sources, and IM allowlists.
- Generate JSON and Markdown reports for internal audits or remediation tracking.
- Collect reproducible evidence without exposing real credentials or private messages.

This Skill performs checks, targeted read-only review by an OpenClaw Agent, and report generation only. It does not automatically remediate findings. Items that cannot be resolved by automated checks produce structured `manualReview` entries; sanitized machine evidence collected by the Agent is validated by the scripts before being included in the final report.

## Prerequisites

- Node.js is available.
- The `openclaw` CLI is available.
- The host running this Skill is the OpenClaw host to be assessed.
- The executing account can read the configuration and state directory of the current OpenClaw profile.

## Installation

In an OpenClaw conversation, ask the Agent to install this Skill directly from GitHub:

> Install the `openclaw-security-self-check` Skill from the [Xiaoyiyi23/openclaw-security-self-check](https://github.com/Xiaoyiyi23/openclaw-security-self-check) GitHub repository. After installation, confirm that Node.js and the `openclaw` CLI are available, and tell me the Skill installation directory and whether it can be invoked with `$openclaw-security-self-check`.

The Agent will install the repository into a Skill directory recognized by the current OpenClaw environment. After installation, invoke it using one of the examples below.

## Recommended Usage

Enter the following directly in a conversation:

> Invoke `openclaw-security-self-check` in `baseline` mode to perform a strict read-only security assessment of the current OpenClaw host. Do not remediate findings or modify system state. Return the assessment summary, every non-PASS item, the supporting evidence, and the report file paths.

You can also invoke it explicitly with a Skill command:

```text
/openclaw-security-self-check Assess the current OpenClaw host in baseline mode. Do not remediate any findings.
```

To assess a specific profile, include the profile name in the request:

> Invoke `openclaw-security-self-check` to run a baseline security assessment of the OpenClaw profile `prod`. Keep the assessment read-only and return the JSON and Markdown reports.

## Operating Modes

| Mode          | Accesses the current OpenClaw host | Modifies system state | Purpose                                                                    |
| ------------- | ---------------------------------- | --------------------- | -------------------------------------------------------------------------- |
| `baseline`    | Yes                                | No                    | Collects evidence and asks the OpenClaw Agent to review `NOT_TESTED` items |
| `report-only` | No                                 | No                    | Merges existing baseline/manual-review data into JSON and Markdown reports |

Neither mode modifies the assessed system. Writing report files explicitly requested by the user is considered audit output, not system remediation.

### baseline

This is the default mode. It uses read-only commands and file metadata to assess the current host, including:

- Gateway binding, listening ports, and authentication status;
- sandbox and workspace filesystem policies;
- effective exec permissions and human approval policies;
- tool profile, allow, deny, `alsoAllow`, and `tools.agentToAgent` settings;
- the OpenClaw process account and permissions on the state directory, configuration file, and state-directory `.env` file;
- logging, redaction, update channels, package sources, and IM allowlists;
- cryptographic verification of npm registry signatures and Sigstore/SLSA provenance bound to the official repository and release workflow.

The baseline does not validate controls by attempting actual unauthorized access. A check receives `PASS` only when read-only evidence is sufficient to confirm the relevant configuration and runtime state. If the required evidence cannot be obtained, the result is `NOT_TESTED` or `ERROR`. Every `NOT_TESTED` observation receives a stable `reviewId` for targeted read-only review by the OpenClaw Agent.

After the initial baseline is complete, generate the review template:

```bash
node scripts/report-merge.mjs \
  --baseline <baseline.json> \
  --review-template-out <manual-review.json> \
  --json-out <report.json> \
  --markdown-out <report.md>
```

After the Agent investigates each template item and fills in a sanitized observation, merge the final report:

```bash
node scripts/report-merge.mjs \
  --baseline <baseline.json> \
  --manual-review <manual-review.json> \
  --json-out <report.json> \
  --markdown-out <report.md>
```

### report-only

This mode does not invoke OpenClaw or reassess the host. It reads an existing baseline JSON file, optionally merges an existing manual-review JSON file, validates evidence binding and check structure, recalculates the summary, and generates archival JSON and Chinese-language Markdown reports.

## Report Statuses

| Status           | Meaning                                                                                   |
| ---------------- | ----------------------------------------------------------------------------------------- |
| `PASS`           | The required read-only evidence was collected and the configuration or runtime state complies with the check |
| `WARN`           | Evidence is available, but the configuration is weak, contains exceptions, or requires manual review         |
| `FAIL`           | Evidence shows that a required control is missing or the configuration is clearly insecure                    |
| `NOT_TESTED`     | The target component is not running, or the required read-only evidence could not be obtained                 |
| `ERROR`          | Evidence collection, parsing, or version compatibility failed                                                 |
| `NOT_APPLICABLE` | Evidence confirms that the corresponding component is not present on the current host                         |

`NOT_TESTED` does not mean secure. It only means that the available evidence is insufficient.

The report creates a `manualReview` entry with a `reviewId` for every `NOT_TESTED` observation. The OpenClaw Agent must collect evidence using the current CLI, source contracts, and targeted read-only host commands, then complete the manual-review JSON file. The report script accepts only review items bound to the current baseline; it cannot produce `PASS` without machine evidence from the current host.

## Security Boundaries

- Does not output or persist tokens, passwords, API keys, cookies, SecretRef contents, or private messages.
- Does not modify configuration, permissions, services, firewall rules, packages, or users.
- Does not create canaries or perform unauthorized access, path traversal, or high-risk test commands.
- Does not validate public network reachability, real unauthorized third-party IM accounts, or remote SIEM delivery.
- Does not automatically remediate findings; remediation requires separate user authorization.
- Reports are sanitized but still contain security posture information such as ports, policies, finding IDs, and file permissions. Store and share them as internal security material.

## Frequently Asked Questions

### Why does the report contain `NOT_TESTED` items?

Common reasons include a Gateway that is not running, an unknown log path, unreadable Windows ACLs, or an OpenClaw version that does not expose the required CLI JSON interface. The Skill does not run active probes merely to obtain a `PASS` result.

The report lists the targeted read-only review actions that the OpenClaw Agent must perform. The Agent records its findings in the manual-review JSON file. If evidence is still unavailable, it records the specific blocker and retains `NOT_TESTED`.

When the log path is derived at runtime, the Agent can record sanitized file metadata directly or locate the current log file using read-only methods and then run:

```bash
node scripts/host-baseline.mjs \
  --json \
  --log-path <actual-log-file> \
  --output <baseline.json>
```

After rerunning, the script validates the file object type and permissions and updates both the audit log integrity and sensitive-information redaction checks.

Rerunning the baseline changes its timestamp and content, so the manual-review template must be regenerated. An older review file will be rejected because its baseline binding no longer matches.

### What is required for npm source verification to receive `PASS`?

The package source check receives `PASS` only when all of the following validations succeed:

- the registry uses HTTPS;
- `dist.integrity` uses SHA-512;
- the signature over `openclaw@<version>:<integrity>` is cryptographically verified using the registry public key;
- Sigstore verifies the SLSA provenance bundle;
- the provenance subject matches the package version and SHA-512 digest;
- the provenance is bound to the official `openclaw/openclaw` repository, a trusted release branch, and the release workflow.

If the network is unavailable or the OpenClaw `sigstore` dependency cannot be loaded, the result is `NOT_TESTED`. An invalid signature, missing provenance, or mismatched trust policy results in `FAIL`.

### Does the Skill automatically remediate findings?

No. The Skill only generates evidence and reports. When remediation is required, review the proposed remediation separately and obtain explicit user authorization before implementation.

### Do the recommendations in the report modify the system?

No. Recommendations in the report only explain the conclusions of the read-only audit—for example, recommending tighter `tools.agentToAgent.allow` settings or stronger protection for `.env` permissions. Any configuration, permission, or service change must be performed as a separate task.

### Why does the report retain English statuses and configuration fields?

Statuses such as `PASS`, check IDs, JSON fields, and OpenClaw configuration keys are stable machine interfaces and remain in English for reliable script processing. User-facing explanations, headings, and operating instructions in the generated report are written in Chinese.

## More Information

- Check matrix: `references/check-matrix.md`
- Evidence and status rules: `references/evidence-rules.md`
- OpenClaw runtime contracts: `references/openclaw-contracts.md`
- Evidence requirements for targeted OpenClaw Agent review: `references/manual-review-evidence.md`
