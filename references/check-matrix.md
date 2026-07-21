# Read-Only Host Check Matrix

This Skill covers only checks that can be verified through configuration, CLI output, process information, and file metadata on the current OpenClaw host. It does not run active attack probes.

| Check | Required read-only evidence | PASS criteria | Typical reason for NOT_TESTED |
| ----- | --------------------------- | ------------- | ----------------------------- |
| OpenClaw-1-1 | Effective Gateway port/bind, Browser/CDP ports, mDNS mode, and host listeners | Configuration and observed listeners are limited to the expected interfaces; mDNS is the recommended `minimal` mode or the stricter `off` mode | Gateway or Browser is not running, so runtime listeners cannot be verified |
| OpenClaw-1-2 | Effective authentication mode, native audit findings for weak tokens, and configuration-file permissions | Authentication is enabled, no weak-credential finding exists, and the configuration file is protected | The CLI cannot provide authentication or audit evidence |
| OpenClaw-2-1 | `openclaw sandbox explain --json` for every configured Agent | Agents that require sandboxing report `mode=all` and the session is sandboxed | Sandbox-explain output cannot be obtained |
| OpenClaw-2-2 | `tools.fs.workspaceOnly`, sandbox workspaceAccess, and object types and permissions for the state directory, configuration file, and `.env` | workspaceOnly is effective, workspaceAccess is restricted, and sensitive paths have correct permissions | Windows ACLs cannot be read or the target path is inaccessible |
| OpenClaw-3-1 | Effective exec host/security/ask/mode and approval allowlist | Effective security is deny/allowlist and the allowlist contains no broad pattern | exec-policy JSON is unavailable or structurally incompatible |
| OpenClaw-3-2 | Effective exec ask/mode and autoReview state | Execution is denied, or the policy explicitly requires human approval and automatic review is disabled | The effective approval policy cannot be parsed |
| OpenClaw-3-3 | Global and per-Agent profile/allow/alsoAllow/deny, `tools.agentToAgent`, and process account/SID | The tool surface is restricted, cross-Agent access is disabled or uses an explicit allowlist, and the runtime account is not root/Administrator/SYSTEM | No running process is found or its owner cannot be identified |
| OpenClaw-4-1 | Effective state of `OPENCLAW_NO_AUTO_UPDATE`, update.auto, and checkOnStart | Update checks are enabled while automatic installation is disabled | Required configuration cannot be read |
| OpenClaw-5-3 | Channel history limits, contextTokens, and compaction mode | Explicit limits are reasonable and compaction is configured correctly | Required configuration cannot be read |
| OpenClaw-7-1 | Effective log level and log-file object type and permissions | Logging is enabled and log-file permissions are protected | The log path is generated at runtime and cannot be located |
| OpenClaw-7-2 | Deep security audit, loop detection, and local monitoring configuration | The deep audit succeeds with no severe finding, and anomaly detection is configured correctly | The security audit cannot run or be parsed |
| OpenClaw-7-3 | redactSensitive, custom redaction patterns, and log-file permissions | Redaction is not disabled and, when the log file can be located, its permissions are protected | The log path or permissions cannot be obtained |
| OpenClaw-9-3 | Effective update channel, npm/ClawHub URL, SHA-512 integrity, registry keys, and Sigstore/SLSA provenance | A stable controlled channel and HTTPS sources are used; registry signatures are cryptographically verified; provenance verifies successfully and is bound to the official OpenClaw release workflow | Network, registry, or Sigstore verification capability is unavailable |
| OpenClaw-11-1 | Effective Channel DM/group policy, allowFrom/groupAllowFrom, and native audit findings | Enabled Channels do not use open or wildcard access and their allowlists are non-empty | Plugin-specific policies cannot be parsed through public configuration or audit interfaces |

## Read-Only Assurance Boundary

- `PASS` means that observable effective configuration and runtime state meet the check requirements. It does not mean that penetration testing was performed.
- Do not validate controls through real anonymous requests, unauthorized reads, directory traversal, commands outside an allowlist, or fake-secret writes.
- Do not create test Agents, change production Agent policies, or temporarily elevate privileges.
- Do not read real SSH keys, cloud metadata, databases, user documents, private messages, or production secrets.
- Public network reachability, real unauthorized third-party IM accounts, and remote SIEM delivery are out of scope.

## Conditions That Cannot Be Verified

Return `NOT_TESTED`, never a guessed `PASS`, when:

- The target component is not running and the required runtime state cannot be obtained.
- The public CLI does not return the required JSON structure.
- Windows ACLs, process ownership, or log-file metadata cannot be read.
- A Channel uses plugin-specific policies that cannot be parsed through public interfaces.
- Evidence exists only in an inaccessible external system.
