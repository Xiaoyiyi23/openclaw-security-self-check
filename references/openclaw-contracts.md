# OpenClaw Contracts Used by This Skill

Prefer public CLI JSON interfaces over reading raw configuration directly. The CLI applies configuration loading and secret-redaction rules.

## Commands

```bash
openclaw --version
openclaw config get <path> --json
openclaw security audit --deep --json
openclaw sandbox explain --json
openclaw sandbox explain --agent <id> --json
openclaw exec-policy show --json
openclaw update status --json
npm config get registry
```

Place root arguments such as `--profile <name>` before the subcommand.

## Effective-Value Rules

- A valid `OPENCLAW_GATEWAY_PORT` overrides `gateway.port`.
- A valid `OPENCLAW_LOG_LEVEL` overrides `logging.level`.
- `OPENCLAW_NO_AUTO_UPDATE` disables automatic updates even when configuration enables them.
- `OPENCLAW_CLAWHUB_URL` takes precedence over `CLAWHUB_URL`. When neither is set, use `https://clawhub.ai`.
- `--profile <name>` selects `~/.openclaw-<name>` unless an explicit state/configuration environment variable overrides that path.
- Exec policy uses layered merging. `mode` expands into security/ask; a later explicit security/ask layer removes the inherited mode label.
- Exec `mode=auto` means allowlist/on-miss with automatic review, not evidence of human approval.
- The exec approval-file policy is a security ceiling. It can restrict but cannot expand the policy derived from configuration.
- Exec `host=auto` resolves to sandbox when a sandbox is active and to Gateway otherwise. Sandbox defaults are `deny/off`; non-sandbox defaults are `full/off`.
- Tool `profile=full` expands to wildcard access. A non-empty `allow` containing `*` is not a restrictive policy.
- Tool `alsoAllow` expands the current profile. Without a restrictive profile or explicit allowlist, it retains the default tool surface; `alsoAllow: ["*"]` means full access.
- When `tools.agentToAgent.enabled=true` and `allow` is unset, the current policy matches any Agent. `allow: ["*"]` also means any Agent; other patterns containing `*` use case-insensitive wildcard matching.
- A Channel with policy `disabled` ignores inbound traffic. An enabled Channel with `open` or wildcard access is not hardened.
- After account overrides, Telegram group-sender policy resolves as `groupAllowFrom ?? allowFrom`.

## mDNS

- The current OpenClaw default and recommendation is `discovery.mdns.mode="minimal"`; `off` is stricter. Both pass this check.
- `full` publishes additional host metadata. Return `WARN` when the Gateway is bound only to loopback and `FAIL` for other bindings, consistent with the native security audit's exposure classification.

## npm Source Verification

- Do not return `PASS` merely because `dist.signatures` is non-empty.
- Use the registry public key from `/-/npm/v1/keys` to verify the signature over `openclaw@<version>:<dist.integrity>`.
- Verify the npm attestation's Sigstore bundle, SLSA subject SHA-512, official repository, release workflow, trusted branch, GitHub Actions builder, and OIDC issuer.
- This verification proves the source and integrity of the registry artifact. It does not prove that the local installation directory was never modified after installation.

## Source References

When adapting to a new OpenClaw version, inspect:

- `src/config/paths.ts`: State/configuration paths and effective Gateway port.
- `src/cli/profile.ts`: Root-profile projection.
- `src/logging/env-log-level.ts`: Effective log level.
- `src/infra/update-startup.ts`: Effective update behavior.
- `src/infra/exec-approvals.ts`: Exec mode and approval boundaries.
- `src/infra/exec-policy.ts`: Policy-layer precedence.
- `src/agents/exec-defaults.ts`: Runtime exec defaults.
- `src/agents/sandbox-tool-policy.ts` and `src/agents/agent-tools.policy.ts`: `alsoAllow` and profile precedence.
- `src/plugin-sdk/session-visibility.ts`: Cross-Agent access semantics for `tools.agentToAgent.enabled`, an empty allow value, and wildcard allow patterns.
- `src/commands/sandbox-explain.ts`: Sandbox-explain semantics.
- `src/security/audit-channel.ts`: Effective Channel-policy audit.
- `extensions/telegram/src/bot-core.ts`: Telegram sender-allowlist inheritance.
- `extensions/browser/src/browser/config.ts`: Browser/CDP port derivation.
- `src/security/audit-gateway-config.ts`: Risk classification for mDNS full mode.
- `scripts/openclaw-npm-postpublish-verify.ts`: Trust policy for npm registry signatures and Sigstore/SLSA provenance.

If command output no longer matches the expected JSON structure, return `ERROR` with the OpenClaw version. Do not silently fall back to guessed defaults.
