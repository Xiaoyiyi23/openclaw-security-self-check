# 本 Skill 使用的 OpenClaw 契约

优先使用公开 CLI JSON 接口，不要直接读取原始配置；CLI 会应用配置加载和秘密脱敏规则。

## 命令

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

将 `--profile <name>` 等根参数放在子命令之前。

## 有效值规则

- 合法的 `OPENCLAW_GATEWAY_PORT` 覆盖 `gateway.port`。
- 合法的 `OPENCLAW_LOG_LEVEL` 覆盖 `logging.level`。
- `OPENCLAW_NO_AUTO_UPDATE` 会禁用自动更新，即使配置启用了自动更新。
- `OPENCLAW_CLAWHUB_URL` 优先于 `CLAWHUB_URL`，两者都未设置时使用 `https://clawhub.ai`。
- `--profile <name>` 选择 `~/.openclaw-<name>`，除非显式状态/配置环境变量覆盖该路径。
- Exec policy 采用分层合并。`mode` 会展开为 security/ask；后续显式 security/ask 层会移除继承的 mode 标签。
- Exec `mode=auto` 表示 allowlist/on-miss 加自动审查，不是人工审批证据。
- Exec approval 文件策略是安全上限，只能限制、不能扩大配置派生策略。
- Exec `host=auto` 在沙箱活动时解析为 sandbox，否则解析为 Gateway。沙箱默认 `deny/off`，非沙箱默认 `full/off`。
- Tool `profile=full` 展开为通配访问。非空 `allow` 包含 `*` 时不属于限制性策略。
- Tool `alsoAllow` 会扩大当前 profile。没有限制性 profile 或显式白名单时，它保留默认工具面；`alsoAllow: ["*"]` 表示完整访问。
- `tools.agentToAgent.enabled=true` 且 `allow` 未配置时，当前策略会让任意 Agent 匹配。`allow: ["*"]` 同样表示任意 Agent；含 `*` 的其他模式按大小写不敏感通配匹配。
- Channel policy 为 `disabled` 时忽略入站流量。已启用的 `open` 或通配访问不属于加固状态。
- Telegram group sender policy 在 account override 后按 `groupAllowFrom ?? allowFrom` 解析。

## mDNS

- 当前 OpenClaw 默认并推荐 `discovery.mdns.mode="minimal"`；`off` 更严格，两者均可通过本检查。
- `full` 会发布额外主机元数据。Gateway 仅绑定 loopback 时返回 `WARN`，其他绑定返回 `FAIL`，与原生安全审计的暴露判断保持一致。

## npm 来源验证

- 不得仅凭 `dist.signatures` 非空判定 `PASS`。
- 使用 registry `/-/npm/v1/keys` 公钥验证载荷 `openclaw@<version>:<dist.integrity>` 的签名。
- 验证 npm attestation 的 Sigstore bundle、SLSA subject SHA-512、官方仓库、发布 workflow、可信分支、GitHub Actions builder 和 OIDC issuer。
- 该验证证明 registry 发布物的来源与完整性，不证明本机安装目录在安装后从未被修改。

## 源码参考

适配新 OpenClaw 版本时检查以下源码：

- `src/config/paths.ts`：状态/配置路径和有效 Gateway 端口。
- `src/cli/profile.ts`：根 profile 投影。
- `src/logging/env-log-level.ts`：有效日志级别。
- `src/infra/update-startup.ts`：有效更新行为。
- `src/infra/exec-approvals.ts`：exec mode 和审批边界。
- `src/infra/exec-policy.ts`：policy 层优先级。
- `src/agents/exec-defaults.ts`：运行时 exec 默认值。
- `src/agents/sandbox-tool-policy.ts` 和 `src/agents/agent-tools.policy.ts`：`alsoAllow` 和 profile 优先级。
- `src/plugin-sdk/session-visibility.ts`：`tools.agentToAgent.enabled`、空 allow 和通配 allow 的跨 Agent 访问语义。
- `src/commands/sandbox-explain.ts`：sandbox explain 语义。
- `src/security/audit-channel.ts`：有效 Channel policy 审计。
- `extensions/telegram/src/bot-core.ts`：Telegram sender allowlist 继承。
- `extensions/browser/src/browser/config.ts`：Browser/CDP 端口推导。
- `src/security/audit-gateway-config.ts`：mDNS full 模式的风险分级。
- `scripts/openclaw-npm-postpublish-verify.ts`：npm registry 签名和 Sigstore/SLSA provenance 信任策略。

命令输出不再符合预期 JSON 结构时，返回带 OpenClaw 版本的 `ERROR`。不得静默退回猜测的默认值。
