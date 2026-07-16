# OpenClaw 安全自检

`openclaw-security-self-check` 用于对当前 OpenClaw 主机执行基于证据的只读安全自检。它不会修改 OpenClaw 配置、文件权限、服务、防火墙、软件包或用户，也不会创建 canary 或执行主动攻击探针。

## 适用场景

- 上线前检查 OpenClaw 主机的基础安全状态。
- 定期检查 Gateway、认证、沙箱、exec、工具权限、日志、更新源和 IM 白名单。
- 为内部审计或整改跟踪生成 JSON、Markdown 报告。
- 在不暴露真实凭证和私人消息的前提下收集可复核证据。

这个 Skill 只负责检查、OpenClaw Agent 定向只读复核和报告，不会自动修复发现的问题。自动检查无法判断的项目会生成结构化 `manualReview`；Agent 收集的脱敏机器证据会经过脚本校验后进入正式报告。

## 前置条件

- Node.js 可用。
- `openclaw` CLI 可用。
- Skill 所在主机就是需要检查的 OpenClaw 主机。
- 运行账号有权读取当前 OpenClaw profile 的配置和状态目录。

## 推荐用法

直接在对话中输入：

> 请调用 `openclaw-security-self-check`，以 `baseline` 模式对当前 OpenClaw 主机执行严格只读安全自检。禁止修复或修改系统状态；返回检查摘要、全部非 PASS 项、对应证据及报告文件路径。

也可以通过 Skill 命令明确调用：

```text
/openclaw-security-self-check 请以 baseline 模式检查当前 OpenClaw 主机，不要修复任何问题。
```

检查指定 profile 时，应在请求中明确 profile 名称：

> 请调用 `openclaw-security-self-check`，对 OpenClaw profile `prod` 执行 baseline 安全自检。保持只读，返回 JSON 和 Markdown 报告。

## 两种模式

| 模式          | 是否访问当前 OpenClaw | 是否修改系统状态 | 用途                                                        |
| ------------- | --------------------- | ---------------- | ----------------------------------------------------------- |
| `baseline`    | 是                    | 否               | 自动取证，并由 OpenClaw Agent 定向复核 `NOT_TESTED`         |
| `report-only` | 否                    | 否               | 合并已有 baseline/manual-review，生成 JSON 和 Markdown 报告 |

两种模式都不会修改被审计系统。写入用户明确指定的报告文件属于审计输出，不属于系统整改。

### baseline

这是默认模式。它通过只读命令和文件元数据检查当前主机，包括：

- Gateway 绑定、监听端口和认证状态；
- 沙箱与工作区文件系统策略；
- exec 的有效权限和人工审批策略；
- tool profile、allow、deny、`alsoAllow` 与 `tools.agentToAgent`；
- OpenClaw 进程账号、状态目录、配置文件和状态目录 `.env` 权限；
- 日志、脱敏、更新通道、软件包来源和 IM 白名单。
- npm registry 签名的密码学验证，以及绑定官方仓库和发布工作流的 Sigstore/SLSA provenance 验证。

baseline 不会通过实际越权访问来验证控制。只读证据足以确认配置和运行状态时可以得到 `PASS`；无法取得所需证据时返回 `NOT_TESTED` 或 `ERROR`。每条 `NOT_TESTED` 都会获得稳定 `reviewId`，供 OpenClaw Agent 执行定向只读复核。

初始 baseline 完成后，先生成复核模板：

```bash
node scripts/report-merge.mjs \
  --baseline <baseline.json> \
  --review-template-out <manual-review.json> \
  --json-out <report.json> \
  --markdown-out <report.md>
```

Agent 按模板逐项调查并填写脱敏 observation 后，合并最终报告：

```bash
node scripts/report-merge.mjs \
  --baseline <baseline.json> \
  --manual-review <manual-review.json> \
  --json-out <report.json> \
  --markdown-out <report.md>
```

### report-only

此模式不调用 OpenClaw，也不重新检查主机。它读取已有 baseline JSON，可选合并已有 manual-review JSON，校验证据绑定和检查结构，重新计算摘要，并生成便于归档的 JSON 和中文 Markdown 报告。

## 报告状态

| 状态             | 含义                                           |
| ---------------- | ---------------------------------------------- |
| `PASS`           | 所需只读证据已收集，配置或运行状态符合检查要求 |
| `WARN`           | 已有证据，但配置偏弱、含例外或需要人工复核     |
| `FAIL`           | 证据表明控制缺失或配置明显不安全               |
| `NOT_TESTED`     | 目标组件未运行，或所需只读证据无法取得         |
| `ERROR`          | 证据收集、解析或版本兼容性失败                 |
| `NOT_APPLICABLE` | 已证明当前主机没有对应组件                     |

`NOT_TESTED` 不代表安全，只表示当前证据不足。

报告会为每条 `NOT_TESTED` 生成带 `reviewId` 的 `manualReview`。OpenClaw Agent 必须使用当前版本 CLI、源码契约和定向只读主机命令收集证据，并填写 manual-review JSON。报告脚本只接受绑定当前 baseline 的复核项；没有当前主机机器证据时不能输出 `PASS`。

## 安全边界

- 不输出或持久化 token、密码、API key、Cookie、SecretRef 内容和私人消息。
- 不修改配置、权限、服务、防火墙、软件包或用户。
- 不创建 canary，不执行越权访问、路径穿越或测试性高危命令。
- 不验证公网可达性、真实第三方 IM 未授权账号和远程 SIEM 投递。
- 不自动修复；整改必须由用户单独授权。
- 报告虽然会脱敏，但仍包含端口、策略、finding id 和文件权限等安全姿态信息，应按内部安全材料保存和共享。

## 常见问题

### 为什么报告中有 `NOT_TESTED`？

常见原因包括 Gateway 未运行、日志路径无法确定、Windows ACL 无法读取，或当前 OpenClaw 版本没有所需的 CLI JSON 接口。Skill 不会为了得到 `PASS` 而执行主动探针。

报告会列出 OpenClaw Agent 必须执行的定向只读复核动作。Agent 将调查结果写入 manual-review JSON；如果仍然缺少证据，就记录具体阻塞原因并保留 `NOT_TESTED`。

日志路径由运行时推导时，可以直接记录脱敏的文件元数据，也可以先只读定位当前实际日志文件，再运行：

```bash
node scripts/host-baseline.mjs \
  --json \
  --log-path <实际日志文件> \
  --output <baseline.json>
```

重跑后脚本会核验该文件的对象类型和权限，并同时更新审计日志完整性与敏感信息脱敏两个检查项。

baseline 重跑后时间和内容会改变，必须重新生成 manual-review 模板；旧复核文件会因为 baseline 绑定不匹配而被拒绝。

### npm 来源验证如何判定 PASS？

只有以下验证全部成功时，软件包来源检查才会得到 `PASS`：

- registry 使用 HTTPS；
- `dist.integrity` 使用 SHA-512；
- 使用 registry 公钥对 `openclaw@<version>:<integrity>` 的签名完成密码学验证；
- Sigstore 验证 SLSA provenance bundle；
- provenance subject 与包版本和 SHA-512 一致；
- provenance 绑定官方 `openclaw/openclaw` 仓库、受信任发布分支和发布 workflow。

网络不可用或无法加载 OpenClaw 的 `sigstore` 依赖时返回 `NOT_TESTED`；签名无效、provenance 缺失或信任策略不匹配时返回 `FAIL`。

### 会自动修复问题吗？

不会。Skill 只生成证据和报告。需要整改时，应先单独审阅修复方案，再由用户明确授权实施。

### 报告中的建议会修改系统吗？

不会。报告里的建议只是只读审计结论的解释，例如建议收紧 `tools.agentToAgent.allow` 或保护 `.env` 权限。任何配置、权限或服务变更都必须作为单独任务执行。

### 为什么报告保留英文状态和配置字段？

`PASS` 等状态、检查 ID、JSON 字段和 OpenClaw 配置键是稳定的机器接口，保留英文便于脚本处理；面向用户的说明、标题和操作指引使用中文。

## 更多信息

- 检查矩阵：`references/check-matrix.md`
- 证据与状态规则：`references/evidence-rules.md`
- OpenClaw 运行契约：`references/openclaw-contracts.md`
- OpenClaw Agent 定向复核证据：`references/manual-review-evidence.md`
