---
name: openclaw-security-self-check
description: "对当前 OpenClaw 主机执行基于证据的严格只读安全自检，逐项处理 NOT_TESTED 的 OpenClaw Agent 定向复核，并将结构化复核证据合并为正式审计报告。也用于根据已有 baseline JSON 和 manual-review JSON 离线整理报告。"
metadata: { "openclaw": { "requires": { "bins": ["node", "openclaw"] } } }
---

# OpenClaw 安全自检

只评估能够通过当前主机上的只读配置、CLI 输出、进程信息和文件元数据验证的事实。先使用确定性脚本收集常规证据，再由 OpenClaw Agent 对 `NOT_TESTED` 执行定向只读复核，最后由脚本校验并合并结构化复核证据。

## 强制规则

- 未取得 `references/evidence-rules.md` 要求的机器证据时，不得输出 `PASS`。
- 不得打印或持久化凭证值、SecretRef 内容、私人消息或真实个人数据。
- 不得修改 OpenClaw 配置、防火墙规则、软件包、服务、用户或权限。
- 不得创建 canary，或执行越权访问、路径穿越、测试性高危命令和 Agent 主动探针。
- 除用户指定的报告输出文件外，不得写入被审计主机状态。
- 无法取得必需只读证据的检查必须标记为 `NOT_TESTED` 或 `ERROR`，不得猜测为 `PASS`。
- 出现 `NOT_TESTED` 时，必须由 OpenClaw Agent 逐项执行 `manualReview.requiredAction`，并把脱敏事实、来源、时间和结论写入结构化 manual-review 文件。
- Agent 的推测、源码契约或解释不能单独产生 `PASS`；`PASS` 必须包含当前目标主机的可复核机器证据。
- manual-review 只能处理当前 baseline 中已有的 `reviewId`，不得覆盖没有待复核证据缺口的检查结果。
- 不在本 Skill 中验证公网可达性、真实第三方 IM 未授权账号或远程 SIEM 投递。
- 不得自动修复。整改必须作为独立任务等待用户明确授权。
- 报告即使已脱敏，也包含主机安全姿态信息；交付时提醒用户按内部安全材料处理。

## 加载参考资料

选择检查项前读取 `references/check-matrix.md`。判定状态前读取 `references/evidence-rules.md`。处理 `manualReview` 前读取 `references/manual-review-evidence.md`。OpenClaw CLI 输出、配置结构或版本行为不明确时读取 `references/openclaw-contracts.md`。

## 模式

- `baseline`：读取当前 OpenClaw 主机的配置、CLI 输出和主机元数据；对 `NOT_TESTED` 执行 OpenClaw Agent 定向只读复核；生成合并后的正式报告。默认模式。
- `report-only`：读取已有 baseline JSON，并可合并已有 manual-review JSON；不运行 OpenClaw 或主机检查命令。

不存在主动验证模式。不得自行创建临时文件或提升权限来补充动态证据。

## baseline 流程

1. 确认目标是当前 OpenClaw 主机，并说明检查的 OpenClaw profile 或状态目录。
2. 运行：

   ```bash
   node {baseDir}/scripts/host-baseline.mjs --json --output <baseline.json>
   ```

3. 仅在非默认运行环境中添加 `--openclaw-bin <path>`、`--openclaw-arg <arg>`、`--state-dir <path>` 或 `--config-path <path>`。
4. 生成初始报告和 manual-review 模板：

   ```bash
   node {baseDir}/scripts/report-merge.mjs \
     --baseline <baseline.json> \
     --review-template-out <manual-review.json> \
     --json-out <report.json> \
     --markdown-out <report.md>
   ```

5. 检查 `fatal`、`ERROR`、`FAIL`、`WARN`、每个 `NOT_TESTED` 和 `manualReview`。不得隐藏无法取得的证据。
6. `manualReview.required=true` 时，读取 `references/manual-review-evidence.md`，逐项执行 `requiredAction`：
   - 只运行与该证据缺口直接相关的 OpenClaw CLI、源码查询和主机只读命令；
   - 不进行宽泛主机枚举，不执行主动攻击探针；
   - 在 `<manual-review.json>` 对应 `reviewId` 的 `observation` 中记录脱敏证据和结论；
   - 仍无法判断时写入 `NOT_TESTED`，记录已经执行的只读检查和具体阻塞原因。

7. 能够定位实际日志文件时，可以使用以下方式让 baseline 脚本直接取得文件权限证据：

   ```bash
   node {baseDir}/scripts/host-baseline.mjs \
     --json \
     --log-path <实际日志文件> \
     --output <baseline.json>
   ```

   baseline 改变后，重新生成 manual-review 模板；旧模板与新 baseline 不匹配，报告脚本必须拒绝合并。

8. 合并 OpenClaw Agent 的结构化复核证据并生成最终输出：

   ```bash
   node {baseDir}/scripts/report-merge.mjs \
     --baseline <baseline.json> \
     --manual-review <manual-review.json> \
     --json-out <report.json> \
     --markdown-out <report.md>
   ```

9. 检查 `agentReview` 和剩余 `manualReview`。只有仍然缺少机器证据的项目才保留 `NOT_TESTED`。

## report-only 流程

1. 不运行任何 OpenClaw 或主机检查命令。
2. 读取用户提供的 baseline JSON；如果用户同时提供 manual-review JSON，只合并该文件，不自行执行其中的主机复核动作。
3. 运行：

   ```bash
   node {baseDir}/scripts/report-merge.mjs \
     --baseline <baseline.json> \
     --json-out <report.json> \
     --markdown-out <report.md>
   ```

   合并已有结构化复核证据时添加：

   ```bash
   --manual-review <manual-review.json>
   ```

4. 报告输入无效时返回 `ERROR`，不得补造缺失证据。
5. 报告仍包含 `manualReview` 时，明确告知用户需要回到目标 OpenClaw 主机执行其中的只读复核；`report-only` 自身不得执行这些命令。

## 交付

返回：

- 总体状态和数量；
- 每个 `FAIL`、`ERROR`、`WARN` 和 `NOT_TESTED`，以及简明证据；
- 每个已合并的 `agentReview`、待处理的 `manualReview` 和仍然存在的证据阻塞；
- JSON 和 Markdown 报告的准确文件路径；
- 使用时返回 manual-review JSON 的准确文件路径；
- 使用的模式、profile 或状态目录；
- 只覆盖本地主机只读证据的保证边界。
- 报告敏感性提示，以及非 PASS 项的只读整改建议。

不得自动修复。用户要求整改时，只提供独立、分阶段的修复计划，等待用户另行授权。
