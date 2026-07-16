# 证据与状态规则

## 状态词汇

- `PASS`：所有必需只读子检查均已执行，并取得肯定的机器证据。
- `WARN`：已有证据，但设置偏弱、存在歧义或依赖操作员控制的例外。
- `FAIL`：证据表明所需控制缺失或配置明显不安全。
- `NOT_TESTED`：目标未运行，或必需只读证据无法取得。
- `ERROR`：证据收集、解析或版本兼容性失败。
- `NOT_APPLICABLE`：已证明当前主机没有相关组件，例如没有启用 IM Channel。

按以下顺序聚合严重程度：

```text
ERROR > FAIL > NOT_TESTED > WARN > PASS > NOT_APPLICABLE
```

只有通过有效配置证明组件不存在时，才能使用 `NOT_APPLICABLE`。配置缺失或收集失败不能证明组件不存在。

## 必需证据

每条观察结果必须直接或通过报告元数据包含：

- 检查 ID；
- 方法：`static` 或 `runtime`；
- 时间戳；
- 已脱敏的事实或命令结果；
- 来源命令、文件元数据或 OpenClaw 审计 finding ID。

不得保存：

- token、密码、API key、Cookie、SecretRef 值；
- 原始私人消息或模型 transcript；
- 完整环境变量转储；
- approval socket token；
- 任何为了验证控制而生成的秘密或敏感样本。

## PASS 门槛

- 只读配置和运行状态足以证明检查矩阵定义的控制时，可以得到 `PASS`。
- OpenClaw Agent 定向复核取得的当前主机 CLI 输出、进程/监听器事实和文件元数据属于机器证据，但必须以 `references/manual-review-evidence.md` 定义的脱敏结构写入 manual-review 文件并通过报告脚本校验。
- 源码契约和 Agent 推理只能解释当前主机机器证据，不能单独产生 `PASS`。
- `PASS` 只代表观察到的配置与状态合规，不代表已经执行渗透测试或行为绕过测试。
- OpenClaw exec `mode=auto` 表示自动审查，不是人工审批证据。
- 已启用 allowlist 中包含 `*` 时属于开放访问，不能得到 allowlist `PASS`。
- 禁用的 Channel 会忽略入站流量；禁用策略下遗留的通配条目不会使其变为开放状态。
- 配置值被环境变量覆盖时，必须按有效值判定。
- POSIX 权限必须验证预期对象类型和准确 mode；Windows 必须取得 ACL 证据，否则返回 `NOT_TESTED`。
- 找不到目标进程、监听器或日志文件时，不得根据配置推测对应运行时事实。

## 只读约束

- 不创建 canary、测试会话、测试用户或临时 Agent。
- 不执行匿名 Gateway 请求、越权读取、目录穿越、allowlist 外命令或假密钥写入。
- 不修改配置、权限、服务、防火墙、软件包、用户或数据库。
- 除用户指定的报告输出文件外，不写入被审计主机状态。
- `report-only` 只读取已有报告，不调用 OpenClaw 或主机检查命令。

## NOT_TESTED 定向复核

- 每条 `NOT_TESTED` 必须生成一条带稳定 `reviewId` 的 `manualReview`，包含检查 ID、证据缺口和必需的只读复核动作。
- baseline 模式下，OpenClaw Agent 必须逐项执行最小范围的定向只读调查，并把结果写入绑定当前 baseline 的 manual-review JSON。
- manual-review observation 通过校验后替换对应的 `NOT_TESTED` observation；检查项状态按全部剩余 observations 重新聚合。
- manual-review 只能处理当前 baseline 已列出的 `reviewId`。baseline 时间、版本、状态目录或配置路径不匹配时必须拒绝合并。
- report-only 模式可以合并用户提供的 manual-review JSON，但不得自行执行主机命令。
- Agent 推理不能替代机器证据。仍无法取得证据时写入新的 `NOT_TESTED` observation，并明确记录已执行的检查和阻塞原因。
- 日志路径由运行时推导时，可以只读定位实际日志文件并写入结构化文件元数据；也可以用 `host-baseline.mjs --log-path <实际路径>` 重跑权限检查。重跑 baseline 后必须重新生成 manual-review 模板。

## 报告元数据

报告必须包含：

- schema 版本；
- Checklist 版本；
- Skill 名称和版本；
- OpenClaw 版本；
- 主机操作系统和架构；
- 状态目录和配置路径；
- 模式；
- 开始和结束时间；
- 生成的报告路径；
- manual-review 输入或模板路径，以及已合并和仍待复核的数量；
- 排除的外部验证范围。
