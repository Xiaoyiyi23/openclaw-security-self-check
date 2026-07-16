# OpenClaw Agent 定向复核证据

仅对 baseline 中生成的 `manualReview.items` 执行复核。不要扩大到无关主机枚举、主动攻击探针或系统修改。

## 工作流程

1. 使用 `report-merge.mjs --review-template-out <manual-review.json>` 生成绑定当前 baseline 的模板。
2. 按模板中每个 `requiredAction` 执行最小范围的只读调查。
3. 在对应项目的 `observation` 中记录结论。不要改动 `reviewId`、`checkId` 或 `baseline` 绑定信息。
4. 使用 `report-merge.mjs --manual-review <manual-review.json>` 校验并合并证据。
5. 检查最终报告的 `agentReview` 和剩余 `manualReview`。

## observation 结构

```json
{
  "status": "PASS",
  "method": "runtime",
  "timestamp": "2026-07-16T10:00:00.000Z",
  "source": "OpenClaw 定向只读文件元数据检查",
  "message": "实际日志文件类型和权限符合要求",
  "evidence": {
    "objectType": "file",
    "mode": "0600"
  }
}
```

字段要求：

- `status`：使用 `PASS`、`WARN`、`FAIL`、`NOT_TESTED`、`ERROR` 或 `NOT_APPLICABLE`。
- `method`：只使用 `static` 或 `runtime`。
- `timestamp`：记录实际取得证据的时间。
- `source`：记录脱敏后的命令类别、文件元数据来源或当前版本源码契约；不要保存含凭证的完整命令行。
- `message`：简述观察到的事实和判断理由。
- `evidence`：每条 observation 都必须提供；只保存判断需要的脱敏结构化事实，不保存完整原始输出。`NOT_TESTED` 和 `ERROR` 也要记录已经执行的检查、错误类别或阻塞点。

## 状态门槛

- `PASS`：必须有当前目标主机的肯定机器证据。源码契约或 Agent 推理只能解释证据，不能单独证明主机状态。
- `WARN`：证据表明设置偏弱、范围含糊或依赖操作员控制。
- `FAIL`：证据直接表明控制缺失或配置不安全。
- `NOT_APPLICABLE`：当前主机配置明确证明对应组件不存在或未启用。
- `NOT_TESTED`：已执行定向只读调查，但仍缺少必要机器证据；在 `message` 和 `evidence` 中记录阻塞点。
- `ERROR`：复核命令执行、权限、解析或版本契约失败。

## 安全限制

- 不保存 token、密码、API key、Cookie、Authorization、SecretRef、私钥或 approval socket token。
- 不保存私人消息、模型 transcript、完整环境变量或完整配置转储。
- 不创建 canary、测试 Agent、测试账号或临时生产配置。
- 不执行匿名请求、越权读取、路径穿越、allowlist 外命令或高危测试命令。
- 不修改配置、权限、服务、防火墙、软件包、用户或数据库。
- 复核文件是安全姿态报告的一部分，按内部安全材料保存和共享。
