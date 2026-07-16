# 只读主机检查矩阵

本 Skill 只覆盖能够通过当前 OpenClaw 主机的配置、CLI 输出、进程信息和文件元数据验证的检查。它不执行主动攻击探针。

| 检查项        | 必需只读证据                                                                               | PASS 条件                                                                                                     | 返回 NOT_TESTED 的典型情况                 |
| ------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| OpenClaw-1-1  | Gateway 有效端口/bind、Browser/CDP 端口、mDNS 模式、主机监听器                             | 配置和已观察监听器均限制在预期接口；mDNS 为推荐的 `minimal` 或更严格的 `off`                                  | Gateway/Browser 未运行，无法核对运行时监听 |
| OpenClaw-1-2  | 有效认证模式、弱 Token 原生审计 finding、配置文件权限                                      | 认证已启用、没有弱凭证 finding、配置文件受保护                                                                | CLI 无法提供认证或审计证据                 |
| OpenClaw-2-1  | 每个已配置 Agent 的 `openclaw sandbox explain --json`                                      | 要求沙箱的 Agent 显示 `mode=all` 且 session 已沙箱化                                                          | 无法取得 sandbox explain 结果              |
| OpenClaw-2-2  | `tools.fs.workspaceOnly`、sandbox workspaceAccess、状态/配置/`.env` 对象类型和权限         | workspaceOnly 生效、workspaceAccess 受限且敏感路径权限正确                                                    | Windows ACL 无法读取或目标路径不可访问     |
| OpenClaw-3-1  | 有效 exec host/security/ask/mode、审批 allowlist                                           | 有效 security 为 deny/allowlist，且没有宽泛 allowlist                                                         | exec-policy JSON 不可用或结构不兼容        |
| OpenClaw-3-2  | 有效 exec ask/mode 和 autoReview 状态                                                      | 操作被禁止，或策略明确要求人工审批且未启用自动审查                                                            | 无法解析有效审批策略                       |
| OpenClaw-3-3  | 全局和各 Agent 的 profile/allow/alsoAllow/deny、`tools.agentToAgent`、进程账号/SID         | 工具面受到限制，跨 Agent 访问未启用或 allowlist 明确，且运行账号不是 root/Administrator/SYSTEM                | 未发现运行中进程或无法识别进程所有者       |
| OpenClaw-4-1  | `OPENCLAW_NO_AUTO_UPDATE`、update.auto、checkOnStart 的有效状态                            | 更新检查启用，实际自动安装禁用                                                                                | 所需配置无法读取                           |
| OpenClaw-5-3  | Channel 历史限制、contextTokens、compaction 模式                                           | 显式限制合理且压缩配置有效                                                                                    | 所需配置无法读取                           |
| OpenClaw-7-1  | 有效日志级别、日志文件对象类型和权限                                                       | 日志启用且文件权限受保护                                                                                      | 日志路径由运行时生成且无法定位             |
| OpenClaw-7-2  | deep security audit、loop detection 和本地监控配置                                         | deep audit 成功且没有严重 finding，异常检测配置有效                                                           | security audit 无法执行或解析              |
| OpenClaw-7-3  | redactSensitive、自定义脱敏模式、日志文件权限                                              | 脱敏未关闭，且可定位日志文件时权限受保护                                                                      | 日志路径或权限无法取得                     |
| OpenClaw-9-3  | 有效更新通道、npm/ClawHub URL、SHA-512 integrity、registry 密钥和 Sigstore/SLSA provenance | 使用稳定受控通道和 HTTPS 来源；registry 签名完成密码学验证；provenance 验证成功并绑定官方 OpenClaw 发布工作流 | 网络、registry 或 Sigstore 验证能力不可用  |
| OpenClaw-11-1 | 有效 Channel DM/group policy、allowFrom/groupAllowFrom 和原生审计 finding                  | 已启用 Channel 不使用 open 或通配访问，allowlist 非空                                                         | 插件自有策略无法通过公开配置或审计接口解析 |

## 只读保证边界

- `PASS` 表示可观察的有效配置和运行状态符合检查要求，不表示已经进行渗透测试。
- 不通过实际匿名请求、越权读取、目录穿越、allowlist 外命令或假密钥写入来验证控制。
- 不创建测试 Agent，不更改生产 Agent policy，不临时提升权限。
- 不读取真实 SSH key、云元数据、数据库、用户文档、私人消息或生产秘密。
- 公网可达性、真实第三方 IM 未授权账号和远程 SIEM 投递不在范围内。

## 无法验证的情况

以下情况返回 `NOT_TESTED`，不得猜测为 `PASS`：

- 目标组件未运行，无法取得所需运行时状态；
- 公开 CLI 没有返回所需 JSON 结构；
- Windows ACL、进程所有者或日志文件元数据无法读取；
- Channel 使用无法通过公开接口解析的插件自有策略；
- 证据只存在于不可访问的外部系统。
