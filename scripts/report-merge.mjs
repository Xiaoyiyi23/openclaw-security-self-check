#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const REPORT_SCHEMA_VERSION = 2;
const MANUAL_REVIEW_SCHEMA_VERSION = 1;
const MAX_EVIDENCE_BYTES = 16 * 1024;
const STATUS_RANK = {
  NOT_APPLICABLE: 0,
  PASS: 1,
  WARN: 2,
  NOT_TESTED: 3,
  FAIL: 4,
  ERROR: 5,
};
const METHODS = new Set(["static", "runtime"]);
const FORBIDDEN_EVIDENCE_KEY_PARTS = [
  "apikey",
  "authorization",
  "cookie",
  "credential",
  "password",
  "privatekey",
  "secret",
  "token",
];
const MANUAL_OBSERVATION_FIELDS = new Set([
  "status",
  "method",
  "timestamp",
  "source",
  "message",
  "evidence",
]);

const DISPLAY_VALUES = {
  baseline: "只读基线",
  "report-only": "仅生成报告",
  static: "静态检查",
  runtime: "运行状态检查",
};

function display(value, fallback = "未知") {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  return DISPLAY_VALUES[value] || value;
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const value = () => {
      if (index + 1 >= argv.length) {
        throw new Error(`${arg} 需要一个值`);
      }
      index += 1;
      return path.resolve(argv[index]);
    };
    if (arg === "--baseline") {
      options.baseline = value();
    } else if (arg === "--manual-review") {
      options.manualReview = value();
    } else if (arg === "--review-template-out") {
      options.reviewTemplateOut = value();
    } else if (arg === "--json-out") {
      options.jsonOut = value();
    } else if (arg === "--markdown-out") {
      options.markdownOut = value();
    } else if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else {
      throw new Error(`未知参数：${arg}`);
    }
  }
  return options;
}

function help() {
  console.log(`用法：node report-merge.mjs --baseline <file> [选项]

选项：
  --manual-review <file>       合并 OpenClaw Agent 的结构化只读复核证据
  --review-template-out <file> 为待复核项生成结构化证据模板
  --json-out <file>            report-only JSON 输出
  --markdown-out <file>        report-only Markdown 输出`);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function validTimestamp(value) {
  return typeof value === "string" && value.trim() !== "" && !Number.isNaN(Date.parse(value));
}

function evidenceHasForbiddenKey(value) {
  if (!value || typeof value !== "object") {
    return false;
  }
  if (Array.isArray(value)) {
    return value.some(evidenceHasForbiddenKey);
  }
  return Object.entries(value).some(
    ([key, child]) =>
      FORBIDDEN_EVIDENCE_KEY_PARTS.some((part) =>
        key
          .replaceAll(/[^a-z0-9]/giu, "")
          .toLowerCase()
          .includes(part),
      ) || evidenceHasForbiddenKey(child),
  );
}

function validateEvidence(evidence, label) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) {
    throw new Error(`${label} 的 evidence 必须是对象`);
  }
  if (Object.keys(evidence).length === 0) {
    throw new Error(`${label} 的 evidence 不能为空`);
  }
  if (evidenceHasForbiddenKey(evidence)) {
    throw new Error(`${label} 的 evidence 包含禁止保存的敏感字段名`);
  }
  if (Buffer.byteLength(JSON.stringify(evidence), "utf8") > MAX_EVIDENCE_BYTES) {
    throw new Error(`${label} 的 evidence 超过 16 KiB 上限`);
  }
}

function validateObservation(observation, label, options = {}) {
  if (!observation || !Object.hasOwn(STATUS_RANK, observation.status)) {
    throw new Error(`${label} 包含无效 observation 状态`);
  }
  if (!METHODS.has(observation.method)) {
    throw new Error(`${label} 包含无效 method`);
  }
  if (!validTimestamp(observation.timestamp)) {
    throw new Error(`${label} 缺少有效 timestamp`);
  }
  if (typeof observation.source !== "string" || !observation.source.trim()) {
    throw new Error(`${label} 缺少 source`);
  }
  if (typeof observation.message !== "string" || !observation.message.trim()) {
    throw new Error(`${label} 缺少 message`);
  }
  if (observation.source.length > 512 || observation.message.length > 2_000) {
    throw new Error(`${label} 的 source 或 message 过长`);
  }
  if (
    options.manual === true &&
    Object.keys(observation).some((key) => !MANUAL_OBSERVATION_FIELDS.has(key))
  ) {
    throw new Error(`${label} 包含不允许的 observation 字段`);
  }
  if (observation.evidence !== undefined) {
    validateEvidence(observation.evidence, label);
  }
  if (options.manual === true && observation.evidence === undefined) {
    throw new Error(`${label} 的人工结论必须包含脱敏 evidence`);
  }
}

function aggregateStatus(observations) {
  return observations.reduce(
    (status, observation) =>
      STATUS_RANK[observation.status] > STATUS_RANK[status] ? observation.status : status,
    "NOT_APPLICABLE",
  );
}

function validateCheck(check) {
  if (!check || typeof check.id !== "string" || !Object.hasOwn(STATUS_RANK, check.status)) {
    throw new Error("检查结果无效");
  }
  if (!Array.isArray(check.observations)) {
    throw new Error(`${check.id} 的 observations 无效`);
  }
  for (const [index, observation] of check.observations.entries()) {
    validateObservation(observation, `${check.id} observation ${index + 1}`);
  }
  const derivedStatus = aggregateStatus(check.observations);
  if (derivedStatus !== check.status) {
    throw new Error(
      `${check.id} 的 status=${check.status} 与 observations=${derivedStatus} 不一致`,
    );
  }
}

function manualReviewId(checkId, observationIndex) {
  return `${checkId}#${observationIndex + 1}`;
}

function manualReviewInstruction(checkId, message) {
  if (/日志文件路径由运行时推导/u.test(message)) {
    return "由 OpenClaw 只读定位当前版本实际日志文件，核对配置覆盖和运行时默认路径；记录脱敏文件元数据，或使用 host-baseline.mjs --log-path <实际路径> 取得证据。";
  }
  return `由 OpenClaw 针对 ${checkId} 使用当前版本 CLI、源码契约和定向只读主机命令收集证据；不得使用主动攻击探针。`;
}

function collectManualReview(checks) {
  const items = [];
  for (const check of checks) {
    for (const [index, observation] of check.observations.entries()) {
      if (observation.status !== "NOT_TESTED") {
        continue;
      }
      items.push({
        reviewId: manualReviewId(check.id, index),
        checkId: check.id,
        title: check.title,
        reason: observation.message,
        requiredAction: manualReviewInstruction(check.id, observation.message),
      });
    }
  }
  return {
    required: items.length > 0,
    status: items.length > 0 ? "PENDING" : "NOT_REQUIRED",
    items,
  };
}

function validateBaseline(baseline) {
  if (!baseline || baseline.mode !== "baseline") {
    throw new Error("输入必须是 baseline 报告");
  }
  if (baseline.schemaVersion !== REPORT_SCHEMA_VERSION) {
    throw new Error(`baseline schemaVersion 必须为 ${REPORT_SCHEMA_VERSION}`);
  }
  if (!validTimestamp(baseline.generatedAt)) {
    throw new Error("baseline 缺少有效 generatedAt");
  }
  if (!Array.isArray(baseline.checks)) {
    throw new Error("baseline 报告缺少 checks 数组");
  }
  const ids = new Set();
  for (const check of baseline.checks) {
    validateCheck(check);
    if (ids.has(check.id)) {
      throw new Error(`baseline 包含重复检查项：${check.id}`);
    }
    ids.add(check.id);
  }
}

function buildReviewTemplate(baseline) {
  validateBaseline(baseline);
  const pending = collectManualReview(baseline.checks);
  return {
    schemaVersion: MANUAL_REVIEW_SCHEMA_VERSION,
    mode: "manual-review",
    baseline: {
      generatedAt: baseline.generatedAt,
      openclawVersion: baseline.openclawVersion,
      stateDir: baseline.stateDir,
      configPath: baseline.configPath,
    },
    reviewer: { type: "openclaw-agent", reviewedAt: null },
    items: pending.items.map((item) => ({
      reviewId: item.reviewId,
      checkId: item.checkId,
      title: item.title,
      reason: item.reason,
      requiredAction: item.requiredAction,
      observation: null,
    })),
  };
}

function sameOptionalValue(left, right) {
  return (left ?? null) === (right ?? null);
}

function validateManualReview(review, baseline, pendingById) {
  if (!review || review.schemaVersion !== MANUAL_REVIEW_SCHEMA_VERSION) {
    throw new Error(`manual-review schemaVersion 必须为 ${MANUAL_REVIEW_SCHEMA_VERSION}`);
  }
  if (review.mode !== "manual-review") {
    throw new Error("人工复核输入的 mode 必须为 manual-review");
  }
  if (
    review.baseline?.generatedAt !== baseline.generatedAt ||
    !sameOptionalValue(review.baseline?.openclawVersion, baseline.openclawVersion) ||
    !sameOptionalValue(review.baseline?.stateDir, baseline.stateDir) ||
    !sameOptionalValue(review.baseline?.configPath, baseline.configPath)
  ) {
    throw new Error("人工复核证据与当前 baseline 不匹配");
  }
  if (review.reviewer?.type !== "openclaw-agent") {
    throw new Error("人工复核 reviewer.type 必须为 openclaw-agent");
  }
  if (!Array.isArray(review.items)) {
    throw new Error("人工复核输入缺少 items 数组");
  }
  const seen = new Set();
  let completed = 0;
  const evidenceTimestamps = [];
  for (const [index, item] of review.items.entries()) {
    const label = `manual-review item ${index + 1}`;
    if (!item || typeof item.reviewId !== "string" || typeof item.checkId !== "string") {
      throw new Error(`${label} 缺少 reviewId 或 checkId`);
    }
    if (seen.has(item.reviewId)) {
      throw new Error(`人工复核包含重复 reviewId：${item.reviewId}`);
    }
    seen.add(item.reviewId);
    const pending = pendingById.get(item.reviewId);
    if (!pending || pending.checkId !== item.checkId) {
      throw new Error(`${label} 未绑定当前 baseline 的待复核项`);
    }
    if (item.observation === null || item.observation === undefined) {
      continue;
    }
    validateObservation(item.observation, label, { manual: true });
    evidenceTimestamps.push(Date.parse(item.observation.timestamp));
    completed += 1;
  }
  if (completed > 0 && !validTimestamp(review.reviewer.reviewedAt)) {
    throw new Error("已填写人工复核结论时必须提供 reviewer.reviewedAt");
  }
  if (completed > 0) {
    const baselineTime = Date.parse(baseline.generatedAt);
    const reviewedTime = Date.parse(review.reviewer.reviewedAt);
    if (
      reviewedTime < baselineTime ||
      evidenceTimestamps.some((timestamp) => timestamp < baselineTime || timestamp > reviewedTime)
    ) {
      throw new Error("人工复核时间必须位于 baseline 生成时间和 reviewer.reviewedAt 之间");
    }
  }
}

function applyManualReview(checks, review, baseline) {
  if (!review) {
    return {
      checks,
      agentReview: {
        provided: false,
        completed: 0,
        resolved: 0,
        stillNotTested: 0,
        items: [],
      },
    };
  }
  const pending = collectManualReview(checks);
  const pendingById = new Map(pending.items.map((item) => [item.reviewId, item]));
  validateManualReview(review, baseline, pendingById);
  const output = checks.map((check) => ({
    ...check,
    observations: check.observations.map((observation) => ({ ...observation })),
  }));
  const applied = [];
  for (const item of review.items) {
    if (item.observation === null || item.observation === undefined) {
      continue;
    }
    const check = output.find((candidate) => candidate.id === item.checkId);
    const observationIndex = Number(item.reviewId.slice(item.reviewId.lastIndexOf("#") + 1)) - 1;
    const original = check?.observations[observationIndex];
    if (!check || !original || original.status !== "NOT_TESTED") {
      throw new Error(`无法定位待复核项：${item.reviewId}`);
    }
    check.observations[observationIndex] = {
      ...item.observation,
      review: {
        reviewId: item.reviewId,
        reviewer: review.reviewer.type,
        reviewedAt: review.reviewer.reviewedAt,
        originalReason: original.message,
      },
    };
    applied.push({
      reviewId: item.reviewId,
      checkId: item.checkId,
      status: item.observation.status,
      source: item.observation.source,
      message: item.observation.message,
    });
  }
  for (const check of output) {
    check.status = aggregateStatus(check.observations);
  }
  return {
    checks: output,
    agentReview: {
      provided: true,
      reviewedAt: review.reviewer.reviewedAt,
      completed: applied.length,
      resolved: applied.filter((item) => item.status !== "NOT_TESTED").length,
      stillNotTested: applied.filter((item) => item.status === "NOT_TESTED").length,
      items: applied,
    },
  };
}

function buildReport(baseline, review) {
  validateBaseline(baseline);
  const sourceChecks = baseline.checks.map((check) => ({
    ...check,
    observations: check.observations.map((observation) => ({ ...observation })),
  }));
  const { checks, agentReview } = applyManualReview(sourceChecks, review, baseline);
  const summary = Object.fromEntries(
    Object.keys(STATUS_RANK).map((status) => [
      status,
      checks.filter((check) => check.status === status).length,
    ]),
  );
  const finishedAt = new Date().toISOString();
  return {
    ...baseline,
    schemaVersion: REPORT_SCHEMA_VERSION,
    mode: "report-only",
    sourceMode: baseline.mode,
    sourceGeneratedAt: baseline.generatedAt,
    generatedAt: finishedAt,
    finishedAt,
    summary,
    checks,
    agentReview,
    manualReview: collectManualReview(checks),
  };
}

function escapeTable(value) {
  return String(value ?? "")
    .replaceAll("|", "\\|")
    .replaceAll("\n", " ");
}

function markdown(report) {
  const lines = [
    "# OpenClaw 主机安全自检报告",
    "",
    `- 报告生成时间：\`${report.generatedAt}\``,
    `- 基线生成时间：\`${display(report.sourceGeneratedAt)}\``,
    `- OpenClaw：\`${escapeTable(display(report.openclawVersion))}\``,
    `- 主机：\`${escapeTable(display(report.platform))}\``,
    `- 模式：\`${display(report.mode)}\``,
    `- 证据来源：\`${display(report.sourceMode)}\``,
    `- 检查清单：\`${escapeTable(display(report.checklistVersion))}\``,
    "",
    "## 摘要",
    "",
    "| PASS | WARN | FAIL | NOT_TESTED | ERROR | NOT_APPLICABLE |",
    "| ---: | ---: | ---: | ---: | ---: | ---: |",
    `| ${report.summary.PASS || 0} | ${report.summary.WARN || 0} | ${report.summary.FAIL || 0} | ${report.summary.NOT_TESTED || 0} | ${report.summary.ERROR || 0} | ${report.summary.NOT_APPLICABLE || 0} |`,
    "",
    "## 检查结果",
    "",
  ];
  for (const check of report.checks) {
    lines.push(`### ${check.id} — ${check.title || "检查项"}`, "", `状态：**${check.status}**`, "");
    for (const observation of check.observations) {
      const reviewed = observation.review ? `；OpenClaw 复核 ${observation.review.reviewId}` : "";
      lines.push(
        `- ${observation.status}（${display(observation.method)}${reviewed}）：${escapeTable(observation.message)}`,
      );
    }
    lines.push("");
  }
  if (report.agentReview.provided) {
    lines.push(
      "## OpenClaw 定向只读复核",
      "",
      `已合并 ${report.agentReview.completed} 条结构化复核结论；解决 ${report.agentReview.resolved} 条，仍为 NOT_TESTED ${report.agentReview.stillNotTested} 条。`,
      "",
    );
    for (const item of report.agentReview.items) {
      lines.push(
        `- ${item.reviewId}：**${item.status}**；来源：${escapeTable(item.source)}；${escapeTable(item.message)}`,
      );
    }
    lines.push("");
  }
  if (report.manualReview.required) {
    lines.push(
      "## 仍需 OpenClaw 复核",
      "",
      "以下项目仍缺少完成判定所需的机器证据。继续执行定向、只读复核；不得把 `NOT_TESTED` 当作 `PASS`。",
      "",
    );
    for (const item of report.manualReview.items) {
      lines.push(
        `### ${item.reviewId} — ${item.title || "检查项"}`,
        "",
        `- 未完成原因：${escapeTable(item.reason)}`,
        `- 必需动作：${escapeTable(item.requiredAction)}`,
        "",
      );
    }
  }
  lines.push(
    "## 范围限制",
    "",
    "本报告只覆盖 baseline 和 OpenClaw 定向复核收集的本地主机只读证据，不包括主动攻击探针、公网可达性、真实第三方 IM 未授权账号以及远程日志/SIEM 投递。",
    "",
    "本报告已避免输出凭证值，但仍包含端口、策略、finding id 和文件权限等安全姿态信息。请按内部安全材料保存和共享。",
    "",
  );
  return lines.join("\n");
}

function write(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, content, { encoding: "utf8", mode: 0o600 });
}

function main() {
  try {
    const options = parseArgs(process.argv.slice(2));
    if (options.help) {
      return (help(), 0);
    }
    if (!options.baseline) {
      throw new Error("必须提供 --baseline");
    }
    if (!options.jsonOut && !options.markdownOut && !options.reviewTemplateOut) {
      throw new Error("必须提供 --json-out、--markdown-out 或 --review-template-out");
    }
    if (
      options.manualReview &&
      options.reviewTemplateOut &&
      options.manualReview === options.reviewTemplateOut
    ) {
      throw new Error("--manual-review 和 --review-template-out 不能指向同一文件");
    }
    const baseline = readJson(options.baseline);
    const manualReview = options.manualReview ? readJson(options.manualReview) : undefined;
    const report = buildReport(baseline, manualReview);
    report.reportPaths = {
      json: options.jsonOut || null,
      markdown: options.markdownOut || null,
      manualReview: options.reviewTemplateOut || options.manualReview || null,
    };
    if (options.reviewTemplateOut) {
      write(
        options.reviewTemplateOut,
        `${JSON.stringify(buildReviewTemplate(baseline), null, 2)}\n`,
      );
    }
    if (options.jsonOut) {
      write(options.jsonOut, `${JSON.stringify(report, null, 2)}\n`);
    }
    if (options.markdownOut) {
      write(options.markdownOut, `${markdown(report)}\n`);
    }
    console.log(
      JSON.stringify(
        {
          json: options.jsonOut || null,
          markdown: options.markdownOut || null,
          reviewTemplate: options.reviewTemplateOut || null,
          manualReview: options.manualReview || null,
          summary: report.summary,
          agentReview: report.agentReview,
        },
        null,
        2,
      ),
    );
    return report.summary.ERROR ? 2 : report.summary.FAIL ? 1 : 0;
  } catch (error) {
    console.error(`错误（ERROR）：${error.message}`);
    return 2;
  }
}

process.exitCode = main();
