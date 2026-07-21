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
  baseline: "read-only baseline",
  "report-only": "report only",
  static: "static check",
  runtime: "runtime check",
};

function display(value, fallback = "unknown") {
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
        throw new Error(`${arg} requires a value`);
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
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return options;
}

function help() {
  console.log(`Usage: node report-merge.mjs --baseline <file> [options]

Options:
  --manual-review <file>       Merge structured read-only review evidence from an OpenClaw Agent
  --review-template-out <file> Generate a structured evidence template for pending review items
  --json-out <file>            Write report-only JSON output
  --markdown-out <file>        Write report-only Markdown output`);
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
    throw new Error(`${label} evidence must be an object`);
  }
  if (Object.keys(evidence).length === 0) {
    throw new Error(`${label} evidence must not be empty`);
  }
  if (evidenceHasForbiddenKey(evidence)) {
    throw new Error(`${label} evidence contains a forbidden sensitive field name`);
  }
  if (Buffer.byteLength(JSON.stringify(evidence), "utf8") > MAX_EVIDENCE_BYTES) {
    throw new Error(`${label} evidence exceeds the 16 KiB limit`);
  }
}

function validateObservation(observation, label, options = {}) {
  if (!observation || !Object.hasOwn(STATUS_RANK, observation.status)) {
    throw new Error(`${label} contains an invalid observation status`);
  }
  if (!METHODS.has(observation.method)) {
    throw new Error(`${label} contains an invalid method`);
  }
  if (!validTimestamp(observation.timestamp)) {
    throw new Error(`${label} lacks a valid timestamp`);
  }
  if (typeof observation.source !== "string" || !observation.source.trim()) {
    throw new Error(`${label} lacks a source`);
  }
  if (typeof observation.message !== "string" || !observation.message.trim()) {
    throw new Error(`${label} lacks a message`);
  }
  if (observation.source.length > 512 || observation.message.length > 2_000) {
    throw new Error(`${label} source or message is too long`);
  }
  if (
    options.manual === true &&
    Object.keys(observation).some((key) => !MANUAL_OBSERVATION_FIELDS.has(key))
  ) {
    throw new Error(`${label} contains a disallowed observation field`);
  }
  if (observation.evidence !== undefined) {
    validateEvidence(observation.evidence, label);
  }
  if (options.manual === true && observation.evidence === undefined) {
    throw new Error(`${label} manual conclusion must include sanitized evidence`);
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
    throw new Error("Invalid check result");
  }
  if (!Array.isArray(check.observations)) {
    throw new Error(`${check.id} observations are invalid`);
  }
  for (const [index, observation] of check.observations.entries()) {
    validateObservation(observation, `${check.id} observation ${index + 1}`);
  }
  const derivedStatus = aggregateStatus(check.observations);
  if (derivedStatus !== check.status) {
    throw new Error(
      `${check.id} status=${check.status} does not match observations=${derivedStatus}`,
    );
  }
}

function manualReviewId(checkId, observationIndex) {
  return `${checkId}#${observationIndex + 1}`;
}

function manualReviewInstruction(checkId, message) {
  if (/log-file path is derived at runtime/iu.test(message)) {
    return "Use OpenClaw read-only methods to locate the actual log file for the current version and verify configuration overrides and runtime defaults. Record sanitized file metadata or use host-baseline.mjs --log-path <actual-path> to collect evidence.";
  }
  return `Use the current OpenClaw CLI, source-code contracts, and targeted read-only host commands to collect evidence for ${checkId}. Do not use active attack probes.`;
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
    throw new Error("The input must be a baseline report");
  }
  if (baseline.schemaVersion !== REPORT_SCHEMA_VERSION) {
    throw new Error(`baseline schemaVersion must be ${REPORT_SCHEMA_VERSION}`);
  }
  if (!validTimestamp(baseline.generatedAt)) {
    throw new Error("The baseline lacks a valid generatedAt value");
  }
  if (!Array.isArray(baseline.checks)) {
    throw new Error("The baseline report lacks a checks array");
  }
  const ids = new Set();
  for (const check of baseline.checks) {
    validateCheck(check);
    if (ids.has(check.id)) {
      throw new Error(`The baseline contains a duplicate check: ${check.id}`);
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
    throw new Error(`manual-review schemaVersion must be ${MANUAL_REVIEW_SCHEMA_VERSION}`);
  }
  if (review.mode !== "manual-review") {
    throw new Error("The manual-review input mode must be manual-review");
  }
  if (
    review.baseline?.generatedAt !== baseline.generatedAt ||
    !sameOptionalValue(review.baseline?.openclawVersion, baseline.openclawVersion) ||
    !sameOptionalValue(review.baseline?.stateDir, baseline.stateDir) ||
    !sameOptionalValue(review.baseline?.configPath, baseline.configPath)
  ) {
    throw new Error("The manual-review evidence does not match the current baseline");
  }
  if (review.reviewer?.type !== "openclaw-agent") {
    throw new Error("The manual-review reviewer.type must be openclaw-agent");
  }
  if (!Array.isArray(review.items)) {
    throw new Error("The manual-review input lacks an items array");
  }
  const seen = new Set();
  let completed = 0;
  const evidenceTimestamps = [];
  for (const [index, item] of review.items.entries()) {
    const label = `manual-review item ${index + 1}`;
    if (!item || typeof item.reviewId !== "string" || typeof item.checkId !== "string") {
      throw new Error(`${label} lacks reviewId or checkId`);
    }
    if (seen.has(item.reviewId)) {
      throw new Error(`The manual review contains a duplicate reviewId: ${item.reviewId}`);
    }
    seen.add(item.reviewId);
    const pending = pendingById.get(item.reviewId);
    if (!pending || pending.checkId !== item.checkId) {
      throw new Error(`${label} is not bound to a pending item in the current baseline`);
    }
    if (item.observation === null || item.observation === undefined) {
      continue;
    }
    validateObservation(item.observation, label, { manual: true });
    evidenceTimestamps.push(Date.parse(item.observation.timestamp));
    completed += 1;
  }
  if (completed > 0 && !validTimestamp(review.reviewer.reviewedAt)) {
    throw new Error("reviewer.reviewedAt is required when a manual-review conclusion is present");
  }
  if (completed > 0) {
    const baselineTime = Date.parse(baseline.generatedAt);
    const reviewedTime = Date.parse(review.reviewer.reviewedAt);
    if (
      reviewedTime < baselineTime ||
      evidenceTimestamps.some((timestamp) => timestamp < baselineTime || timestamp > reviewedTime)
    ) {
      throw new Error("Manual-review timestamps must fall between baseline generation and reviewer.reviewedAt");
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
      throw new Error(`Unable to locate the pending review item: ${item.reviewId}`);
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
    "# OpenClaw Host Security Self-Check Report",
    "",
    `- Report generated: \`${report.generatedAt}\``,
    `- Baseline generated: \`${display(report.sourceGeneratedAt)}\``,
    `- OpenClaw: \`${escapeTable(display(report.openclawVersion))}\``,
    `- Host: \`${escapeTable(display(report.platform))}\``,
    `- Mode: \`${display(report.mode)}\``,
    `- Evidence source: \`${display(report.sourceMode)}\``,
    `- Checklist: \`${escapeTable(display(report.checklistVersion))}\``,
    "",
    "## Summary",
    "",
    "| PASS | WARN | FAIL | NOT_TESTED | ERROR | NOT_APPLICABLE |",
    "| ---: | ---: | ---: | ---: | ---: | ---: |",
    `| ${report.summary.PASS || 0} | ${report.summary.WARN || 0} | ${report.summary.FAIL || 0} | ${report.summary.NOT_TESTED || 0} | ${report.summary.ERROR || 0} | ${report.summary.NOT_APPLICABLE || 0} |`,
    "",
    "## Check Results",
    "",
  ];
  for (const check of report.checks) {
    lines.push(`### ${check.id} — ${check.title || "Check"}`, "", `Status: **${check.status}**`, "");
    for (const observation of check.observations) {
      const reviewed = observation.review ? `; OpenClaw review ${observation.review.reviewId}` : "";
      lines.push(
        `- ${observation.status} (${display(observation.method)}${reviewed}): ${escapeTable(observation.message)}`,
      );
    }
    lines.push("");
  }
  if (report.agentReview.provided) {
    lines.push(
      "## Targeted Read-Only OpenClaw Review",
      "",
      `Merged ${report.agentReview.completed} structured review conclusions; resolved ${report.agentReview.resolved}; still NOT_TESTED: ${report.agentReview.stillNotTested}.`,
      "",
    );
    for (const item of report.agentReview.items) {
      lines.push(
        `- ${item.reviewId}: **${item.status}**; source: ${escapeTable(item.source)}; ${escapeTable(item.message)}`,
      );
    }
    lines.push("");
  }
  if (report.manualReview.required) {
    lines.push(
      "## Remaining OpenClaw Review",
      "",
      "The following items still lack the machine evidence required for a final determination. Continue targeted read-only review; do not treat `NOT_TESTED` as `PASS`.",
      "",
    );
    for (const item of report.manualReview.items) {
      lines.push(
        `### ${item.reviewId} — ${item.title || "Check"}`,
        "",
        `- Reason incomplete: ${escapeTable(item.reason)}`,
        `- Required action: ${escapeTable(item.requiredAction)}`,
        "",
      );
    }
  }
  lines.push(
    "## Scope Limitations",
    "",
    "This report covers only read-only local-host evidence collected by the baseline and targeted OpenClaw review. It excludes active attack probes, public network reachability, real unauthorized third-party IM accounts, and remote log/SIEM delivery.",
    "",
    "This report omits credential values but still contains security-posture information such as ports, policies, finding IDs, and file permissions. Store and share it as internal security material.",
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
      throw new Error("--baseline is required");
    }
    if (!options.jsonOut && !options.markdownOut && !options.reviewTemplateOut) {
      throw new Error("At least one of --json-out, --markdown-out, or --review-template-out is required");
    }
    if (
      options.manualReview &&
      options.reviewTemplateOut &&
      options.manualReview === options.reviewTemplateOut
    ) {
      throw new Error("--manual-review and --review-template-out must not point to the same file");
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
    console.error(`Error (ERROR): ${error.message}`);
    return 2;
  }
}

process.exitCode = main();
