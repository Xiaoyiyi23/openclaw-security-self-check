#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import process from "node:process";

const SCHEMA_VERSION = 2;
const CHECKLIST_VERSION = "OpenClaw Product Security Checklist V1.0";
const SKILL_VERSION = "1.5.0";
const DEFAULT_PORT = 18789;
const TIMEOUT_MS = 90_000;
const STATUS_RANK = {
  NOT_APPLICABLE: 0,
  PASS: 1,
  WARN: 2,
  NOT_TESTED: 3,
  FAIL: 4,
  ERROR: 5,
};
const CHECKS = [
  ["OpenClaw-1-1", "Minimize Network Exposure"],
  ["OpenClaw-1-2", "Authentication and Credential Security"],
  ["OpenClaw-2-1", "Execution Sandbox Isolation"],
  ["OpenClaw-2-2", "Workspace Filesystem Protection"],
  ["OpenClaw-3-1", "Strict System Command Restrictions"],
  ["OpenClaw-3-2", "Mandatory Human Approval for High-Risk Tools"],
  ["OpenClaw-3-3", "Least-Privilege Tools and Runtime Permissions"],
  ["OpenClaw-4-1", "Disable Automatic Core Updates in Production"],
  ["OpenClaw-5-3", "Limit and Compact Session History"],
  ["OpenClaw-7-1", "Audit Log Integrity"],
  ["OpenClaw-7-2", "Configuration Anomaly Monitoring and Alerts"],
  ["OpenClaw-7-3", "Sensitive-Information Redaction"],
  ["OpenClaw-9-3", "Core Update-Source Verification and Supply-Chain Protection"],
  ["OpenClaw-11-1", "Mandatory Authentication and Allowlist Isolation for IM Bots"],
];
const LOG_LEVELS = new Set(["silent", "fatal", "error", "warn", "info", "debug", "trace"]);
const WINDOWS_SENSITIVE_RIGHTS = 1 | 2 | 4 | 8 | 16 | 64 | 128 | 256 | 65_536 | 262_144 | 524_288;
const HIGH_RISK_TOOLS = new Set(["exec", "process", "gateway", "nodes", "group:runtime"]);
const NPM_PROVENANCE_PREDICATE_TYPE = "https://slsa.dev/provenance/v1";
const NPM_PROVENANCE_REPOSITORY = "https://github.com/openclaw/openclaw";
const NPM_PROVENANCE_WORKFLOW_PATH = ".github/workflows/openclaw-npm-release.yml";
const NPM_PROVENANCE_CERTIFICATE_ISSUER = "https://token.actions.githubusercontent.com";
const NPM_PROVENANCE_BUILDER_ID = "https://github.com/actions/runner/github-hosted";
const NPM_REGISTRY_REQUEST_TIMEOUT_MS = 30_000;
const NPM_REGISTRY_RESPONSE_BODY_MAX_BYTES = 4 * 1024 * 1024;

function parseArgs(argv) {
  const options = {
    bin: process.env.OPENCLAW_BIN || "openclaw",
    binArgs: [],
    stateDir: process.env.OPENCLAW_STATE_DIR || path.join(os.homedir(), ".openclaw"),
    configPath: process.env.OPENCLAW_CONFIG_PATH,
    json: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const value = () => {
      if (index + 1 >= argv.length) {
        throw new Error(`${arg} requires a value`);
      }
      index += 1;
      return argv[index];
    };
    if (arg === "--json") {
      options.json = true;
    } else if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else if (arg === "--openclaw-bin") {
      options.bin = value();
    } else if (arg === "--openclaw-arg") {
      options.binArgs.push(value());
    } else if (arg.startsWith("--openclaw-arg=")) {
      options.binArgs.push(arg.slice("--openclaw-arg=".length));
    } else if (arg === "--state-dir") {
      options.stateDir = path.resolve(value());
    } else if (arg === "--config-path") {
      options.configPath = path.resolve(value());
    } else if (arg === "--log-path") {
      options.logPath = path.resolve(value());
    } else if (arg === "--output") {
      options.output = path.resolve(value());
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  options.configPath ||= path.join(options.stateDir, "openclaw.json");
  return options;
}

function printHelp() {
  console.log(`Usage: node host-baseline.mjs [options]

Options:
  --json                       Output JSON without a human-readable summary
  --output <path>              Write the JSON report to a file
  --openclaw-bin <path>        OpenClaw executable (default: openclaw)
  --openclaw-arg <arg>         OpenClaw root argument; may be repeated
  --state-dir <path>           OpenClaw state directory
  --config-path <path>         OpenClaw configuration-file path
  --log-path <path>            Manually confirmed current runtime log-file path
  -h, --help                   Show help`);
}

function findOnWindowsPath(command) {
  if (path.extname(command)) {
    return fs.existsSync(command) ? command : undefined;
  }
  const extensions = [".ps1", ".exe", ".com"];
  for (const directory of String(process.env.PATH || "").split(path.delimiter)) {
    for (const extension of extensions) {
      const candidate = path.join(directory.replace(/^"|"$/gu, ""), `${command}${extension}`);
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
  }
  return undefined;
}

function resolveInvocation(command, args) {
  if (process.platform !== "win32") {
    return { command, args };
  }
  const resolved = findOnWindowsPath(command) || command;
  if (resolved.toLowerCase().endsWith(".ps1")) {
    return {
      command: "powershell.exe",
      args: [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        resolved,
        ...args,
      ],
    };
  }
  return { command: resolved, args };
}

function run(command, args, timeout = TIMEOUT_MS) {
  const invocation = resolveInvocation(command, args);
  const result = spawnSync(invocation.command, invocation.args, {
    encoding: "utf8",
    shell: false,
    timeout,
    windowsHide: true,
  });
  return {
    status: result.status ?? (result.error ? -1 : 0),
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    error: result.error?.message,
  };
}

function failure(result) {
  return result.error || result.stderr.trim() || result.stdout.trim() || `exit ${result.status}`;
}

function parseJson(text) {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new Error("JSON output is empty");
  }
  return JSON.parse(trimmed);
}

function runOpenClaw(options, args) {
  return run(options.bin, [...options.binArgs, ...args]);
}

function configGet(options, key) {
  const result = runOpenClaw(options, ["config", "get", key, "--json"]);
  if (result.status !== 0) {
    if (/not found|does not exist|missing/iu.test(`${result.stdout}\n${result.stderr}`)) {
      return undefined;
    }
    throw new Error(`Failed to read configuration ${key}: ${failure(result)}`);
  }
  return parseJson(result.stdout);
}

function createReportChecks() {
  return new Map(
    CHECKS.map(([id, title]) => [id, { id, title, status: "NOT_APPLICABLE", observations: [] }]),
  );
}

function observe(checks, id, status, message, evidence) {
  const check = checks.get(id);
  if (!check) {
    throw new Error(`Unknown check: ${id}`);
  }
  check.observations.push({
    status,
    method: "static",
    timestamp: new Date().toISOString(),
    source: evidence?.source || "host-baseline",
    message,
    ...(evidence ? { evidence } : {}),
  });
  if (STATUS_RANK[status] > STATUS_RANK[check.status]) {
    check.status = status;
  }
}

function walkObjects(value, pathParts = [], output = []) {
  if (!value || typeof value !== "object") {
    return output;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkObjects(item, [...pathParts, String(index)], output));
    return output;
  }
  output.push({ path: pathParts.join("."), value });
  for (const [key, child] of Object.entries(value)) {
    walkObjects(child, [...pathParts, key], output);
  }
  return output;
}

function addAudit(checks, id, audit, patterns) {
  for (const finding of audit?.findings || []) {
    if (
      !patterns.some((pattern) =>
        typeof pattern === "string" ? finding.checkId === pattern : pattern.test(finding.checkId),
      )
    ) {
      continue;
    }
    const status = finding.severity === "critical" ? "FAIL" : "WARN";
    observe(
      checks,
      id,
      status,
      `${finding.checkId}: ${finding.title || finding.detail || finding.severity}`,
      {
        findingId: finding.checkId,
        severity: finding.severity,
      },
    );
  }
}

function isValidPort(value) {
  return Number.isInteger(value) && value > 0 && value <= 65535;
}

function parsePort(raw) {
  const value = raw?.trim();
  if (!value) {
    return undefined;
  }
  const direct = /^\d+$/u.test(value)
    ? value
    : (/^\[[^\]]+\]:(\d+)$/u.exec(value)?.[1] ?? /^[^:]+:(\d+)$/u.exec(value)?.[1]);
  const port = Number(direct);
  return isValidPort(port) ? port : undefined;
}

function gatewayPort(config) {
  return (
    parsePort(process.env.OPENCLAW_GATEWAY_PORT) ??
    (isValidPort(config.gateway?.port) ? config.gateway.port : DEFAULT_PORT)
  );
}

function mdnsStatus(mode, bind) {
  if (mode === "off" || mode === "minimal") {
    return "PASS";
  }
  if (mode === "full") {
    return bind === "loopback" ? "WARN" : "FAIL";
  }
  return "FAIL";
}

function normalizeAddress(value) {
  return String(value || "")
    .replace(/^\[|\]$/gu, "")
    .replace(/%.+$/u, "")
    .toLowerCase();
}

function isLoopback(value) {
  const address = normalizeAddress(value);
  if (address === "localhost" || address === "::1") {
    return true;
  }
  const match = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u.exec(address);
  return Boolean(match && match.slice(1).every((part) => Number(part) <= 255));
}

function urlPort(value) {
  if (typeof value !== "string" || !value.trim()) {
    return undefined;
  }
  try {
    const url = new URL(value);
    if (url.port) {
      return Number(url.port);
    }
    if (["https:", "wss:"].includes(url.protocol)) {
      return 443;
    }
    if (["http:", "ws:"].includes(url.protocol)) {
      return 80;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function browserPorts(port, browser = {}) {
  const control = isValidPort(port + 2) ? port + 2 : 18791;
  const derived = isValidPort(control + 9) ? control + 9 : 18800;
  const start =
    isValidPort(browser.cdpPortRangeStart) && browser.cdpPortRangeStart + 99 <= 65535
      ? browser.cdpPortRangeStart
      : derived;
  const profiles = Object.values(browser.profiles || {}).flatMap((profile) => [
    profile?.cdpPort,
    urlPort(profile?.cdpUrl),
  ]);
  return {
    control,
    start,
    end: start + 99,
    explicit: [urlPort(browser.cdpUrl), ...profiles].filter(isValidPort),
  };
}

function collectListeners() {
  if (process.platform === "win32") {
    const script = [
      "$tcp=Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; [pscustomobject]@{protocol='tcp';address=$_.LocalAddress;port=$_.LocalPort;pid=$_.OwningProcess;process=$p.ProcessName} }",
      "$udp=Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object { $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; [pscustomobject]@{protocol='udp';address=$_.LocalAddress;port=$_.LocalPort;pid=$_.OwningProcess;process=$p.ProcessName} }",
      "@($tcp)+@($udp) | ConvertTo-Json -Compress",
    ].join("; ");
    const result = run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script]);
    if (result.status !== 0) {
      return { listeners: [], error: failure(result) };
    }
    try {
      const parsed = result.stdout.trim() ? parseJson(result.stdout) : [];
      return { listeners: (Array.isArray(parsed) ? parsed : [parsed]).filter(Boolean) };
    } catch (error) {
      return { listeners: [], error: error.message };
    }
  }
  const result = run("ss", ["-H", "-lntup"]);
  if (result.status !== 0) {
    return { listeners: [], error: failure(result) };
  }
  const listeners = [];
  for (const line of result.stdout.split(/\r?\n/u)) {
    const fields = line.trim().split(/\s+/u);
    const local = fields[4] || fields[3];
    const match = /^(?:\[([^\]]+)\]|(.+)):(\d+)$/u.exec(local || "");
    if (!match) {
      continue;
    }
    const owner = /users:\(\("([^"]+)".*pid=(\d+)/u.exec(line);
    listeners.push({
      protocol: fields[0],
      address: match[1] || match[2],
      port: Number(match[3]),
      ...(owner ? { process: owner[1], pid: Number(owner[2]) } : {}),
    });
  }
  return { listeners };
}

function collectProcesses() {
  if (process.platform === "win32") {
    const script = [
      "$items=Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match 'openclaw' -and $_.CommandLine -notmatch 'security-self-check|host-baseline' }",
      "$items | ForEach-Object { $o=Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue; $s=Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid -ErrorAction SilentlyContinue; [pscustomobject]@{pid=$_.ProcessId;user=$o.User;domain=$o.Domain;sid=$s.Sid} } | ConvertTo-Json -Compress",
    ].join("; ");
    const result = run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script]);
    if (result.status !== 0) {
      return { owners: [], error: failure(result) };
    }
    try {
      const parsed = result.stdout.trim() ? parseJson(result.stdout) : [];
      return { owners: (Array.isArray(parsed) ? parsed : [parsed]).filter(Boolean) };
    } catch (error) {
      return { owners: [], error: error.message };
    }
  }
  const result = run("ps", ["-eo", "user=,pid=,args="]);
  if (result.status !== 0) {
    return { owners: [], error: failure(result) };
  }
  const owners = [];
  for (const line of result.stdout.split(/\r?\n/u)) {
    if (!/openclaw/iu.test(line) || /security-self-check|host-baseline/iu.test(line)) {
      continue;
    }
    const match = /^\s*(\S+)\s+(\d+)\s+/u.exec(line);
    if (match) {
      owners.push({ user: match[1], pid: Number(match[2]) });
    }
  }
  return { owners };
}

function fileMetadata(filePath) {
  try {
    const stat = fs.lstatSync(filePath);
    return {
      exists: true,
      mode: stat.mode & 0o777,
      file: stat.isFile(),
      directory: stat.isDirectory(),
      symlink: stat.isSymbolicLink(),
      uid: stat.uid,
    };
  } catch (error) {
    return error?.code === "ENOENT" ? { exists: false } : { exists: false, error: error.message };
  }
}

function powershellSingleQuoted(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

function collectWindowsAcl(target) {
  const script = [
    "$ErrorActionPreference='Stop'",
    `$acl=Get-Acl -LiteralPath ${powershellSingleQuoted(target)}`,
    "$rules=$acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | ForEach-Object { [pscustomobject]@{sid=$_.IdentityReference.Value;rights=[int64]$_.FileSystemRights;type=$_.AccessControlType.ToString()} }",
    "$ownerSid=$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value",
    "$currentSid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    "[pscustomobject]@{ownerSid=$ownerSid;currentSid=$currentSid;rules=@($rules)} | ConvertTo-Json -Compress -Depth 4",
  ].join("; ");
  const result = run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script]);
  if (result.status !== 0) {
    return { error: failure(result) };
  }
  try {
    return parseJson(result.stdout);
  } catch (error) {
    return { error: error.message };
  }
}

function unsafeWindowsAclEntries(acl) {
  const trusted = new Set(
    [acl?.ownerSid, acl?.currentSid, "S-1-5-18", "S-1-5-32-544"]
      .filter(Boolean)
      .map((sid) => String(sid).toUpperCase()),
  );
  return (acl?.rules || []).filter(
    (rule) =>
      rule.type === "Allow" &&
      !trusted.has(String(rule.sid || "").toUpperCase()) &&
      (Number(rule.rights) & WINDOWS_SENSITIVE_RIGHTS) !== 0,
  );
}

function windowsAclOwnerKnown(acl) {
  return Boolean(String(acl?.ownerSid || "").trim());
}

function checkPathPermissions(checks, id, label, target, expectedType, expectedMode) {
  const meta = fileMetadata(target);
  const expectedTypeLabel = expectedType === "directory" ? "directory" : "file";
  if (!meta.exists) {
    return observe(checks, id, "WARN", `${label} does not exist or is inaccessible`, {
      path: target,
    });
  }
  const typeOk = expectedType === "directory" ? meta.directory : meta.file;
  if (process.platform === "win32") {
    const acl = collectWindowsAcl(target);
    if (acl.error) {
      return observe(checks, id, "NOT_TESTED", `Failed to collect the Windows ACL for ${label}: ${acl.error}`, {
        path: target,
      });
    }
    const unsafe = unsafeWindowsAclEntries(acl);
    const ownerKnown = windowsAclOwnerKnown(acl);
    return observe(
      checks,
      id,
      typeOk && !meta.symlink && ownerKnown && !unsafe.length ? "PASS" : "FAIL",
      `${label} type=${typeOk ? expectedTypeLabel : "unexpected"}; recognized owner=${String(ownerKnown)}; untrusted sensitive ACL entries=${unsafe.length}`,
      { path: target, expectedType, unsafeSids: [...new Set(unsafe.map((rule) => rule.sid))] },
    );
  }
  const modeOk = meta.mode === expectedMode;
  observe(
    checks,
    id,
    typeOk && modeOk && !meta.symlink ? "PASS" : "FAIL",
    `${label} type/permission mode=${typeOk ? expectedTypeLabel : "unexpected"}/0${meta.mode.toString(8)}`,
    {
      path: target,
      expectedType,
      expectedMode: `0${expectedMode.toString(8)}`,
    },
  );
}

function checkOptionalPathPermissions(checks, id, label, target, expectedType, expectedMode) {
  const meta = fileMetadata(target);
  if (!meta.exists) {
    return observe(checks, id, "NOT_APPLICABLE", `${label} does not exist; skipping the permission check`, {
      path: target,
    });
  }
  return checkPathPermissions(checks, id, label, target, expectedType, expectedMode);
}

function readApprovals(stateDir) {
  const filePath = path.join(stateDir, "exec-approvals.json");
  try {
    const file = JSON.parse(fs.readFileSync(filePath, "utf8"));
    const patterns = walkObjects(file).flatMap((entry) =>
      typeof entry.value.pattern === "string" ? [entry.value.pattern] : [],
    );
    return { file, patterns, path: filePath };
  } catch (error) {
    return error?.code === "ENOENT"
      ? { file: {}, patterns: [], path: filePath }
      : { file: {}, patterns: [], path: filePath, error: error.message };
  }
}

function sandboxAvailableForScope(scope, sandboxes) {
  const sandbox = sandboxes.find((entry) =>
    scope.agentId ? entry.agentId === scope.agentId : !entry.agentId || entry.agentId === "main",
  );
  return sandbox?.sandbox?.sessionIsSandboxed === true;
}

function isOpenClawDefaultSource(source) {
  return typeof source === "string" && source.startsWith("OpenClaw default");
}

function execModeFromPolicy(security, ask) {
  if (security === "deny") {
    return "deny";
  }
  if (security === "allowlist" && ask === "off") {
    return "allowlist";
  }
  if (security === "full" && ask !== "always") {
    return "full";
  }
  return "ask";
}

function execPolicies(execPolicy, sandboxes) {
  const scopes = execPolicy?.effectivePolicy?.scopes;
  if (!Array.isArray(scopes)) {
    throw new Error("exec-policy show did not return an effectivePolicy.scopes array");
  }
  return scopes.map((scope) => {
    const requestedHost = scope.host?.requested;
    const effectiveHost =
      requestedHost === "auto"
        ? sandboxAvailableForScope(scope, sandboxes)
          ? "sandbox"
          : "gateway"
        : requestedHost;
    const sandboxed = effectiveHost === "sandbox";
    const security = sandboxed
      ? isOpenClawDefaultSource(scope.security?.requestedSource)
        ? "deny"
        : scope.security?.requested
      : scope.security?.effective;
    const ask = sandboxed
      ? isOpenClawDefaultSource(scope.ask?.requestedSource)
        ? "off"
        : scope.ask?.requested
      : scope.ask?.effective;
    const explicitSandboxMode =
      sandboxed && String(scope.mode?.requestedSource || "").endsWith(".mode");
    const mode = sandboxed
      ? explicitSandboxMode
        ? scope.mode?.requested
        : execModeFromPolicy(security, ask)
      : scope.mode?.effective;
    return {
      label: scope.scopeLabel || scope.configPath || scope.agentId || "tools.exec",
      agentId: scope.agentId || "main",
      policy: {
        host: effectiveHost,
        mode,
        security,
        ask,
        autoReview: mode === "auto" && security === "allowlist" && ask === "on-miss",
      },
    };
  });
}

function broadExecPattern(value) {
  const normalized = String(value || "")
    .trim()
    .replaceAll("\\", "/")
    .toLowerCase();
  const base = path.posix.basename(normalized).replace(/\.exe$/u, "");
  return (
    normalized === "*" ||
    normalized.endsWith("/**") ||
    [
      "bash",
      "cmd",
      "env",
      "node",
      "perl",
      "powershell",
      "pwsh",
      "python",
      "python3",
      "ruby",
      "sh",
      "zsh",
    ].includes(base)
  );
}

function effectiveLogLevel(config) {
  const env = process.env.OPENCLAW_LOG_LEVEL?.trim();
  return env && LOG_LEVELS.has(env)
    ? { level: env, source: "OPENCLAW_LOG_LEVEL" }
    : { level: config.logging?.level || "info", source: "logging.level/default" };
}

function truthy(value) {
  return ["1", "on", "true", "yes"].includes(
    String(value || "")
      .trim()
      .toLowerCase(),
  );
}

function collectHistoryLimits(config) {
  const values = [];
  for (const entry of walkObjects(config.channels || {})) {
    for (const key of ["historyLimit", "dmHistoryLimit"]) {
      if (typeof entry.value[key] === "number") {
        values.push({ path: `channels.${entry.path}.${key}`, value: entry.value[key] });
      }
    }
  }
  if (typeof config.messages?.groupChat?.historyLimit === "number") {
    values.push({
      path: "messages.groupChat.historyLimit",
      value: config.messages.groupChat.historyLimit,
    });
  }
  return values;
}

function channelPolicies(channels) {
  const policies = [];
  for (const entry of walkObjects(channels || {})) {
    const node = entry.value;
    if (node.enabled === false) {
      continue;
    }
    const dmPolicy = node.dmPolicy ?? node.dm?.policy;
    const groupPolicy = node.groupPolicy;
    if (dmPolicy === undefined && groupPolicy === undefined) {
      continue;
    }
    const channelId = entry.path.split(".")[0];
    const channelRoot = channels?.[channelId];
    policies.push({
      path: `channels.${entry.path}`,
      dmPolicy,
      groupPolicy,
      allowFrom: node.allowFrom ?? node.dm?.allowFrom,
      groupAllowFrom:
        node.groupAllowFrom ??
        (channelId === "telegram"
          ? (node.allowFrom ?? channelRoot?.groupAllowFrom ?? channelRoot?.allowFrom)
          : undefined),
    });
  }
  return policies;
}

function effectiveToolScope(globalTools, agent) {
  const agentTools = agent?.tools;
  return {
    label: agent?.id || "global",
    profile: agentTools?.profile ?? globalTools.profile,
    profileAlsoAllow: agentTools?.alsoAllow ?? globalTools.alsoAllow,
    policyLayers: [globalTools, ...(agentTools ? [agentTools] : [])],
  };
}

function toolScopeObservation(scope) {
  const alsoAllow = Array.isArray(scope.profileAlsoAllow) ? scope.profileAlsoAllow : [];
  const profileRestrictive =
    ["minimal", "coding", "messaging"].includes(scope.profile) && !wildcard(alsoAllow);
  const allowRestrictive = scope.policyLayers.some((layer) => {
    if (!Array.isArray(layer.allow)) {
      return false;
    }
    return !wildcard([...layer.allow, ...(Array.isArray(layer.alsoAllow) ? layer.alsoAllow : [])]);
  });
  const effectiveRestrictive = profileRestrictive || allowRestrictive;
  const explicitlyBroad =
    scope.profile === "full" ||
    wildcard(alsoAllow) ||
    scope.policyLayers.some((layer) => wildcard(layer.allow));
  if (!effectiveRestrictive && explicitlyBroad) {
    return { status: "FAIL", message: `${scope.label}: the effective policy grants wildcard/full tool access` };
  }
  if (!effectiveRestrictive && !scope.profile && alsoAllow.length) {
    return {
      status: "FAIL",
      message: `${scope.label}: alsoAllow is configured without a restrictive profile/allowlist, so the default tool surface remains available`,
    };
  }
  const highRisk = alsoAllow.filter((value) =>
    HIGH_RISK_TOOLS.has(String(value).trim().toLowerCase()),
  );
  if (highRisk.length) {
    return {
      status: "WARN",
      message: `${scope.label}: alsoAllow adds high-risk tools: ${highRisk.join(", ")}`,
    };
  }
  if (effectiveRestrictive) {
    const suffix = alsoAllow.length ? `, plus ${alsoAllow.length} explicit alsoAllow entries` : "";
    return {
      status: "PASS",
      message: `${scope.label}: a restrictive profile or explicit allowlist is configured${suffix}`,
    };
  }
  if (scope.policyLayers.some((layer) => Array.isArray(layer.deny) && layer.deny.length > 0)) {
    return {
      status: "WARN",
      message: `${scope.label}: a deny-only policy is broader than an allowlist`,
    };
  }
  return { status: "WARN", message: `${scope.label}: no explicit least-privilege tool policy is configured` };
}

function agentToAgentObservation(tools) {
  const a2a = tools?.agentToAgent;
  if (a2a?.enabled !== true) {
    return {
      status: "PASS",
      message: "tools.agentToAgent.enabled=false; cross-Agent session access is disabled",
    };
  }
  const rawAllow = Array.isArray(a2a.allow) ? a2a.allow : [];
  const allow = rawAllow.map((value) => String(value || "").trim()).filter(Boolean);
  if (!rawAllow.length) {
    return {
      status: "FAIL",
      message:
        "tools.agentToAgent.enabled=true but allow is unset; the current OpenClaw policy matches any Agent. Configure an explicit Agent ID list or disable this feature",
    };
  }
  if (!allow.length) {
    return {
      status: "WARN",
      message: "tools.agentToAgent.allow contains only empty values; cross-Agent access is effectively unavailable. Clean up the configuration",
    };
  }
  if (allow.includes("*")) {
    return {
      status: "FAIL",
      message: 'tools.agentToAgent.allow contains "*", allowing any Agent to access any other Agent. Use an explicit Agent ID list instead',
    };
  }
  const wildcardPatterns = allow.filter((value) => value.includes("*"));
  if (wildcardPatterns.length) {
    return {
      status: "WARN",
      message: `tools.agentToAgent.allow contains ${wildcardPatterns.length} wildcard patterns; confirm that their scope is sufficiently narrow`,
    };
  }
  return {
    status: "PASS",
    message: `tools.agentToAgent.allow is restricted to ${allow.length} explicit entries`,
  };
}

function isPrivilegedProcessOwner(owner) {
  const user = String(owner.user || "")
    .trim()
    .toLowerCase();
  const domainUser = `${owner.domain || ""}\\${owner.user || ""}`.toLowerCase();
  const sid = String(owner.sid || "").toUpperCase();
  if (!user && !sid) {
    return undefined;
  }
  return (
    sid === "S-1-5-18" ||
    sid.endsWith("-500") ||
    ["root", "administrator", "system"].includes(user) ||
    ["builtin\\administrator", "nt authority\\system"].includes(domainUser)
  );
}

function parseOpenClawVersion(value) {
  return /\b\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\b/u.exec(String(value || ""))?.[0];
}

function contextTokensStatus(value) {
  return typeof value === "number" && value > 0 ? "PASS" : value === undefined ? "WARN" : "FAIL";
}

class NpmVerificationError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function npmVerificationFailure(message) {
  return new NpmVerificationError("FAIL", message);
}

function parseReleaseVersion(version) {
  const match =
    /^(?<year>\d{4})\.(?<month>[1-9]\d?)\.(?<patch>[1-9]\d*)(?:-(?:(?<channel>alpha|beta)\.(?<prerelease>[1-9]\d*)|(?<correction>[1-9]\d*)))?$/u.exec(
      version,
    );
  if (!match?.groups) {
    return undefined;
  }
  const month = Number(match.groups.month);
  if (month < 1 || month > 12) {
    return undefined;
  }
  return {
    baseVersion: `${match.groups.year}.${match.groups.month}.${match.groups.patch}`,
    channel: match.groups.channel || "stable",
  };
}

function verifyNpmRegistrySignatures({ integrity, keys, packageName, signatures, version }) {
  if (typeof integrity !== "string" || !integrity.startsWith("sha512-")) {
    throw npmVerificationFailure(`The npm registry did not return SHA-512 integrity for ${packageName}`);
  }
  if (!Array.isArray(signatures) || signatures.length === 0) {
    throw npmVerificationFailure(`The npm registry did not return signatures for ${packageName}@${version}`);
  }

  const payload = `${packageName}@${version}:${integrity}`;
  for (const signature of signatures) {
    const key = Array.isArray(keys)
      ? keys.find((candidate) => candidate?.keyid === signature?.keyid)
      : undefined;
    if (!key?.key || !signature?.sig) {
      continue;
    }
    try {
      const publicKey = createPublicKey({
        key: Buffer.from(key.key, "base64"),
        format: "der",
        type: "spki",
      });
      if (
        verifySignature(
          "sha256",
          Buffer.from(payload, "utf8"),
          publicKey,
          Buffer.from(signature.sig, "base64"),
        )
      ) {
        return;
      }
    } catch {
      // Try the remaining signatures and keys returned by the registry.
    }
  }
  throw npmVerificationFailure(`npm registry signature verification failed for ${packageName}@${version}`);
}

function resolveNpmProvenancePolicy(statement, version) {
  const parsedVersion = parseReleaseVersion(version);
  if (!parsedVersion) {
    throw npmVerificationFailure(`Unsupported OpenClaw release version: ${version}`);
  }
  const workflow = statement?.predicate?.buildDefinition?.externalParameters?.workflow;
  const workflowRef = workflow?.ref;
  const expectedReleaseRef = `refs/heads/release/${parsedVersion.baseVersion}`;
  const trustedRef =
    workflowRef === "refs/heads/main" ||
    workflowRef === expectedReleaseRef ||
    (parsedVersion.channel === "alpha" &&
      /^refs\/heads\/tideclaw\/alpha\/[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}Z$/u.test(
        workflowRef || "",
      ));
  if (
    workflow?.repository !== NPM_PROVENANCE_REPOSITORY ||
    workflow?.path !== NPM_PROVENANCE_WORKFLOW_PATH ||
    !trustedRef ||
    statement?.predicate?.runDetails?.builder?.id !== NPM_PROVENANCE_BUILDER_ID
  ) {
    throw npmVerificationFailure(
      `npm provenance for ${version} is not bound to a trusted OpenClaw GitHub release workflow`,
    );
  }
  return {
    certificateIssuer: NPM_PROVENANCE_CERTIFICATE_ISSUER,
    certificateIdentityURI: `${NPM_PROVENANCE_REPOSITORY}/${NPM_PROVENANCE_WORKFLOW_PATH}@${workflowRef}`,
  };
}

async function readBoundedJson(url) {
  const response = await fetch(url, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(NPM_REGISTRY_REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`npm registry request failed: HTTP ${response.status}`);
  }
  if (!response.body) {
    throw new Error("The npm registry response body is empty");
  }
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    size += value.byteLength;
    if (size > NPM_REGISTRY_RESPONSE_BODY_MAX_BYTES) {
      await reader.cancel();
      throw npmVerificationFailure("The npm registry response exceeds the 4 MiB safety limit");
    }
    chunks.push(Buffer.from(value));
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw npmVerificationFailure("The npm registry returned invalid JSON");
  }
}

async function loadSigstoreVerify() {
  try {
    const sigstore = await import("sigstore");
    if (typeof sigstore.verify === "function") {
      return sigstore.verify;
    }
  } catch {
    // Continue searching dependency directories for the current or global OpenClaw installation.
  }
  for (const args of [["root"], ["root", "-g"]]) {
    const result = run("npm", args, 30_000);
    if (result.status !== 0 || !result.stdout.trim()) {
      continue;
    }
    try {
      const requireFromOpenClaw = createRequire(
        path.join(result.stdout.trim(), "openclaw", "package.json"),
      );
      const sigstore = requireFromOpenClaw("sigstore");
      if (typeof sigstore.verify === "function") {
        return sigstore.verify;
      }
    } catch {
      // Continue with the next dependency location.
    }
  }
  throw new NpmVerificationError(
    "NOT_TESTED",
    "Unable to load OpenClaw's sigstore dependency; provenance cryptographic verification was not completed",
  );
}

async function verifyNpmProvenanceAttestation({ attestations, integrity, packageName, version }) {
  const expectedSubject = `pkg:npm/${packageName}@${version}`;
  const expectedSha512 = Buffer.from(integrity.slice("sha512-".length), "base64").toString("hex");
  let policyError;
  let verificationError;
  for (const attestation of attestations || []) {
    if (attestation?.predicateType !== NPM_PROVENANCE_PREDICATE_TYPE) {
      continue;
    }
    const payload = attestation?.bundle?.dsseEnvelope?.payload;
    if (!payload) {
      continue;
    }
    let statement;
    try {
      statement = JSON.parse(Buffer.from(payload, "base64").toString("utf8"));
    } catch {
      continue;
    }
    const subjectMatches = statement?.subject?.some(
      (subject) => subject?.name === expectedSubject && subject?.digest?.sha512 === expectedSha512,
    );
    if (!subjectMatches) {
      continue;
    }
    let policy;
    try {
      policy = resolveNpmProvenancePolicy(statement, version);
    } catch (error) {
      policyError = error;
      continue;
    }
    const verifyBundle = await loadSigstoreVerify();
    try {
      await verifyBundle(attestation.bundle, policy);
      return;
    } catch (error) {
      verificationError = error;
    }
  }
  if (verificationError) {
    throw npmVerificationFailure(
      `Sigstore provenance verification failed for ${packageName}@${version}: ${verificationError.message}`,
    );
  }
  if (policyError) {
    throw policyError;
  }
  throw npmVerificationFailure(
    `The provenance for ${packageName}@${version} does not match the package version or SHA-512 integrity`,
  );
}

async function collectPackageProvenance(versionOutput) {
  const version = parseOpenClawVersion(versionOutput);
  if (!version) {
    return { status: "NOT_TESTED", error: "Unable to parse the OpenClaw version required for npm source verification" };
  }
  let registry;
  try {
    const registryResult = run("npm", ["config", "get", "registry"], 30_000);
    if (registryResult.status !== 0) {
      throw new Error(failure(registryResult));
    }
    registry = new URL(registryResult.stdout.trim());
    if (registry.protocol !== "https:") {
      throw npmVerificationFailure(`The npm registry must use HTTPS: ${registry.origin}`);
    }
    if (!registry.pathname.endsWith("/")) {
      registry.pathname = `${registry.pathname}/`;
    }
    const packageName = "openclaw";
    const packageDocument = await readBoundedJson(
      new URL(`${encodeURIComponent(packageName)}/${encodeURIComponent(version)}`, registry),
    );
    const keysDocument = await readBoundedJson(new URL("-/npm/v1/keys", registry));
    const integrity = packageDocument?.dist?.integrity;
    const signatures = packageDocument?.dist?.signatures;
    verifyNpmRegistrySignatures({
      packageName,
      version,
      integrity,
      signatures,
      keys: keysDocument?.keys,
    });

    const provenance = packageDocument?.dist?.attestations?.provenance;
    const attestationUrl = packageDocument?.dist?.attestations?.url;
    if (
      provenance?.predicateType !== NPM_PROVENANCE_PREDICATE_TYPE ||
      typeof attestationUrl !== "string" ||
      !attestationUrl
    ) {
      throw npmVerificationFailure(`${packageName}@${version} is missing SLSA provenance metadata`);
    }
    const parsedAttestationUrl = new URL(attestationUrl);
    const attestationPrefix = new URL("-/npm/v1/attestations/", registry).pathname;
    if (
      parsedAttestationUrl.protocol !== "https:" ||
      parsedAttestationUrl.origin !== registry.origin ||
      !parsedAttestationUrl.pathname.startsWith(attestationPrefix)
    ) {
      throw npmVerificationFailure(`${packageName}@${version} returned an untrusted attestation URL`);
    }
    const attestationDocument = await readBoundedJson(parsedAttestationUrl);
    if (
      !Array.isArray(attestationDocument?.attestations) ||
      !attestationDocument.attestations.length
    ) {
      throw npmVerificationFailure(`${packageName}@${version} is missing a provenance attestation`);
    }
    await verifyNpmProvenanceAttestation({
      packageName,
      version,
      integrity,
      attestations: attestationDocument.attestations,
    });
    return {
      status: "PASS",
      version,
      registryOrigin: registry.origin,
      integrityAlgorithm: "sha512",
      registrySignatureVerified: true,
      provenanceVerified: true,
    };
  } catch (error) {
    return {
      status: error instanceof NpmVerificationError ? error.status : "NOT_TESTED",
      version,
      registryOrigin: registry?.origin,
      error: error.message,
    };
  }
}

function clawHubProtocol(env = process.env) {
  const value = env.OPENCLAW_CLAWHUB_URL || env.CLAWHUB_URL || "https://clawhub.ai";
  try {
    return new URL(value).protocol;
  } catch {
    return undefined;
  }
}

function hasConfiguredEnabledChannel(channels) {
  return Object.values(channels || {}).some(
    (channel) =>
      channel &&
      typeof channel === "object" &&
      channel.enabled !== false &&
      Object.keys(channel).length > 0,
  );
}

function wildcard(values) {
  return Array.isArray(values) && values.some((value) => String(value).trim() === "*");
}

function evaluate(
  config,
  audit,
  sandboxes,
  listeners,
  processes,
  approvals,
  options,
  auditError,
  runtimeEvidence,
) {
  const checks = createReportChecks();
  const port = gatewayPort(config);
  const bind = config.gateway?.bind || "loopback";
  observe(
    checks,
    "OpenClaw-1-1",
    ["lan", "auto", "custom"].includes(bind) ? "FAIL" : bind === "tailnet" ? "WARN" : "PASS",
    `Effective Gateway bind mode=${bind}`,
  );
  observe(
    checks,
    "OpenClaw-1-1",
    port === DEFAULT_PORT ? "WARN" : "PASS",
    `Effective Gateway port=${port}`,
  );
  const mdns = config.discovery?.mdns?.mode || "minimal";
  observe(
    checks,
    "OpenClaw-1-1",
    mdnsStatus(mdns, bind),
    `discovery.mdns.mode=${mdns}${mdns === "minimal" ? " (OpenClaw recommended value)" : ""}`,
  );
  if (listeners.error) {
    observe(checks, "OpenClaw-1-1", "ERROR", `Failed to collect listener information: ${listeners.error}`);
  } else {
    const browser = browserPorts(port, config.browser);
    const relevant = listeners.listeners.filter(
      (item) =>
        item.port === port ||
        item.port === browser.control ||
        browser.explicit.includes(item.port) ||
        (item.port >= browser.start && item.port <= browser.end),
    );
    if (!relevant.length) {
      observe(
        checks,
        "OpenClaw-1-1",
        "NOT_TESTED",
        "Gateway/Browser is not currently listening, so the runtime bind address cannot be verified",
      );
    }
    for (const item of relevant) {
      observe(
        checks,
        "OpenClaw-1-1",
        isLoopback(item.address) ? "PASS" : "FAIL",
        `${item.protocol} ${item.address}:${item.port}`,
        { pid: item.pid, process: item.process },
      );
    }
  }
  addAudit(checks, "OpenClaw-1-1", audit, [/^gateway\./u, /^discovery\.mdns/u, /^browser\./u]);

  const authMode = config.gateway?.auth?.mode;
  observe(
    checks,
    "OpenClaw-1-2",
    authMode === "none" ? "FAIL" : authMode ? "PASS" : "WARN",
    `gateway.auth.mode=${authMode || "unset"}`,
  );
  addAudit(checks, "OpenClaw-1-2", audit, [
    "gateway.token_too_short",
    /^gateway\..*auth/u,
    /^config\.secrets/u,
  ]);
  if (!sandboxes.length) {
    observe(checks, "OpenClaw-2-1", "ERROR", "No sandbox-explain result was obtained");
  }
  for (const sandbox of sandboxes) {
    const state = sandbox.sandbox || {};
    observe(
      checks,
      "OpenClaw-2-1",
      state.mode === "all" && state.sessionIsSandboxed === true ? "PASS" : "FAIL",
      `${sandbox.agentId || "default Agent"}: mode=${state.mode || "off"}, sandboxed=${String(state.sessionIsSandboxed)}`,
    );
  }
  addAudit(checks, "OpenClaw-2-1", audit, [/^sandbox\./u]);
  const workspaceOnly = config.tools?.fs?.workspaceOnly === true;
  observe(
    checks,
    "OpenClaw-2-2",
    workspaceOnly ? "PASS" : "FAIL",
    `tools.fs.workspaceOnly=${String(workspaceOnly)}`,
  );
  for (const agent of config.agents?.list || []) {
    const effective = agent.tools?.fs?.workspaceOnly ?? workspaceOnly;
    observe(
      checks,
      "OpenClaw-2-2",
      effective ? "PASS" : "FAIL",
      `${agent.id}: effective workspaceOnly=${String(effective)}`,
    );
  }
  for (const sandbox of sandboxes) {
    const access = sandbox.sandbox?.workspaceAccess;
    observe(
      checks,
      "OpenClaw-2-2",
      ["none", "ro"].includes(access) ? "PASS" : "WARN",
      `${sandbox.agentId || "default Agent"}: workspaceAccess=${access || "unknown"}`,
    );
  }
  checkPathPermissions(checks, "OpenClaw-2-2", "State directory", options.stateDir, "directory", 0o700);
  checkPathPermissions(checks, "OpenClaw-2-2", "Configuration file", options.configPath, "file", 0o600);
  checkOptionalPathPermissions(
    checks,
    "OpenClaw-2-2",
    "State-directory .env",
    path.join(options.stateDir, ".env"),
    "file",
    0o600,
  );
  if (runtimeEvidence.execPolicyError) {
    observe(
      checks,
      "OpenClaw-3-1",
      "ERROR",
      `exec-policy show failed: ${runtimeEvidence.execPolicyError}`,
    );
    observe(
      checks,
      "OpenClaw-3-2",
      "ERROR",
      `exec-policy show failed: ${runtimeEvidence.execPolicyError}`,
    );
  } else {
    try {
      for (const entry of execPolicies(runtimeEvidence.execPolicy, sandboxes)) {
        const policy = entry.policy;
        const restricted = policy.security === "deny" || policy.security === "allowlist";
        observe(
          checks,
          "OpenClaw-3-1",
          policy.security === "full" ? "FAIL" : restricted ? "PASS" : "NOT_TESTED",
          `${entry.label}: host=${policy.host || "unknown"}, security=${policy.security || "unknown"}, ask=${policy.ask || "unknown"}, mode=${policy.mode || "derived"}`,
        );
        const human =
          policy.security === "deny" ||
          (["on-miss", "always"].includes(policy.ask) && !policy.autoReview);
        observe(
          checks,
          "OpenClaw-3-2",
          policy.security === "unknown" || policy.ask === "unknown"
            ? "NOT_TESTED"
            : human
              ? "PASS"
              : "FAIL",
          `${entry.label}: host=${policy.host || "unknown"}, ask=${policy.ask || "off"}, autoReview=${String(policy.autoReview === true)}`,
        );
      }
    } catch (error) {
      observe(checks, "OpenClaw-3-1", "ERROR", error.message);
      observe(checks, "OpenClaw-3-2", "ERROR", error.message);
    }
  }
  const broad = approvals.patterns.filter(broadExecPattern);
  observe(
    checks,
    "OpenClaw-3-1",
    broad.length ? "FAIL" : "PASS",
    broad.length
      ? `Found ${broad.length} broad exec allowlist patterns`
      : "No broad exec allowlist patterns were found",
  );
  if (approvals.error) {
    observe(checks, "OpenClaw-3-1", "ERROR", `Failed to parse exec approvals: ${approvals.error}`);
  }
  addAudit(checks, "OpenClaw-3-1", audit, [/^tools\.exec/u, /^gateway\.nodes/u]);
  const globalTools = config.tools || {};
  const toolScopes = [
    effectiveToolScope(globalTools),
    ...(config.agents?.list || []).map((agent) => effectiveToolScope(globalTools, agent)),
  ];
  for (const scope of toolScopes) {
    const result = toolScopeObservation(scope);
    observe(checks, "OpenClaw-3-3", result.status, result.message);
  }
  {
    const result = agentToAgentObservation(globalTools);
    observe(checks, "OpenClaw-3-3", result.status, result.message);
  }
  if (processes.error) {
    observe(checks, "OpenClaw-3-3", "ERROR", `Failed to collect process-owner information: ${processes.error}`);
  } else if (!processes.owners.length) {
    observe(checks, "OpenClaw-3-3", "NOT_TESTED", "No running OpenClaw process was found");
  } else {
    for (const owner of processes.owners) {
      const privileged = isPrivilegedProcessOwner(owner);
      observe(
        checks,
        "OpenClaw-3-3",
        privileged === undefined ? "NOT_TESTED" : privileged ? "FAIL" : "PASS",
        `PID ${owner.pid} owner=${owner.domain ? `${owner.domain}\\` : ""}${owner.user || "unknown"}`,
      );
    }
  }
  const autoConfigured = config.update?.auto?.enabled === true;
  const disabledByEnv = truthy(process.env.OPENCLAW_NO_AUTO_UPDATE);
  const effectiveAuto = autoConfigured && !disabledByEnv;
  const checkOnStart = config.update?.checkOnStart !== false;
  observe(
    checks,
    "OpenClaw-4-1",
    checkOnStart ? "PASS" : "FAIL",
    `update.checkOnStart=${String(checkOnStart)}`,
  );
  observe(
    checks,
    "OpenClaw-4-1",
    effectiveAuto ? "FAIL" : autoConfigured ? "WARN" : "PASS",
    `Effective automatic updates=${String(effectiveAuto)}${disabledByEnv ? " (disabled by OPENCLAW_NO_AUTO_UPDATE)" : ""}`,
  );

  const limits = collectHistoryLimits(config);
  if (!limits.length) {
    observe(checks, "OpenClaw-5-3", "WARN", "No explicit Channel history limit was found");
  }
  for (const limit of limits) {
    observe(
      checks,
      "OpenClaw-5-3",
      Number.isInteger(limit.value) && limit.value >= 0 ? "PASS" : "FAIL",
      `${limit.path}=${limit.value}`,
    );
  }
  const contextTokens = config.agents?.defaults?.contextTokens;
  observe(
    checks,
    "OpenClaw-5-3",
    contextTokensStatus(contextTokens),
    `agents.defaults.contextTokens=${contextTokens ?? "unset"}`,
  );
  const compaction = config.agents?.defaults?.compaction;
  observe(
    checks,
    "OpenClaw-5-3",
    compaction && ["default", "safeguard"].includes(compaction.mode || "safeguard")
      ? "PASS"
      : "WARN",
    `compaction.mode=${compaction?.mode || "implicit default"}`,
  );

  const log = effectiveLogLevel(config);
  observe(
    checks,
    "OpenClaw-7-1",
    log.level === "silent" ? "FAIL" : ["fatal", "error"].includes(log.level) ? "WARN" : "PASS",
    `Effective log level=${log.level}, source=${log.source}`,
  );
  const logPath = options.logPath || config.logging?.file;
  if (logPath) {
    checkPathPermissions(
      checks,
      "OpenClaw-7-1",
      "Log file",
      path.resolve(logPath.replace(/^~(?=$|[\\/])/u, os.homedir())),
      "file",
      0o600,
    );
  } else {
    observe(checks, "OpenClaw-7-1", "NOT_TESTED", "The log-file path is derived at runtime and its permissions have not been verified");
  }
  if (auditError) {
    observe(checks, "OpenClaw-7-2", "ERROR", `Security audit failed: ${auditError}`);
  } else {
    observe(checks, "OpenClaw-7-2", "PASS", "openclaw security audit --deep completed", audit.summary);
    if ((audit.summary?.critical || 0) > 0) {
      observe(checks, "OpenClaw-7-2", "FAIL", `${audit.summary.critical} critical-severity audit findings`);
    }
    if ((audit.summary?.warn || 0) > 0) {
      observe(checks, "OpenClaw-7-2", "WARN", `${audit.summary.warn} warning-severity audit findings`);
    }
  }
  observe(
    checks,
    "OpenClaw-7-2",
    config.tools?.loopDetection?.enabled === true ? "PASS" : "WARN",
    `tools.loopDetection.enabled=${String(config.tools?.loopDetection?.enabled === true)}`,
  );
  const redact = config.logging?.redactSensitive || "tools";
  observe(
    checks,
    "OpenClaw-7-3",
    redact === "off" ? "FAIL" : "PASS",
    `logging.redactSensitive=${redact}`,
  );
  observe(
    checks,
    "OpenClaw-7-3",
    "PASS",
    config.logging?.redactPatterns?.length
      ? `${config.logging.redactPatterns.length} custom redaction patterns are configured`
      : "Built-in sensitive-value redaction is enabled and no custom pattern is configured",
  );
  if (logPath) {
    checkPathPermissions(
      checks,
      "OpenClaw-7-3",
      "Log file",
      path.resolve(logPath.replace(/^~(?=$|[\\/])/u, os.homedir())),
      "file",
      0o600,
    );
  } else {
    observe(checks, "OpenClaw-7-3", "NOT_TESTED", "The log-file path is derived at runtime and its permissions have not been verified");
  }

  const channel = runtimeEvidence.updateStatus?.channel?.value ?? config.update?.channel;
  if (runtimeEvidence.updateStatusError && !channel) {
    observe(
      checks,
      "OpenClaw-9-3",
      "NOT_TESTED",
      `Failed to collect the effective update channel: ${runtimeEvidence.updateStatusError}`,
    );
  } else {
    observe(
      checks,
      "OpenClaw-9-3",
      ["stable", "beta"].includes(channel) ? "PASS" : "FAIL",
      `Effective update channel=${channel || "unknown"}`,
    );
  }
  const registryResult = run("npm", ["config", "get", "registry"]);
  if (registryResult.status !== 0) {
    observe(checks, "OpenClaw-9-3", "ERROR", `Failed to collect the npm registry: ${failure(registryResult)}`);
  } else {
    const registry = registryResult.stdout.trim();
    observe(
      checks,
      "OpenClaw-9-3",
      registry.startsWith("https://") ? "PASS" : "FAIL",
      `npm registry protocol=${registry.split(":")[0] || "unknown"}`,
    );
  }
  const clawHubScheme = clawHubProtocol();
  observe(
    checks,
    "OpenClaw-9-3",
    clawHubScheme === "https:" ? "PASS" : "FAIL",
    `ClawHub registry protocol=${clawHubScheme?.replace(":", "") || "invalid"}`,
  );
  const provenance = runtimeEvidence.packageProvenance;
  if (provenance.error) {
    observe(
      checks,
      "OpenClaw-9-3",
      provenance.status || "NOT_TESTED",
      `Source verification failed for openclaw@${provenance.version || "unknown"}: ${provenance.error}`,
      {
        registryOrigin: provenance.registryOrigin,
        verification: "registry-signature-and-sigstore-provenance",
      },
    );
  } else {
    observe(
      checks,
      "OpenClaw-9-3",
      "PASS",
      `openclaw@${provenance.version}: SHA-512 integrity, npm registry signatures, and Sigstore/SLSA provenance were all verified`,
      {
        registryOrigin: provenance.registryOrigin,
        integrityAlgorithm: provenance.integrityAlgorithm,
        registrySignatureVerified: provenance.registrySignatureVerified,
        provenanceVerified: provenance.provenanceVerified,
      },
    );
  }

  const policies = channelPolicies(config.channels);
  if (!policies.length) {
    const configuredChannel = hasConfiguredEnabledChannel(config.channels);
    observe(
      checks,
      "OpenClaw-11-1",
      configuredChannel ? "WARN" : "NOT_APPLICABLE",
      configuredChannel
        ? "Configured Channels use implicit or plugin-specific policies; review native audit findings"
        : "No configured and enabled Channel was found",
    );
  }
  for (const policy of policies) {
    if (policy.dmPolicy !== undefined) {
      const disabled = policy.dmPolicy === "disabled";
      const unsafe = !disabled && (policy.dmPolicy === "open" || wildcard(policy.allowFrom));
      const empty =
        policy.dmPolicy === "allowlist" &&
        (!Array.isArray(policy.allowFrom) || !policy.allowFrom.length);
      observe(
        checks,
        "OpenClaw-11-1",
        unsafe || empty ? "FAIL" : "PASS",
        `${policy.path}: dmPolicy=${policy.dmPolicy}`,
      );
    }
    if (policy.groupPolicy !== undefined) {
      const disabled = policy.groupPolicy === "disabled";
      const unsafe =
        !disabled && (policy.groupPolicy === "open" || wildcard(policy.groupAllowFrom));
      const empty =
        policy.groupPolicy === "allowlist" &&
        (!Array.isArray(policy.groupAllowFrom) || !policy.groupAllowFrom.length);
      observe(
        checks,
        "OpenClaw-11-1",
        unsafe || empty ? "FAIL" : "PASS",
        `${policy.path}: groupPolicy=${policy.groupPolicy}`,
      );
    }
  }
  addAudit(checks, "OpenClaw-11-1", audit, [
    /^channels\..*\.dm\./u,
    /^channels\..*allowlist/u,
    /dangerous_name_matching_enabled$/u,
  ]);

  return [...checks.values()];
}

function summary(checks) {
  return Object.fromEntries(
    Object.keys(STATUS_RANK).map((status) => [
      status,
      checks.filter((check) => check.status === status).length,
    ]),
  );
}

function manualReviewInstruction(checkId, message) {
  if (/log-file path is derived at runtime/iu.test(message)) {
    return "Have the OpenClaw Agent locate the actual log file for the current version using read-only methods and verify configuration overrides and runtime defaults. Record sanitized file metadata or rerun the baseline with --log-path <actual-path> to collect permission evidence.";
  }
  return `Have the OpenClaw Agent collect evidence for ${checkId} using the current CLI, source-code contracts, and targeted read-only host commands, then write it to the manual-review JSON file. If the result remains indeterminate, retain NOT_TESTED and record the blocker.`;
}

function collectManualReview(checks) {
  const items = [];
  for (const check of checks) {
    for (const [index, observation] of check.observations.entries()) {
      if (observation.status !== "NOT_TESTED") {
        continue;
      }
      items.push({
        reviewId: `${check.id}#${index + 1}`,
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

function printHuman(report) {
  console.log(`OpenClaw Host Security Self-Check (${report.generatedAt})`);
  console.log(`OpenClaw: ${report.openclawVersion}  Host: ${report.platform}`);
  console.log(
    Object.entries(report.summary)
      .map(([key, value]) => `${key}=${value}`)
      .join(" "),
  );
  for (const check of report.checks) {
    console.log(`\n[${check.status}] ${check.id} ${check.title}`);
    for (const observation of check.observations) {
      console.log(`  - ${observation.status}: ${observation.message}`);
    }
  }
  if (report.manualReview.required) {
    console.log("\nAdditional targeted OpenClaw review is required:");
    for (const item of report.manualReview.items) {
      console.log(`  - ${item.checkId}: ${item.requiredAction}`);
    }
  }
}

async function main() {
  const startedAt = new Date().toISOString();
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
    if (options.help) {
      return (printHelp(), 0);
    }
    const versionResult = runOpenClaw(options, ["--version"]);
    if (versionResult.status !== 0) {
      throw new Error(`OpenClaw CLI execution failed: ${failure(versionResult)}`);
    }
    const config = {};
    const configErrors = [];
    for (const key of [
      "gateway",
      "discovery",
      "agents",
      "tools",
      "update",
      "logging",
      "channels",
      "messages",
      "browser",
    ]) {
      try {
        config[key] = configGet(options, key);
      } catch (error) {
        configErrors.push(error.message);
      }
    }
    let audit = { summary: {}, findings: [] };
    let auditError;
    const auditResult = runOpenClaw(options, ["security", "audit", "--deep", "--json"]);
    if (auditResult.status === 0) {
      try {
        audit = parseJson(auditResult.stdout);
      } catch (error) {
        auditError = error.message;
      }
    } else {
      auditError = failure(auditResult);
    }
    let execPolicy;
    let execPolicyError;
    const execPolicyResult = runOpenClaw(options, ["exec-policy", "show", "--json"]);
    if (execPolicyResult.status === 0) {
      try {
        execPolicy = parseJson(execPolicyResult.stdout);
      } catch (error) {
        execPolicyError = error.message;
      }
    } else {
      execPolicyError = failure(execPolicyResult);
    }
    let updateStatus;
    let updateStatusError;
    const updateStatusResult = runOpenClaw(options, ["update", "status", "--json"]);
    if (updateStatusResult.status === 0) {
      try {
        updateStatus = parseJson(updateStatusResult.stdout);
      } catch (error) {
        updateStatusError = error.message;
      }
    } else {
      updateStatusError = failure(updateStatusResult);
    }
    const sandboxes = [];
    const agentIds = [
      undefined,
      ...(config.agents?.list || []).map((agent) => agent.id).filter(Boolean),
    ];
    for (const agentId of new Set(agentIds)) {
      const args = ["sandbox", "explain", ...(agentId ? ["--agent", agentId] : []), "--json"];
      const result = runOpenClaw(options, args);
      if (result.status === 0) {
        try {
          sandboxes.push(parseJson(result.stdout));
        } catch (error) {
          configErrors.push(`sandbox explain ${agentId || "default Agent"}: ${error.message}`);
        }
      } else {
        configErrors.push(`sandbox explain ${agentId || "default Agent"}: ${failure(result)}`);
      }
    }
    const runtimeEvidence = {
      execPolicy,
      execPolicyError,
      updateStatus,
      updateStatusError,
      packageProvenance: await collectPackageProvenance(
        versionResult.stdout.trim() || versionResult.stderr.trim(),
      ),
    };
    const checks = evaluate(
      config,
      audit,
      sandboxes,
      collectListeners(),
      collectProcesses(),
      readApprovals(options.stateDir),
      options,
      auditError,
      runtimeEvidence,
    );
    for (const message of configErrors) {
      for (const check of checks) {
        check.observations.push({
          status: "ERROR",
          method: "static",
          timestamp: new Date().toISOString(),
          source: "OpenClaw CLI",
          message,
        });
        check.status = "ERROR";
      }
    }
    const finishedAt = new Date().toISOString();
    const report = {
      schemaVersion: SCHEMA_VERSION,
      checklistVersion: CHECKLIST_VERSION,
      skill: { name: "claw-security-self-check", version: SKILL_VERSION },
      mode: "baseline",
      generatedAt: finishedAt,
      startedAt,
      finishedAt,
      openclawVersion: versionResult.stdout.trim() || versionResult.stderr.trim(),
      platform: `${process.platform}/${process.arch}`,
      stateDir: options.stateDir,
      configPath: options.configPath,
      reportPaths: { json: options.output || null, markdown: null },
      excludedScope: [
        "External network reachability",
        "Real unauthorized third-party IM accounts",
        "Remote SIEM/log delivery",
      ],
      summary: summary(checks),
      checks,
      manualReview: collectManualReview(checks),
    };
    const encoded = `${JSON.stringify(report, null, 2)}\n`;
    if (options.output) {
      fs.writeFileSync(options.output, encoded, { encoding: "utf8", mode: 0o600 });
    }
    if (options.json) {
      process.stdout.write(encoded);
    } else {
      printHuman(report);
    }
    return report.summary.ERROR ? 2 : report.summary.FAIL ? 1 : 0;
  } catch (error) {
    const payload = {
      schemaVersion: SCHEMA_VERSION,
      fatal: error.message,
      generatedAt: new Date().toISOString(),
    };
    if (options?.json) {
      console.log(JSON.stringify(payload, null, 2));
    } else {
      console.error(`Error (ERROR): ${error.message}`);
    }
    return 2;
  }
}

process.exitCode = await main();
