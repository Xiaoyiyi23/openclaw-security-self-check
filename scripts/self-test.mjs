#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const baseDir = path.dirname(fileURLToPath(import.meta.url));
const scripts = ["host-baseline.mjs", "report-merge.mjs"];

for (const script of scripts) {
  const args = [script, "--self-test"];
  const result = spawnSync(process.execPath, args, {
    cwd: baseDir,
    encoding: "utf8",
    shell: false,
  });
  if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout || `${script} 自测失败\n`);
    process.exitCode = result.status || 1;
    break;
  }
  process.stdout.write(`${script}: ${result.stdout.trim()}\n`);
}

if (!process.exitCode) {
  console.log("全部自测通过（ALL SELF-TESTS PASS）");
}
