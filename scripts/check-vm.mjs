import fs from "node:fs";
import path from "node:path";

// Load .env.local if present
try {
  const envContent = fs.readFileSync(".env.local", "utf8");
  for (const line of envContent.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq > 0) {
      const key = trimmed.slice(0, eq).trim();
      let val = trimmed.slice(eq + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (!process.env[key]) process.env[key] = val;
    }
  }
} catch {}

import { getLiveSandbox } from "../packages/sandbox/src/live-runner.ts";

async function main() {
  console.log("Connecting to InstaBox VM...");
  let vm;
  try {
    vm = await getLiveSandbox();
    console.log("Connected successfully to InstaBox VM!\n");
  } catch (err) {
    console.error("Connection failed:", err.message);
    process.exit(1);
  }

  const checks = [
    { name: "Python 3 Runtime", cmd: "python3 --version" },
    {
      name: "Python Standard Modules",
      cmd: "python3 -c 'import urllib.request, ssl, json, subprocess, socket, hashlib, re, signal; print(\"Standard modules available\")'",
    },
    { name: "DNS Lookup Utility (dig)", cmd: "dig -v | head -n 1" },
    { name: "OpenSSL CLI", cmd: "openssl version" },
    { name: "Resource Limiter (prlimit)", cmd: "prlimit --version" },
    { name: "Job Locking (flock)", cmd: "flock --version" },
    { name: "Docker Daemon", cmd: "docker --version && docker ps -q" },
    {
      name: "Pre-pulled Security Images",
      cmd: "docker images --format '{{.Repository}}:{{.Tag}}' | grep -E 'zaproxy|nuclei|trivy|gitleaks' || echo 'No security images found'",
    },
  ];

  console.log("=== InstaBox VM Tool & Dependency Audit ===");
  for (const check of checks) {
    process.stdout.write(`Checking ${check.name.padEnd(30)}: `);
    try {
      const res = await vm.commands.run(check.cmd, { timeoutMs: 15000 });
      const out = (res.stdout || "").trim();
      const exitCode = res.exitCode ?? 0;
      if (exitCode === 0) {
        console.log("PASS");
        if (out) {
          const lines = out.split("\n");
          for (const l of lines) console.log(`   └─ ${l}`);
        }
      } else {
        console.log(`FAIL (exit ${exitCode})`);
        if (res.stderr) console.log(`   └─ ${res.stderr.trim()}`);
      }
    } catch (e) {
      console.log(`ERROR (${e.message})`);
    }
  }
  console.log("\nAudit complete!");
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
