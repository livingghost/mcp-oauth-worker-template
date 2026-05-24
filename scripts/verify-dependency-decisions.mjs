import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = process.cwd();
const docs = readFileSync(join(root, "docs", "dependency-decisions.md"), "utf8");
const lockfile = readFileSync(join(root, "pnpm-lock.yaml"), "utf8");
const manifests = [
  "package.json",
  "apps/mcp-worker/package.json",
  "packages/auth-worker/package.json",
  "packages/auth-db/package.json",
  "packages/mcp-tools/package.json",
  "packages/shared/package.json"
].map((path) => [path, JSON.parse(readFileSync(join(root, path), "utf8"))]);

const decisions = new Map();
for (const match of docs.matchAll(/^\| `([^`]+)` \| `([^`]+)` \| `([^`]+)` \|/gm)) {
  decisions.set(match[1], { adopted: match[2], latest: match[3] });
}

let failed = false;
const externalVersions = new Map();
for (const [path, manifest] of manifests) {
  for (const section of ["dependencies", "devDependencies"]) {
    for (const [name, version] of Object.entries(manifest[section] ?? {})) {
      if (version === "workspace:*") {
        continue;
      }
      const existing = externalVersions.get(name);
      if (existing && existing !== version) {
        fail(`Version mismatch for ${name}: ${existing} and ${version} (${path})`);
      }
      externalVersions.set(name, version);
    }
  }
}

const registryCache = new Map();

for (const [name, version] of externalVersions) {
  const decision = decisions.get(name);
  if (!decision) {
    fail(`Missing dependency decision for ${name}@${version}`);
    continue;
  }
  if (decision.adopted !== version) {
    fail(`Dependency decision for ${name} records ${decision.adopted}, package uses ${version}`);
  }
  if (!lockfile.includes(`${name}@${version}`)) {
    fail(`pnpm-lock.yaml does not contain ${name}@${version}`);
  }
  if (String(version).includes("-") && !docs.includes(`${name}\` | \`${version}\``)) {
    fail(`Pre-release dependency lacks explicit decision: ${name}@${version}`);
  }
  const latest = await registryLatest(name);
  if (decision.latest !== latest) {
    fail(`Dependency decision for ${name} records registry latest ${decision.latest}, registry currently reports ${latest}`);
  }
  if (version !== latest) {
    fail(`${name}@${version} is not registry latest ${latest}`);
  }
}

for (const name of decisions.keys()) {
  if (!externalVersions.has(name)) {
    fail(`Dependency decision exists for unused package ${name}`);
  }
}

if (failed) {
  process.exitCode = 1;
}

function fail(message) {
  console.error(message);
  failed = true;
}

async function registryLatest(name) {
  if (registryCache.has(name)) {
    return registryCache.get(name);
  }
  const registryName = name.startsWith("@") ? name.replace("/", "%2F") : name;
  const response = await fetch(`https://registry.npmjs.org/${registryName}/latest`, {
    headers: { Accept: "application/json" }
  });
  if (!response.ok) {
    fail(`Failed to query npm registry for ${name}: ${response.status}`);
    return "";
  }
  const body = await response.json();
  const latest = String(body.version ?? "");
  registryCache.set(name, latest);
  return latest;
}
