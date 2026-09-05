#!/usr/bin/env node
// Product security pre-deploy gate. Walks the repo, runs mechanical checks from
// the OWASP-based checklist, prints PASS/WARN/FAIL, and exits non-zero on any
// FAIL so it can gate a deploy. Pure Node (no ripgrep/grep dependency).
//
// Usage:  node security-gate.mjs [repoDir]
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

const ROOT = path.resolve(process.argv[2] || process.cwd());
const SKIP_DIRS = new Set(["node_modules", ".next", ".git", "dist", "build", "out", "coverage", ".turbo", ".vercel"]);
const CODE_EXT = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);
const results = [];

function walk(dir, acc = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return acc; }
  for (const e of entries) {
    if (e.name.startsWith(".") && e.name !== ".github") { /* skip dotfiles except workflows */ }
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      walk(full, acc);
    } else {
      acc.push(full);
    }
  }
  return acc;
}
const ALL = walk(ROOT);
const rel = (f) => path.relative(ROOT, f).replace(/\\/g, "/");
function read(f) { try { return fs.readFileSync(f, "utf8"); } catch { return ""; } }
const byExt = (exts) => ALL.filter((f) => exts.has(path.extname(f)));
const CODE = byExt(CODE_EXT);
const TF = ALL.filter((f) => f.endsWith(".tf"));
const DOCKER = ALL.filter((f) => /(^|\/)Dockerfile[^/]*$/.test(rel(f)));
const isNext = ALL.some((f) => /(^|\/)next\.config\.[mc]?js$/.test(rel(f)));

// A check records: name, status (PASS|WARN|FAIL), and findings[].
function check(name, status, findings = [], note = "") {
  results.push({ name, status, findings, note });
}
// Scan code files for a regex; return [{file,line,text}].
function scan(regex, files = CODE, { excludeExample = true } = {}) {
  const hits = [];
  for (const f of files) {
    const r = rel(f);
    if (excludeExample && /(example|sample|\.md$|CHECKLIST|security-gate)/i.test(r)) continue;
    const lines = read(f).split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      regex.lastIndex = 0;
      if (regex.test(lines[i])) hits.push({ file: r, line: i + 1, text: lines[i].trim().slice(0, 160) });
    }
  }
  return hits;
}

// Prefer git-tracked files: a "committed secret" is the risk, and this excludes
// gitignored local files (.env, tfvars) automatically.
let TRACKED = null;
try {
  const out = execSync("git ls-files", { cwd: ROOT, stdio: ["ignore", "pipe", "ignore"] }).toString();
  TRACKED = new Set(out.split(/\r?\n/).filter(Boolean));
} catch { /* not a git repo — fall back to all files */ }
const tracked = (files) => (TRACKED ? files.filter((f) => TRACKED.has(rel(f))) : files);

// 1. Hardcoded secrets (git-tracked only). Real literal secrets — not localhost
// dev creds, placeholders, or ${var} interpolation.
const secretRe = /(AKIA|ASIA)[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|xox[baprs]-[0-9A-Za-z-]{10,}|\bsk-[A-Za-z0-9]{20,}|postgres(ql)?:\/\/[^\s"'/]+:[^@\s"']+@|aws_secret_access_key\s*[:=]\s*["'][^"']{16,}/i;
const FALSE_POS = /localhost|127\.0\.0\.1|@db[:.\-]|@postgres[:.\-]|\$\{|:postgres@|:password@|REPLACE|EXAMPLE|CHANGE|xxxx|placeholder|<[a-z_]+>/i;
{
  const scanFiles = tracked([...CODE, ...ALL.filter((f) => /\.(json|ya?ml|tf|tfvars)$/.test(rel(f)) && !/example|lock/i.test(rel(f)))]);
  const hits = scan(secretRe, scanFiles).filter((h) => !FALSE_POS.test(h.text));
  check("1. Hardcoded secrets / keys / DB URLs", hits.length ? "FAIL" : "PASS", hits,
    hits.length ? "" : "(scanned git-tracked files; localhost/placeholder/${var} creds excluded)");
}

// 2. NEXT_PUBLIC_ secret leak
{
  const hits = scan(/NEXT_PUBLIC_[A-Z0-9_]*(SECRET|KEY|TOKEN|PASSWORD|PRIVATE|CREDENTIAL|DSN|CONN|AWS|BEDROCK)/);
  check("2. NEXT_PUBLIC_ secret exposed to client", hits.length ? "FAIL" : "PASS", hits);
}

// 3. Prisma unsafe raw SQL
{
  const unsafe = scan(/\$(queryRaw|executeRaw)Unsafe|Prisma\.raw\(/).filter((h) => !/^\s*(\/\/|\*|#)/.test(h.text));
  const interpolated = unsafe.filter((h) => /\$\{|["'`]\s*\+|\+\s*[a-zA-Z_]/.test(h.text));
  if (interpolated.length) check("3. Prisma raw SQL with interpolated input (SQLi)", "FAIL", interpolated);
  else if (unsafe.length) check("3. Prisma *Unsafe raw variant used (constant — review)", "WARN", unsafe, "Prefer $queryRaw tagged template.");
  else check("3. Prisma raw SQL", "PASS");
}

// 4. XSS: dangerouslySetInnerHTML (can't prove sanitize -> WARN)
{
  const hits = scan(/dangerouslySetInnerHTML/);
  check("4. dangerouslySetInnerHTML sinks (confirm each is sanitized)", hits.length ? "WARN" : "PASS", hits,
    hits.length ? "Trace each __html value to a sanitize-html/DOMPurify call at the write boundary." : "");
}

// 5. Static AWS keys in app
{
  const hits = scan(/AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|aws_access_key_id/);
  check("5. Static AWS credentials in app/config", hits.length ? "FAIL" : "PASS", hits, hits.length ? "Use the instance/role credential chain, not static keys." : "");
}

// 6. Public S3 in IaC
if (TF.length) {
  const pub = scan(/"Principal"\s*:\s*"\*"|AllUsers|acl\s*=\s*"public/i, TF, { excludeExample: false });
  const hasBucket = TF.some((f) => /aws_s3_bucket"/.test(read(f)));
  const hasBpa = TF.some((f) => /aws_s3_bucket_public_access_block/.test(read(f)));
  if (pub.length) check("6. Public S3 grant in IaC", "FAIL", pub);
  else if (hasBucket && !hasBpa) check("6. S3 bucket without public_access_block", "WARN", [], "Add aws_s3_bucket_public_access_block (all four flags true).");
  else check("6. S3 public access", "PASS");
} else check("6. S3 public access (no IaC found)", "PASS");

// 7. RDS public / open SG
if (TF.length) {
  const rdsPub = scan(/publicly_accessible\s*=\s*true/, TF, { excludeExample: false });
  const openDb = scan(/0\.0\.0\.0\/0/, TF, { excludeExample: false }).filter((h) => /5432|postgres|db|rds/i.test(read(path.join(ROOT, h.file))));
  const hits = [...rdsPub, ...openDb];
  check("7. RDS publicly accessible / 0.0.0.0/0 to DB", rdsPub.length ? "FAIL" : (openDb.length ? "WARN" : "PASS"), hits);
} else check("7. RDS exposure (no IaC found)", "PASS");

// 8. Over-broad IAM
if (TF.length || byExt(new Set([".json"])).length) {
  const iamFiles = [...TF, ...ALL.filter((f) => /iam|policy/i.test(rel(f)) && /\.(tf|json)$/.test(rel(f)))];
  const hits = [];
  for (const f of iamFiles) {
    const c = read(f);
    if (/"?Action"?\s*[:=]\s*\[?\s*"\*"/.test(c) && /"?Resource"?\s*[:=]\s*"\*"/.test(c)) hits.push({ file: rel(f), line: 0, text: 'Action:"*" + Resource:"*"' });
  }
  check("8. Over-broad IAM (Action:* + Resource:*)", hits.length ? "WARN" : "PASS", hits, hits.length ? "Scope to specific ARNs." : "");
} else check("8. IAM scoping (no policy files)", "PASS");

// 9. Security headers (Next apps)
if (isNext) {
  const cfg = ALL.filter((f) => /(next\.config|middleware)\.[mc]?[jt]s$/.test(rel(f))).map(read).join("\n");
  const need = { CSP: /content-security-policy/i, HSTS: /strict-transport-security/i, frame: /x-frame-options|frame-ancestors/i, nosniff: /x-content-type-options/i, ref: /referrer-policy/i };
  const missing = Object.entries(need).filter(([, re]) => !re.test(cfg)).map(([k]) => k);
  check("9. Security headers configured", missing.length ? "FAIL" : "PASS", missing.map((m) => ({ file: "next.config/middleware", line: 0, text: `missing ${m}` })),
    "Verify live with curl -sI after deploy.");
} else check("9. Security headers (not a Next app)", "PASS");

// 10. Public POST without rate limit
{
  const routes = ALL.filter((f) => /\/api\/.*\/route\.[tj]s$/.test(rel(f)));
  const publicPosts = routes.filter((f) => {
    const r = rel(f);
    if (/\/api\/(admin|auth)\//.test(r)) return false; // admin/auth handled separately
    return /export\s+async\s+function\s+POST/.test(read(f));
  });
  const unprot = publicPosts.filter((f) => !/rateLimit|ratelimit|limitByIp|arcjet|@upstash/i.test(read(f)));
  check("10. Public POST endpoints rate-limited", unprot.length ? "WARN" : "PASS",
    unprot.map((f) => ({ file: rel(f), line: 0, text: "no rate limiter detected" })),
    unprot.length ? "Add a per-IP limiter to each public POST." : "");
}

// 11. npm audit high/critical
try {
  const out = execSync("npm audit --audit-level=high --json", { cwd: ROOT, stdio: ["ignore", "pipe", "ignore"] }).toString();
  const j = JSON.parse(out);
  const v = j.metadata?.vulnerabilities || {};
  const high = (v.high || 0) + (v.critical || 0);
  check("11. npm audit (high/critical)", high ? "FAIL" : "PASS", high ? [{ file: "package-lock.json", line: 0, text: `${v.critical || 0} critical, ${v.high || 0} high` }] : []);
} catch (e) {
  // npm audit exits non-zero when vulns exist; parse its stdout.
  try {
    const out = e.stdout?.toString() || "";
    const j = JSON.parse(out);
    const v = j.metadata?.vulnerabilities || {};
    const high = (v.high || 0) + (v.critical || 0);
    check("11. npm audit (high/critical)", high ? "FAIL" : "PASS", high ? [{ file: "package-lock.json", line: 0, text: `${v.critical || 0} critical, ${v.high || 0} high` }] : []);
  } catch { check("11. npm audit", "WARN", [], "Could not run npm audit here — run it in CI."); }
}

// 11b. Stale declared floors: a package.json range whose floor is a materially
// older (and often vulnerable) version than what's actually locked. OSV-based
// scanners read the DECLARED floor, not the lockfile — so `^15.1.4` reads as
// 15.1.4 even when 15.5.25 is installed. Only sensitive packages, to avoid noise.
{
  const SENSITIVE = /^(next|next-auth|@auth\/|react|react-dom|nanoid|@prisma\/client|prisma|bcryptjs?|jsonwebtoken|jose|sanitize-html|cookie|undici|axios|ws)$/;
  const floor = (range) => {
    const m = String(range).match(/(\d+)\.(\d+)\.(\d+)/);
    return m ? [+m[1], +m[2], +m[3]] : null;
  };
  const majorBehind = []; // FAIL: genuinely stale, likely vulnerable floor
  const minorBehind = []; // WARN: floor-reading scanners (OSV) may flag; hygiene
  try {
    const pkg = JSON.parse(read(ALL.find((f) => /(^|\/)package\.json$/.test(rel(f)))));
    const lockFile = ALL.find((f) => /(^|\/)package-lock\.json$/.test(rel(f)));
    const lock = lockFile ? JSON.parse(read(lockFile)) : { packages: {} };
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    for (const [name, range] of Object.entries(deps)) {
      if (!SENSITIVE.test(name)) continue;
      const declared = floor(range);
      const installed = floor(lock.packages?.[`node_modules/${name}`]?.version || "");
      if (!declared || !installed) continue;
      const msg = { file: "package.json", line: 0, text: `${name}: declared floor ${range} but ${installed.join(".")} installed — floor-reading scanners (OSV) read ${declared.join(".")}` };
      if (declared[0] < installed[0]) majorBehind.push(msg); // a full major behind — real staleness
      else if (declared[1] < installed[1]) minorBehind.push(msg); // patch drift is normal; ignore
    }
  } catch { /* no package.json here */ }
  const hint = "Bump the package.json range floor to the patched (installed) version so floor-reading scanners see it as patched.";
  if (majorBehind.length) check("11b. No stale dependency floors (major behind lockfile)", "FAIL", majorBehind, hint);
  else check("11b. No stale dependency floors (major behind lockfile)", "PASS");
  if (minorBehind.length) check("11b-hygiene. Sensitive floors trail lockfile (minor)", "WARN", minorBehind, hint);
}

// 12. Unpinned Docker base image
if (DOCKER.length) {
  const hits = [];
  for (const f of DOCKER) {
    read(f).split(/\r?\n/).forEach((l, i) => {
      const m = l.match(/^\s*FROM\s+(\S+)/i);
      if (m && (/:latest\b/.test(m[1]) || !/[:@]/.test(m[1]))) hits.push({ file: rel(f), line: i + 1, text: l.trim() });
    });
  }
  check("12. Docker base image pinned (no :latest)", hits.length ? "WARN" : "PASS", hits, hits.length ? "Pin FROM to a version (ideally @sha256 digest)." : "");
} else check("12. Docker base image (no Dockerfile)", "PASS");

// 13. Weak password hashing on auth paths
{
  const authFiles = CODE.filter((f) => /(auth|login|password|credential)/i.test(rel(f)));
  const weak = scan(/createHash\(\s*["'](md5|sha1)["']/, authFiles);
  const strong = authFiles.some((f) => /bcrypt|argon2|scrypt/.test(read(f)));
  if (weak.length) check("13. Weak password hashing (md5/sha1)", "FAIL", weak);
  else if (authFiles.length && !strong) check("13. No strong password hash on auth path", "WARN", [], "Expected bcrypt/argon2.");
  else check("13. Password hashing", "PASS");
}

// 14. Dangerous exec / eval
{
  const hits = scan(/\beval\(|new Function\(|child_process|execSync\(|\bexecFileSync?\(|\bspawn\(/);
  // execCommand (rich-text) and pure client editor commands are not shell exec.
  const real = hits.filter((h) => !/execCommand|document\.exec/i.test(h.text));
  check("14. Dangerous exec/eval sinks", real.length ? "WARN" : "PASS", real, real.length ? "Confirm no request/LLM input reaches these." : "");
}

// 15. LLM output into a dangerous sink (heuristic)
{
  // AI handlers = files that actually import an LLM client or call it.
  const aiFiles = CODE.filter((f) => /@aws-sdk\/client-bedrock|askClaude|openai|ConverseCommand|InvokeModel|@\/lib\/ai/.test(read(f)));
  const dangerous = scan(/dangerouslySetInnerHTML|\$queryRawUnsafe|execSync\(|\beval\(/, aiFiles);
  check("15. LLM output into dangerous sink", dangerous.length ? "WARN" : "PASS", dangerous, dangerous.length ? "Ensure model output is treated as text, not executed/rendered raw." : "");
}

// ---- report ----
const order = { FAIL: 0, WARN: 1, PASS: 2 };
results.sort((a, b) => order[a.status] - order[b.status]);
const C = { FAIL: "\x1b[31m", WARN: "\x1b[33m", PASS: "\x1b[32m", reset: "\x1b[0m" };
console.log(`\n  Product security gate — ${rel(ROOT) || "."}\n`);
let fails = 0, warns = 0;
for (const r of results) {
  if (r.status === "FAIL") fails++;
  if (r.status === "WARN") warns++;
  console.log(`  ${C[r.status]}${r.status.padEnd(4)}${C.reset}  ${r.name}`);
  if (r.note) console.log(`         ${r.note}`);
  for (const f of r.findings.slice(0, 8)) console.log(`         - ${f.file}${f.line ? ":" + f.line : ""}  ${f.text}`);
  if (r.findings.length > 8) console.log(`         … and ${r.findings.length - 8} more`);
}
console.log(`\n  ${fails} FAIL · ${warns} WARN · ${results.length - fails - warns} PASS\n`);
if (fails > 0) {
  console.log(`  ${C.FAIL}Deploy blocked — resolve the FAILs above.${C.reset}\n`);
  process.exit(1);
}
if (warns > 0) console.log(`  ${C.WARN}Review each WARN (confirm safe or fix), then deploy.${C.reset}\n`);
else console.log(`  ${C.PASS}All checks passed.${C.reset}\n`);
process.exit(0);
