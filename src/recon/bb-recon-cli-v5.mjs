#!/usr/bin/env node
import { Command } from "commander";
import { load } from "cheerio";
import { JSDOM } from "jsdom";
import fs from "node:fs";
import path from "node:path";

const VERSION = "5.0.1";
const DEFAULT_UA = `bb-recon-cli/${VERSION}`;

function sev(score) {
  if (score >= 11) return "critical";
  if (score >= 8) return "high";
  if (score >= 5) return "medium";
  return "low";
}

function short(v, n = 300) {
  return String(v ?? "").replace(/\s+/g, " ").trim().slice(0, n);
}

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function slugifyUrl(url) {
  return url.replace(/^https?:\/\//, "").replace(/[^a-zA-Z0-9._-]+/g, "_").slice(0, 180);
}

function dedupeFindings(items) {
  const seen = new Set();
  return items
    .sort((a, b) => b.score - a.score)
    .filter((x) => {
      const k = [x.bucket, x.type, x.location || "", x.preview].join("|");
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
}

async function fetchText(url, timeoutMs, userAgent) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: {
        "user-agent": userAgent,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      },
      redirect: "follow",
      signal: controller.signal
    });
    return { finalUrl: res.url, status: res.status, text: await res.text() };
  } finally {
    clearTimeout(timeout);
  }
}

function findApiEndpoints(baseUrl, text) {
  const out = [];
  const seen = new Set();
  const patterns = [
    /https?:\/\/[a-zA-Z0-9._-]+(?:\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]*)?/g,
    /["'`](\/[a-zA-Z0-9/_\-?&=.:%+#~]+)["'`]/g,
    /\b(?:fetch|axios\.(?:get|post|put|patch|delete)|open)\s*\(\s*["'`]([^"'`]+)["'`]/g,
    /\burl\s*:\s*["'`]([^"'`]+)["'`]/g
  ];

  for (const rx of patterns) {
    for (const m of text.matchAll(rx)) {
      const raw = m[1] || m[0];
      try {
        const u = new URL(raw, baseUrl).href;
        if (seen.has(u)) continue;
        seen.add(u);

        let score = 0;
        const reasons = [];
        if (/\/(?:api|graphql|gql|rest|rpc|ajax|internal|admin|services?|svc|v[1-9])(?:\/|$)/i.test(u)) {
          score += 4;
          reasons.push("api-like path");
        }
        if (/graphql|gql/i.test(u)) {
          score += 5;
          reasons.push("graphql");
        }
        if (/\/v[1-9](?:\/|$)/i.test(u)) {
          score += 2;
          reasons.push("versioned");
        }
        if (/json|query|mutation|endpoint|service|rpc/i.test(u)) {
          score += 2;
          reasons.push("api semantics");
        }
        if (score >= 4) {
          out.push({
            bucket: "apiEndpoints",
            type: "api-endpoint",
            location: "static",
            score,
            severity: sev(score),
            reasons,
            preview: u
          });
        }
      } catch {}
    }
  }

  return out;
}

function findHiddenContent(html) {
  const out = [];
  const dom = new JSDOM(html);
  const { document, NodeFilter } = dom.window;

  for (const el of [...document.querySelectorAll("*")]) {
    const style = (el.getAttribute("style") || "").toLowerCase();
    const hidden =
      el.hasAttribute("hidden") ||
      el.getAttribute("aria-hidden") === "true" ||
      /display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0/.test(style);

    if (!hidden) continue;

    const text = short(el.textContent || "");
    let score = 0;
    const reasons = [];
    if (/\b(admin|debug|internal|staging|beta|feature|flag|secret|token|auth|graphql|api)\b/i.test(text)) {
      score += 3;
      reasons.push("interesting text");
    }
    if (/\b[a-f0-9]{24,}\b|\b\d{6,}\b|\/(?:api|graphql|internal|admin|v1|v2|v3)\b/i.test(text)) {
      score += 2;
      reasons.push("route or ID");
    }
    if (score >= 4) {
      out.push({
        bucket: "hiddenContent",
        type: "hidden-element",
        location: el.tagName,
        score,
        severity: sev(score),
        reasons,
        preview: text
      });
    }
  }

  const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
  while (walker.nextNode()) {
    const text = short(walker.currentNode.nodeValue || "");
    let score = 0;
    const reasons = [];
    if (/\b(admin|debug|internal|staging|beta|feature|flag|secret|token|auth|graphql|api)\b/i.test(text)) {
      score += 3;
      reasons.push("interesting comment");
    }
    if (/\b[a-f0-9]{24,}\b|\b\d{6,}\b|\/(?:api|graphql|internal|admin|v1|v2|v3)\b/i.test(text)) {
      score += 2;
      reasons.push("route or ID");
    }
    if (score >= 4) {
      out.push({
        bucket: "hiddenContent",
        type: "comment",
        location: "HTML comment",
        score,
        severity: sev(score),
        reasons,
        preview: text
      });
    }
  }

  return out;
}

function findPrototypePollution(url, text) {
  const out = [];
  const u = new URL(url);

  for (const [k, v] of u.searchParams.entries()) {
    let score = 0;
    const reasons = [];
    if (/(^|[.[\]_%:-])(?:__proto__|prototype|constructor)(?:[.[\]_%:-]|$)/i.test(k)) {
      score += 5;
      reasons.push("suspicious query key");
    }
    if (/(?:__proto__|constructor(?:\.prototype)?|prototype)(?:\[|\]|\.|%5B|%5D|%2E|$)/i.test(decodeURIComponent(`${k}=${v}`))) {
      score += 2;
      reasons.push("encoded pollution path");
    }
    if (score >= 5) {
      out.push({
        bucket: "prototypePollution",
        type: "url-param",
        location: "location.search",
        score,
        severity: sev(score),
        reasons,
        preview: `${k}=${v}`
      });
    }
  }

  if (/qs\.parse|querystring\.parse|Object\.assign|deepmerge|defaultsDeep|__proto__|constructor\.prototype|prototype/i.test(text)) {
    let score = 0;
    const reasons = [];
    if (/qs\.parse|querystring\.parse|URLSearchParams/i.test(text)) {
      score += 3;
      reasons.push("parser");
    }
    if (/Object\.assign|deepmerge|defaultsDeep|merge/i.test(text)) {
      score += 4;
      reasons.push("merge");
    }
    if (/__proto__|constructor\.prototype|prototype/i.test(text)) {
      score += 4;
      reasons.push("pollution path");
    }
    if (score >= 5) {
      out.push({
        bucket: "prototypePollution",
        type: "script-signal",
        location: "static-js",
        score,
        severity: sev(score),
        reasons,
        preview: short(
          text.match(/.{0,120}(?:__proto__|constructor|prototype|qs\.parse|Object\.assign).{0,120}/is)?.[0] || text
        )
      });
    }
  }

  return out;
}

function findXssSinks(text) {
  const out = [];
  const sinks = [
    { rx: /\.innerHTML\s*=/, type: "innerHTML", weight: 5 },
    { rx: /\.outerHTML\s*=/, type: "outerHTML", weight: 5 },
    { rx: /insertAdjacentHTML\s*\(/, type: "insertAdjacentHTML", weight: 5 },
    { rx: /document\.write(?:ln)?\s*\(/, type: "document.write", weight: 5 },
    { rx: /\.srcdoc\s*=/, type: "srcdoc", weight: 5 },
    { rx: /\beval\s*\(/, type: "eval", weight: 5 },
    { rx: /\bnew Function\s*\(/, type: "new Function", weight: 5 },
    { rx: /\.html\s*\(/, type: "jquery.html", weight: 3 }
  ];

  for (const sink of sinks) {
    if (!sink.rx.test(text)) continue;
    let score = sink.weight;
    const reasons = [`sink:${sink.type}`];

    if (/\blocation\.(search|hash|href|pathname)\b|\bURLSearchParams\b|\bsearchParams\.get(?:All)?\b/.test(text)) {
      score += 2;
      reasons.push("location source");
    }
    if (/\bmessage\.data\b|\baddEventListener\s*\(\s*["']message["']/.test(text)) {
      score += 3;
      reasons.push("postMessage source");
    }
    if (/\bDOMPurify\.sanitize\s*\(|\bsanitize(?:HTML)?\s*\(/i.test(text)) {
      score -= 3;
      reasons.push("sanitizer-nearby");
    }

    if (score >= 7) {
      out.push({
        bucket: "xssSinks",
        type: "xss-sink-block",
        location: "static-js",
        score,
        severity: sev(score),
        reasons,
        preview: short(
          text.match(/.{0,140}(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|srcdoc|eval|new Function|\.html\().{0,140}/is)?.[0] || text
        )
      });
    }
  }

  return out;
}

function summarize(findings) {
  const flat = [
    ...findings.prototypePollution,
    ...findings.hiddenContent,
    ...findings.apiEndpoints,
    ...findings.xssSources,
    ...findings.xssSinks
  ];

  const byBucket = {
    prototypePollution: findings.prototypePollution.length,
    hiddenContent: findings.hiddenContent.length,
    apiEndpoints: findings.apiEndpoints.length,
    xssSources: findings.xssSources.length,
    xssSinks: findings.xssSinks.length
  };

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of flat) bySeverity[f.severity] += 1;

  return { total: flat.length, byBucket, bySeverity };
}

function toMarkdown(result) {
  const flat = [
    ...result.findings.prototypePollution,
    ...result.findings.hiddenContent,
    ...result.findings.apiEndpoints,
    ...result.findings.xssSources,
    ...result.findings.xssSinks
  ].sort((a, b) => b.score - a.score);

  const lines = [
    "# bb-recon v5 report",
    "",
    `- url: ${result.meta.url}`,
    `- finalUrl: ${result.meta.finalUrl}`,
    `- title: ${result.meta.title}`,
    `- status: ${result.meta.status}`,
    `- exportedAt: ${result.meta.exportedAt}`,
    "",
    "## Summary",
    "",
    `- total findings: ${result.summary.total}`,
    `- prototype pollution: ${result.summary.byBucket.prototypePollution}`,
    `- hidden content: ${result.summary.byBucket.hiddenContent}`,
    `- api endpoints: ${result.summary.byBucket.apiEndpoints}`,
    `- xss sinks: ${result.summary.byBucket.xssSinks}`,
    ""
  ];

  for (const f of flat) {
    lines.push(`### [${f.severity}] ${f.bucket} :: ${f.type}`);
    lines.push(`- score: ${f.score}`);
    lines.push(`- location: ${f.location || "n/a"}`);
    lines.push(`- reasons: ${f.reasons.join(", ")}`);
    lines.push("```text");
    lines.push(f.preview);
    lines.push("```");
    lines.push("");
  }

  return lines.join("\n");
}

async function scanTarget(url, opts) {
  const page = await fetchText(url, opts.timeoutMs, opts.userAgent);
  const $ = load(page.text);

  const assets = [{ url: page.finalUrl, kind: "html", content: page.text }];

  const scriptUrls = new Set();
  $("script[src]").each((_, el) => {
    const src = $(el).attr("src");
    if (!src) return;
    try {
      scriptUrls.add(new URL(src, page.finalUrl).href);
    } catch {}
  });

  $("script:not([src])").each((_, el) => {
    const type = ($(el).attr("type") || "").toLowerCase();
    assets.push({
      url: `${page.finalUrl}#inline-${assets.length}`,
      kind: type.includes("json") ? "json" : "script",
      content: $(el).html() || ""
    });
  });

  let count = 0;
  for (const scriptUrl of scriptUrls) {
    if (count >= opts.maxScripts) break;
    count += 1;
    try {
      const script = await fetchText(scriptUrl, opts.timeoutMs, opts.userAgent);
      assets.push({ url: script.finalUrl, kind: "script", content: script.text });
    } catch {}
  }

  const allText = assets.map(a => a.content).join("\n\n");

  const findings = {
    prototypePollution: dedupeFindings(findPrototypePollution(url, allText)),
    hiddenContent: dedupeFindings(findHiddenContent(page.text)),
    apiEndpoints: dedupeFindings(findApiEndpoints(page.finalUrl, allText)),
    xssSources: [],
    xssSinks: dedupeFindings(findXssSinks(allText))
  };

  const result = {
    meta: {
      version: VERSION,
      url,
      finalUrl: page.finalUrl,
      title: $("title").first().text().trim(),
      exportedAt: new Date().toISOString(),
      status: page.status,
      userAgent: opts.userAgent
    },
    summary: summarize(findings),
    findings,
    notes: {
      limitations: [
        "Static analysis only.",
        "No browser execution or SPA hydration.",
        "No runtime fetch/XHR/WebSocket interception."
      ],
      cheatSheet: {
        prototypePollution: ["Prioritize nested keys plus parser and merge/path-set chains."],
        hiddenContent: ["Prioritize hidden routes, IDs, flags, templates, and JSON state."],
        apiEndpoints: ["Compare alternate versions and internal-looking paths."],
        xss: ["Best static signal is source plus transform plus sink proximity."]
      }
    }
  };

  if (opts.includeHtml) result.meta.html = page.text;
  return result;
}

function writeJson(filePath, data) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
}

function writeMarkdown(filePath, content) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, content, "utf8");
}

function printSummary(data) {
  console.log(`\n[scan] ${data.meta.url}`);
  console.log(`title: ${data.meta.title}`);
  console.log(`status: ${data.meta.status}`);
  console.log(`total findings: ${data.summary.total}`);
  console.log(`severity: critical=${data.summary.bySeverity.critical} high=${data.summary.bySeverity.high} medium=${data.summary.bySeverity.medium} low=${data.summary.bySeverity.low}`);
  console.log(`buckets: pp=${data.summary.byBucket.prototypePollution} hidden=${data.summary.byBucket.hiddenContent} api=${data.summary.byBucket.apiEndpoints} xssSink=${data.summary.byBucket.xssSinks}`);
}

function buildScanOptions(cmd) {
  return {
    timeoutMs: cmd.timeoutMs ?? 30000,
    maxScripts: cmd.maxScripts ?? 40,
    includeHtml: cmd.includeHtml ?? false,
    userAgent: cmd.userAgent || DEFAULT_UA,
    out: cmd.out,
    markdown: cmd.md,
    quiet: cmd.quiet ?? false
  };
}

const program = new Command();
program
  .name("bb-recon")
  .description("Browserless bug bounty recon CLI for static client-side triage")
  .version(VERSION)
  .showHelpAfterError(true);

program
  .command("scan")
  .description("Scan a single URL")
  .argument("<url>", "Target URL to scan")
  .option("-o, --out <file>", "Write JSON output to file")
  .option("-m, --md <file>", "Write Markdown report to file")
  .option("-t, --timeout-ms <number>", "Request timeout in milliseconds", (v) => Number(v), 30000)
  .option("-s, --max-scripts <number>", "Maximum linked scripts to fetch", (v) => Number(v), 40)
  .option("-u, --user-agent <ua>", "Override User-Agent", DEFAULT_UA)
  .option("--include-html", "Include final HTML in JSON output", false)
  .option("-q, --quiet", "Suppress console summary", false)
  .action(async (url, cmd) => {
    const opts = buildScanOptions(cmd);
    const result = await scanTarget(url, opts);
    if (!opts.quiet) printSummary(result);
    if (opts.out) writeJson(opts.out, result);
    if (opts.markdown) writeMarkdown(opts.markdown, toMarkdown(result));
    if (opts.out) console.log(`written: ${opts.out}`);
    if (opts.markdown) console.log(`written: ${opts.markdown}`);
  });

program
  .command("batch")
  .description("Scan newline-delimited URLs from a file")
  .argument("<file>", "Path to file containing URLs")
  .option("-d, --out-dir <dir>", "Output directory", "./bb-recon-out")
  .option("-t, --timeout-ms <number>", "Request timeout in milliseconds", (v) => Number(v), 30000)
  .option("-s, --max-scripts <number>", "Maximum linked scripts to fetch", (v) => Number(v), 40)
  .option("-u, --user-agent <ua>", "Override User-Agent", DEFAULT_UA)
  .option("--include-html", "Include final HTML in JSON output", false)
  .option("-q, --quiet", "Suppress per-target console summary", false)
  .action(async (file, cmd) => {
    const opts = buildScanOptions(cmd);
    const outDir = cmd.outDir;
    ensureDir(outDir);

    const urls = fs.readFileSync(file, "utf8")
      .split(/\r?\n/)
      .map((x) => x.trim())
      .filter(Boolean)
      .filter((x) => /^https?:\/\//i.test(x));

    if (!urls.length) throw new Error("No valid URLs in input file");

    for (const url of urls) {
      const slug = slugifyUrl(url);
      const jsonPath = path.join(outDir, `${slug}.json`);
      const mdPath = path.join(outDir, `${slug}.md`);
      const result = await scanTarget(url, opts);
      writeJson(jsonPath, result);
      writeMarkdown(mdPath, toMarkdown(result));
      if (!opts.quiet) printSummary(result);
    }
  });

program
  .command("doctor")
  .description("Validate runtime prerequisites")
  .action(() => {
    console.log(JSON.stringify({
      node: process.version,
      fetch: typeof fetch === "function",
      commander: true,
      cheerio: true,
      jsdom: true
    }, null, 2));
  });

program.parseAsync(process.argv).catch((error) => {
  const message = error instanceof Error ? error.stack || error.message : String(error);
  console.error(message);
  process.exit(1);
});
