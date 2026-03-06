/**
 * pi-recon — reconnaissance & security toolkit for redteaming/pentesting.
 * /recon target.com          → full recon (headers, SSL, DNS, tech stack)
 * /recon headers target.com  → security headers audit
 * /recon ssl target.com      → SSL/TLS certificate check
 * /recon dns target.com      → DNS records
 * /recon ports target.com    → common port scan
 * /recon whois target.com    → WHOIS lookup
 * /recon crawl target.com    → discover paths (robots.txt, sitemap, common endpoints)
 * /recon tech target.com     → technology fingerprinting
 */
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { Type } from "@sinclair/typebox";
import { execSync } from "node:child_process";

const RST = "\x1b[0m";
const B = "\x1b[1m";
const D = "\x1b[2m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const MAGENTA = "\x1b[35m";

function section(title: string): string { return `\n${B}${CYAN}── ${title} ──${RST}`; }
function ok(s: string): string { return `${GREEN}✓${RST} ${s}`; }
function warn(s: string): string { return `${YELLOW}⚠${RST} ${s}`; }
function fail(s: string): string { return `${RED}✗${RST} ${s}`; }
function info(k: string, v: string): string { return `  ${D}${k}:${RST} ${v}`; }

// ── Security Headers ────────────────────────────────────────────────────────

const SECURITY_HEADERS: Record<string, { required: boolean; desc: string }> = {
  "strict-transport-security": { required: true, desc: "HSTS — forces HTTPS" },
  "content-security-policy": { required: true, desc: "CSP — prevents XSS" },
  "x-content-type-options": { required: true, desc: "Prevents MIME sniffing" },
  "x-frame-options": { required: false, desc: "Prevents clickjacking" },
  "x-xss-protection": { required: false, desc: "XSS filter (legacy)" },
  "referrer-policy": { required: true, desc: "Controls referrer info" },
  "permissions-policy": { required: false, desc: "Restricts browser features" },
  "cross-origin-opener-policy": { required: false, desc: "COOP — isolates context" },
  "cross-origin-resource-policy": { required: false, desc: "CORP — resource isolation" },
};

async function checkHeaders(url: string): Promise<string> {
  const lines: string[] = [section("Security Headers")];
  try {
    const res = await fetch(url, { method: "HEAD", redirect: "follow" });
    let score = 0;
    const total = Object.keys(SECURITY_HEADERS).length;
    for (const [header, meta] of Object.entries(SECURITY_HEADERS)) {
      const val = res.headers.get(header);
      if (val) {
        lines.push(ok(`${B}${header}${RST}: ${D}${val.slice(0, 80)}${RST}`));
        score++;
      } else if (meta.required) {
        lines.push(fail(`${B}${header}${RST} — ${RED}MISSING${RST} (${meta.desc})`));
      } else {
        lines.push(warn(`${B}${header}${RST} — not set (${meta.desc})`));
      }
    }
    // Check for info leaks
    const server = res.headers.get("server");
    const powered = res.headers.get("x-powered-by");
    if (server) lines.push(warn(`Server header exposed: ${B}${server}${RST}`));
    if (powered) lines.push(fail(`X-Powered-By exposed: ${B}${powered}${RST} — remove this!`));
    
    const grade = score >= 7 ? `${GREEN}A` : score >= 5 ? `${YELLOW}B` : score >= 3 ? `${YELLOW}C` : `${RED}F`;
    lines.push(`\n  ${B}Score: ${grade} (${score}/${total})${RST}`);
  } catch (e: any) { lines.push(fail(e.message)); }
  return lines.join("\n");
}

// ── SSL/TLS ─────────────────────────────────────────────────────────────────

async function checkSSL(host: string): Promise<string> {
  const lines: string[] = [section("SSL/TLS Certificate")];
  try {
    const res = await fetch(`https://${host}`, { method: "HEAD" });
    lines.push(ok(`HTTPS connection successful`));
    lines.push(info("Status", `${res.status}`));
    // Try openssl for cert details
    try {
      const out = execSync(`echo | openssl s_client -connect ${host}:443 -servername ${host} 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null`, { encoding: "utf-8", timeout: 10000 }).trim();
      if (out) for (const line of out.split("\n")) {
        const [k, ...v] = line.split("=");
        if (k && v.length) lines.push(info(k.trim(), v.join("=").trim()));
      }
    } catch { lines.push(D + "  (openssl not available for detailed cert info)" + RST); }
  } catch (e: any) {
    lines.push(fail(`SSL error: ${e.message}`));
  }
  return lines.join("\n");
}

// ── DNS ─────────────────────────────────────────────────────────────────────

function checkDNS(host: string): string {
  const lines: string[] = [section("DNS Records")];
  const types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"];
  for (const type of types) {
    try {
      const cmd = process.platform === "win32" 
        ? `nslookup -type=${type} ${host} 2>nul`
        : `dig +short ${host} ${type} 2>/dev/null`;
      const out = execSync(cmd, { encoding: "utf-8", timeout: 5000 }).trim();
      if (out && out.length > 0) {
        const records = out.split("\n")
          .filter(l => !l.startsWith("Server:") && !l.startsWith("Address:") && !l.startsWith("Non-authoritative") && l.trim())
          .map(l => l.trim()).filter(l => l && !l.includes("can't find"));
        if (records.length > 0) {
          lines.push(`  ${B}${MAGENTA}${type}${RST}`);
          for (const r of records.slice(0, 5)) lines.push(`    ${r}`);
        }
      }
    } catch {}
  }
  if (lines.length === 1) lines.push(D + "  No records found" + RST);
  return lines.join("\n");
}

// ── Port Scan ───────────────────────────────────────────────────────────────

async function scanPorts(host: string): Promise<string> {
  const lines: string[] = [section("Common Ports")];
  const ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 9090];
  const results: { port: number; open: boolean; service: string }[] = [];
  const services: Record<number, string> = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9090: "Proxy"
  };

  // Parallel TCP connect with timeout
  const checks = ports.map(port => {
    return new Promise<{ port: number; open: boolean }>(resolve => {
      const controller = new AbortController();
      const timer = setTimeout(() => { controller.abort(); resolve({ port, open: false }); }, 2000);
      fetch(`http://${host}:${port}`, { signal: controller.signal, method: "HEAD" })
        .then(() => { clearTimeout(timer); resolve({ port, open: true }); })
        .catch(e => {
          clearTimeout(timer);
          // "Connection refused" = closed, timeout/other = might be filtered
          resolve({ port, open: e.message?.includes("refused") ? false : !e.message?.includes("abort") });
        });
    });
  });

  const all = await Promise.all(checks);
  for (const { port, open } of all) {
    if (open) results.push({ port, open, service: services[port] || "unknown" });
  }

  if (results.length === 0) {
    lines.push(D + "  No open ports found (or host is filtered)" + RST);
  } else {
    for (const r of results) {
      lines.push(`  ${GREEN}${B}${String(r.port).padEnd(6)}${RST} ${r.service}`);
    }
  }
  lines.push(D + `\n  Scanned ${ports.length} common ports` + RST);
  return lines.join("\n");
}

// ── Technology Fingerprinting ───────────────────────────────────────────────

async function detectTech(url: string): Promise<string> {
  const lines: string[] = [section("Technology Stack")];
  try {
    const res = await fetch(url, { redirect: "follow" });
    const html = await res.text();
    const headers = Object.fromEntries(res.headers.entries());

    const techs: string[] = [];
    // Server
    if (headers.server) techs.push(`Server: ${headers.server}`);
    if (headers["x-powered-by"]) techs.push(`Powered By: ${headers["x-powered-by"]}`);
    // Frameworks
    if (html.includes("__next") || html.includes("_next/static")) techs.push("Next.js");
    if (html.includes("__nuxt") || html.includes("/_nuxt/")) techs.push("Nuxt.js");
    if (html.includes("__svelte") || headers["x-sveltekit-page"]) techs.push("SvelteKit");
    if (html.includes("ng-version") || html.includes("ng-app")) techs.push("Angular");
    if (html.includes("data-reactroot") || html.includes("__REACT")) techs.push("React");
    if (html.includes("Vue.js") || html.includes("data-v-")) techs.push("Vue.js");
    if (html.includes("wp-content") || html.includes("wordpress")) techs.push("WordPress");
    if (html.includes("Shopify")) techs.push("Shopify");
    if (html.includes("cloudflare") || headers.server?.includes("cloudflare")) techs.push("Cloudflare");
    if (headers["x-vercel-id"]) techs.push("Vercel");
    if (headers["x-amz-cf-id"] || headers.via?.includes("CloudFront")) techs.push("AWS CloudFront");
    if (headers["x-github-request-id"]) techs.push("GitHub Pages");
    // Analytics
    if (html.includes("google-analytics") || html.includes("gtag")) techs.push("Google Analytics");
    if (html.includes("segment.com") || html.includes("analytics.js")) techs.push("Segment");
    // CDN
    if (html.includes("cdn.jsdelivr") || html.includes("cdnjs.cloudflare")) techs.push("CDN (jsDelivr/cdnjs)");
    if (html.includes("fonts.googleapis")) techs.push("Google Fonts");

    if (techs.length === 0) techs.push("No technologies detected");
    for (const t of techs) lines.push(`  ${CYAN}▸${RST} ${t}`);
  } catch (e: any) { lines.push(fail(e.message)); }
  return lines.join("\n");
}

// ── Crawl (robots.txt, sitemap, common paths) ──────────────────────────────

async function crawlPaths(baseUrl: string): Promise<string> {
  const lines: string[] = [section("Path Discovery")];
  const commonPaths = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/humans.txt",
    "/.env", "/.git/config", "/wp-admin/", "/admin/", "/api/", "/graphql",
    "/swagger.json", "/openapi.json", "/api-docs", "/.DS_Store",
    "/server-status", "/debug", "/info", "/health", "/metrics",
  ];

  const found: { path: string; status: number; size: number }[] = [];
  const checks = commonPaths.map(async path => {
    try {
      const res = await fetch(baseUrl + path, { method: "HEAD", redirect: "manual" });
      if (res.status < 404) found.push({ path, status: res.status, size: parseInt(res.headers.get("content-length") || "0") });
    } catch {}
  });
  await Promise.all(checks);

  found.sort((a, b) => a.status - b.status);
  for (const f of found) {
    const sc = f.status < 300 ? GREEN : f.status < 400 ? YELLOW : RED;
    const sensitive = [".env", ".git", ".DS_Store", "server-status", "debug"].some(s => f.path.includes(s));
    const icon = sensitive ? `${RED}🔴` : `${sc}●`;
    lines.push(`  ${icon}${RST} ${sc}${f.status}${RST} ${f.path}${sensitive ? ` ${RED}${B}SENSITIVE!${RST}` : ""}`);
  }
  if (found.length === 0) lines.push(D + "  No interesting paths found" + RST);
  
  // Check robots.txt content
  try {
    const robots = await fetch(baseUrl + "/robots.txt");
    if (robots.ok) {
      const text = await robots.text();
      const disallowed = text.split("\n").filter(l => l.toLowerCase().startsWith("disallow:")).map(l => l.split(":").slice(1).join(":").trim()).filter(Boolean);
      if (disallowed.length > 0) {
        lines.push(`\n  ${B}Disallowed paths (from robots.txt):${RST}`);
        for (const d of disallowed.slice(0, 10)) lines.push(`    ${D}${d}${RST}`);
      }
    }
  } catch {}
  return lines.join("\n");
}

// ── Full Recon ──────────────────────────────────────────────────────────────

async function fullRecon(target: string): Promise<string> {
  const host = target.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  const url = target.startsWith("http") ? target : `https://${target}`;

  const [headers, ssl, dns, tech, paths] = await Promise.all([
    checkHeaders(url),
    checkSSL(host),
    Promise.resolve(checkDNS(host)),
    detectTech(url),
    crawlPaths(url),
  ]);

  return `${B}${CYAN}🔍 RECON: ${host}${RST}\n${headers}\n${ssl}\n${dns}\n${tech}\n${paths}`;
}

export default function piRecon(pi: ExtensionAPI) {
  pi.registerCommand("recon", {
    description: "Security reconnaissance. /recon target.com | /recon headers|ssl|dns|ports|tech|crawl target",
    execute: async (ctx, args) => {
      const parts = args.trim().split(/\s+/);
      if (parts.length === 0 || !parts[0]) {
        ctx.ui.notify("Usage: /recon target.com | /recon [headers|ssl|dns|ports|tech|crawl] target", "info");
        return;
      }

      let sub = "", target = "";
      if (parts.length === 1) { target = parts[0]; sub = "full"; }
      else { sub = parts[0].toLowerCase(); target = parts[1]; }

      const host = target.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      const url = target.startsWith("http") ? target : `https://${target}`;

      ctx.ui.notify(`${D}Scanning ${host}...${RST}`, "info");

      let result = "";
      switch (sub) {
        case "headers": case "h": result = await checkHeaders(url); break;
        case "ssl": case "tls": result = await checkSSL(host); break;
        case "dns": result = checkDNS(host); break;
        case "ports": case "port": case "scan": result = await scanPorts(host); break;
        case "tech": case "stack": result = await detectTech(url); break;
        case "crawl": case "paths": case "discover": result = await crawlPaths(url); break;
        default: result = await fullRecon(target); break;
      }

      ctx.ui.notify(result, "info");
    },
  });

  // LLM tool
  pi.registerTool("security_recon", {
    description: "Run security reconnaissance on a target domain. Returns headers, SSL, DNS, tech stack, and path discovery.",
    parameters: Type.Object({
      target: Type.String({ description: "Target domain (e.g. example.com)" }),
      checks: Type.Optional(Type.Array(Type.String({ description: "Specific checks: headers, ssl, dns, ports, tech, crawl. Omit for all." }))),
    }),
    execute: async (params) => {
      const host = params.target.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      const url = `https://${host}`;
      const checks = params.checks || ["headers", "ssl", "dns", "tech", "crawl"];
      const results: Record<string, string> = {};
      if (checks.includes("headers")) results.headers = await checkHeaders(url);
      if (checks.includes("ssl")) results.ssl = await checkSSL(host);
      if (checks.includes("dns")) results.dns = checkDNS(host);
      if (checks.includes("ports")) results.ports = await scanPorts(host);
      if (checks.includes("tech")) results.tech = await detectTech(url);
      if (checks.includes("crawl")) results.crawl = await crawlPaths(url);
      return results;
    },
  });
}
