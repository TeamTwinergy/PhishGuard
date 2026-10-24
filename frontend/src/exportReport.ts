import type { ScanResponse } from "./types";

export function toMarkdown(r: ScanResponse): string {
  const u = r.url_breakdown;
  const lines: string[] = [
    `# PhishGuard report: ${r.hostname}`,
    "",
    `- Scanned: ${new Date(r.scanned_at).toLocaleString()}`,
    `- Risk score: ${r.risk_score}/100 (${r.risk_category})`,
    `- Scan ID: ${r.scan_id}`,
    "",
    "> The score is an ordinal warning level, not the probability that the URL is malicious.",
    "> 'No threats detected' never means 'guaranteed safe'.",
    "",
    "## Summary",
    r.explanation.summary,
    "",
    `## Warning indicators (${r.findings.length})`,
  ];
  if (r.findings.length === 0) lines.push("None triggered.");
  r.findings.forEach((f) => {
    lines.push(`### ${f.title} (${f.severity}, +${f.weight})`, `- Finding: ${f.evidence}`,
      `- Why it matters: ${f.why_it_matters}`, `- Recommended action: ${f.recommended_action}`, "");
  });
  lines.push("## Positive observations");
  r.positive_observations.forEach((o) => lines.push(`- ${o.title}: ${o.detail}`));
  lines.push("", "## Reputation providers");
  r.reputation.forEach((p) => lines.push(`- ${p.provider}: ${p.status}${p.detail ? ` – ${p.detail}` : ""}`));
  lines.push("", "## Unavailable or inconclusive checks");
  r.skipped_checks.forEach((s) => lines.push(`- ${s.check} (${s.status}): ${s.reason}`));
  lines.push("", "## Recommended next steps");
  r.recommended_next_steps.forEach((s) => lines.push(`- ${s}`));
  lines.push("", "## URL structure (redacted)",
    `- Display form: \`${u.redacted_url}\``, `- Hostname: ${u.hostname}`,
    `- Registered domain (${u.domain_parsing}): ${u.registered_domain ?? "n/a"}`,
    `- Subdomains: ${u.subdomains.join(".") || "none"}`, `- Port: ${u.port ?? "default"}`, "",
    "## Limitations", ...r.explanation.limitations.map((l) => `- ${l}`), "", `_${r.score_method}_`, "");
  return lines.join("\n");
}

export function download(filename: string, text: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

const stem = (r: ScanResponse) => `phishguard-${r.hostname.replace(/[^a-z0-9.-]/gi, "_")}-${r.scan_id.slice(0, 8)}`;
export const downloadJson = (r: ScanResponse) => download(`${stem(r)}.json`, JSON.stringify(r, null, 2), "application/json");
export const downloadMarkdown = (r: ScanResponse) => download(`${stem(r)}.md`, toMarkdown(r), "text/markdown");
