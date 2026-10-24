import { Info, Shield, ShieldAlert, ShieldX } from "lucide-react";
import type { ReactNode } from "react";
import type { ScanResponse } from "../types";

const CATEGORY_STYLE: Record<string, { text: string; border: string; bar: string; icon: ReactNode }> = {
  "Lower observed risk": { text: "text-cyan-300", border: "border-cyan-500/40", bar: "bg-cyan-400", icon: <Info className="h-5 w-5" aria-hidden /> },
  "Caution": { text: "text-amber-300", border: "border-amber-500/40", bar: "bg-amber-400", icon: <Shield className="h-5 w-5" aria-hidden /> },
  "High concern": { text: "text-red-300", border: "border-red-500/40", bar: "bg-red-400", icon: <ShieldAlert className="h-5 w-5" aria-hidden /> },
  "Very high concern": { text: "text-red-200", border: "border-red-400/60", bar: "bg-red-500", icon: <ShieldX className="h-5 w-5" aria-hidden /> },
};

const SEVERITY_LABEL = { low: "Low", medium: "Medium", high: "High" } as const;
const STATUS_LABEL: Record<string, string> = {
  not_checked: "Not checked", match: "Match found", no_match: "No match",
  error: "Error", timeout: "Timed out", rate_limited: "Rate limited",
  unavailable: "Unavailable", inconclusive: "Inconclusive",
};

function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">{title}</h3>
      {children}
    </section>
  );
}

function Row({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5 border-b border-slate-800 py-2 last:border-0 sm:flex-row sm:gap-4">
      <dt className="w-40 shrink-0 text-slate-400">{k}</dt>
      <dd className="min-w-0 break-all font-mono text-sm text-slate-200">{v}</dd>
    </div>
  );
}

export default function ResultView({ r, actions }: { r: ScanResponse; actions?: ReactNode }) {
  const style = CATEGORY_STYLE[r.risk_category] ?? CATEGORY_STYLE["Caution"];
  const u = r.url_breakdown;
  return (
    <div className="space-y-4" aria-live="polite">
      <div className={`rounded-xl border ${style.border} bg-slate-900/60 p-6`}>
        <div className="flex flex-wrap items-end gap-x-6 gap-y-2">
          <div>
            <div className="text-xs uppercase tracking-wide text-slate-400">Risk score</div>
            <div className={`text-6xl font-bold ${style.text}`}>{r.risk_score}<span className="text-2xl text-slate-500">/100</span></div>
          </div>
          <div className={`flex items-center gap-2 pb-2 text-lg font-semibold ${style.text}`}>{style.icon}{r.risk_category}</div>
          {actions && <div className="ml-auto flex gap-2 pb-2">{actions}</div>}
        </div>
        <div className="mt-4 h-2 w-full overflow-hidden rounded bg-slate-800" role="img" aria-label={`Risk score ${r.risk_score} out of 100`}>
          <div className={`h-full ${style.bar}`} style={{ width: `${r.risk_score}%` }} />
        </div>
        <p className="mt-4 text-slate-300">{r.explanation.summary}</p>
        <p className="mt-2 text-xs text-slate-500">
          This is an ordinal warning level, not the probability that the URL is malicious. Bands: 0–{r.thresholds[0] - 1} lower, {r.thresholds[0]}–{r.thresholds[1] - 1} caution, {r.thresholds[1]}–{r.thresholds[2] - 1} high, {r.thresholds[2]}+ very high.
        </p>
      </div>

      <Card title={`Warning indicators (${r.findings.length})`}>
        {r.findings.length === 0 ? (
          <p className="text-slate-300">No warning indicators were triggered by PhishGuard's URL rules. That does not guarantee the site is safe.</p>
        ) : (
          <ul className="space-y-4">
            {r.findings.map((f, i) => {
              const counted = r.score_breakdown[i]?.counted;
              return (
                <li key={f.rule_id + i} className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-semibold">{SEVERITY_LABEL[f.severity]} · +{f.weight}</span>
                    {!counted && <span className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-400">Not counted (duplicate group)</span>}
                    <span className="font-semibold">{f.title}</span>
                  </div>
                  <dl className="mt-2 space-y-1 text-sm">
                    <div><dt className="inline font-semibold text-slate-300">Finding: </dt><dd className="inline text-slate-300">{f.evidence}</dd></div>
                    <div><dt className="inline font-semibold text-slate-300">Why it matters: </dt><dd className="inline text-slate-400">{f.why_it_matters}</dd></div>
                    <div><dt className="inline font-semibold text-slate-300">Recommended action: </dt><dd className="inline text-slate-400">{f.recommended_action}</dd></div>
                  </dl>
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      <Card title="Positive observations">
        <ul className="space-y-2 text-sm">
          {r.positive_observations.map((o) => (
            <li key={o.id}><span className="font-semibold text-slate-200">{o.title}.</span> <span className="text-slate-400">{o.detail}</span></li>
          ))}
        </ul>
      </Card>

      <Card title="Reputation providers (kept separate from heuristics)">
        <ul className="space-y-2 text-sm">
          {r.reputation.map((p) => (
            <li key={p.provider} className="flex flex-wrap items-center gap-2">
              <span className="font-semibold">{p.provider}</span>
              <span className="rounded bg-slate-800 px-2 py-0.5 text-xs">{STATUS_LABEL[p.status] ?? p.status}</span>
              <span className="text-slate-400">{p.detail}{p.threat_types?.length ? ` Threat type: ${p.threat_types.join(", ")}.` : ""}</span>
            </li>
          ))}
        </ul>
        <p className="mt-3 text-xs text-slate-500">"Not checked" means no request was made. It is different from "No match".</p>
      </Card>

      <Card title="Unavailable or inconclusive checks">
        <ul className="space-y-2 text-sm">
          {r.skipped_checks.map((s) => (
            <li key={s.check}><span className="font-semibold">{s.check}</span> <span className="rounded bg-slate-800 px-2 py-0.5 text-xs">{STATUS_LABEL[s.status] ?? s.status}</span><div className="text-slate-400">{s.reason}</div></li>
          ))}
        </ul>
      </Card>

      <Card title="Recommended next steps">
        <ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">
          {r.recommended_next_steps.map((s) => <li key={s}>{s}</li>)}
        </ul>
      </Card>

      <Card title="URL structure (never opened or loaded)">
        <dl>
          <Row k="Safe display form" v={u.redacted_url} />
          <Row k="Protocol" v={u.scheme + (u.scheme_assumed ? " (assumed)" : "")} />
          <Row k="Normalized hostname" v={u.hostname} />
          {u.hostname_unicode !== u.hostname && <Row k="Unicode form" v={u.hostname_unicode} />}
          <Row k="Registered domain" v={u.registered_domain ? `${u.registered_domain} (${u.domain_parsing} guess)` : "n/a (IP address)"} />
          <Row k="Subdomains" v={u.subdomains.length ? u.subdomains.join(" . ") : "none"} />
          <Row k="Port" v={u.port ?? "default"} />
          <Row k="Path" v={u.path || "/"} />
          <Row k="Query parameters" v={u.query_params.length ? u.query_params.map((q) => `${q.name}=${q.value}`).join("  ") : "none"} />
          <Row k="Fragment" v={u.fragment ?? "none"} />
        </dl>
        {u.normalization_notes.map((n) => <p key={n} className="mt-2 text-xs text-amber-300">Note: {n}</p>)}
      </Card>

      <Card title="Limitations of this scan">
        <ul className="list-disc space-y-1 pl-5 text-sm text-slate-400">
          {r.explanation.limitations.map((l) => <li key={l}>{l}</li>)}
        </ul>
        <p className="mt-3 text-xs text-slate-500">{r.score_method}</p>
      </Card>
    </div>
  );
}
