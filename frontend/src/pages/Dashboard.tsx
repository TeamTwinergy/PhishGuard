import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { clearHistory, loadHistory, loadSettings } from "../store";

const CATEGORIES = ["Lower observed risk", "Caution", "High concern", "Very high concern"];
const BAR: Record<string, string> = {
  "Lower observed risk": "bg-cyan-400", "Caution": "bg-amber-400",
  "High concern": "bg-red-400", "Very high concern": "bg-red-500",
};
const STATUS: Record<string, string> = {
  not_checked: "not checked", match: "match", no_match: "no match",
  error: "error", timeout: "timed out", rate_limited: "rate limited",
};

export default function Dashboard() {
  const [history, setHistory] = useState(loadHistory);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("all");
  const retention = loadSettings().retention;

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return history.filter((r) =>
      (category === "all" || r.risk_category === category) &&
      (!q || r.hostname.toLowerCase().includes(q) || r.explanation.summary.toLowerCase().includes(q) ||
        r.findings.some((f) => f.title.toLowerCase().includes(q))));
  }, [history, query, category]);

  const counts = CATEGORIES.map((c) => history.filter((r) => r.risk_category === c).length);
  const max = Math.max(1, ...counts);

  function onClear() {
    if (window.confirm("Delete all saved scan history from this browser?")) {
      clearHistory();
      setHistory([]);
    }
  }

  if (retention === "off") {
    return (
      <div className="py-6 text-slate-300">
        <h1 className="mb-2 text-2xl font-bold">Dashboard</h1>
        <p>History saving is turned off. You can change this in <Link to="/settings" className="text-cyan-300 underline">Settings &amp; privacy</Link>.</p>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <h1 className="text-2xl font-bold">Dashboard</h1>
      {history.length === 0 ? (
        <p className="rounded-lg border border-slate-800 bg-slate-900/40 p-6 text-slate-300">
          No scans saved yet. <Link to="/" className="text-cyan-300 underline">Analyze a URL</Link> and it will appear here.
        </p>
      ) : (
        <>
          <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5" aria-label="Risk distribution">
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Risk distribution ({history.length} scans)</h2>
            <ul className="space-y-2 text-sm">
              {CATEGORIES.map((c, i) => (
                <li key={c} className="flex items-center gap-3">
                  <span className="w-40 shrink-0 text-slate-300">{c}</span>
                  <div className="h-3 flex-1 overflow-hidden rounded bg-slate-800">
                    <div className={`h-full ${BAR[c]}`} style={{ width: `${(counts[i] / max) * 100}%` }} />
                  </div>
                  <span className="w-6 text-right font-mono">{counts[i]}</span>
                </li>
              ))}
            </ul>
          </section>

          <div className="flex flex-col gap-2 sm:flex-row">
            <input aria-label="Search history" value={query} onChange={(e) => setQuery(e.target.value)}
              placeholder="Search hostname or finding…"
              className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm outline-none focus:border-cyan-500" />
            <select aria-label="Filter by category" value={category} onChange={(e) => setCategory(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm">
              <option value="all">All categories</option>
              {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
            <button type="button" onClick={onClear}
              className="rounded-lg border border-red-500/50 px-3 py-2 text-sm text-red-200 hover:bg-red-950/40">Clear history</button>
          </div>

          {shown.length === 0 ? (
            <p className="text-slate-400">No scans match your search or filter.</p>
          ) : (
            <ul className="space-y-3">
              {shown.map((r) => (
                <li key={r.scan_id} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <span className="break-all font-mono text-sm font-semibold">{r.hostname}</span>
                    <span className="text-xs text-slate-400">{new Date(r.scanned_at).toLocaleString()}</span>
                  </div>
                  <div className="mt-1 text-sm"><span className="font-bold">{r.risk_score}/100</span> · {r.risk_category}</div>
                  <p className="mt-1 text-sm text-slate-400">
                    {r.findings.length === 0 ? "No warning indicators triggered." : r.findings.slice(0, 3).map((f) => f.title).join(" · ")}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    Providers: {r.reputation.map((p) => `${p.provider} – ${STATUS[p.status] ?? p.status}`).join("; ")}
                  </p>
                  <Link to={`/report/${r.scan_id}`} className="mt-2 inline-block text-sm text-cyan-300 underline">Open detailed report</Link>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}
