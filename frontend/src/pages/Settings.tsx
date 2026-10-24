import { useEffect, useState } from "react";
import { ApiRequestError, fetchProviders } from "../api";
import { clearHistory, loadHistory, loadSettings, RETENTION_LABELS, saveSettings } from "../store";
import type { Retention } from "../store";
import type { ProviderInfo } from "../types";

export default function Settings() {
  const [retention, setRetention] = useState<Retention>(loadSettings().retention);
  const [count, setCount] = useState(loadHistory().length);
  const [cleared, setCleared] = useState(false);
  const [providers, setProviders] = useState<ProviderInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchProviders().then(setProviders).catch((e) => setError(e instanceof ApiRequestError ? e.message : "Could not load providers."));
  }, []);

  function change(r: Retention) {
    setRetention(r);
    saveSettings({ retention: r });
    if (r === "off") { clearHistory(); setCount(0); }
    else setCount(loadHistory().length);
  }

  return (
    <div className="space-y-5">
      <h1 className="text-2xl font-bold">Settings &amp; privacy</h1>

      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">History retention</h2>
        <fieldset className="space-y-2">
          <legend className="sr-only">History retention</legend>
          {(Object.keys(RETENTION_LABELS) as Retention[]).map((r) => (
            <label key={r} className="flex items-center gap-2 text-sm">
              <input type="radio" name="retention" checked={retention === r} onChange={() => change(r)} />
              {RETENTION_LABELS[r]}
            </label>
          ))}
        </fieldset>
        <p className="mt-3 text-sm text-slate-400">{count} scan(s) saved in this browser.</p>
        <button type="button" onClick={() => { clearHistory(); setCount(0); setCleared(true); }}
          className="mt-3 rounded-lg border border-red-500/50 px-3 py-2 text-sm text-red-200 hover:bg-red-950/40">Clear history now</button>
        {cleared && <p role="status" className="mt-2 text-sm text-cyan-300">History cleared.</p>}
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Reputation providers</h2>
        {error && <p role="alert" className="text-red-200">{error}</p>}
        {!error && !providers && <p role="status" className="text-slate-400">Loading…</p>}
        {providers && (
          <ul className="space-y-2 text-sm">
            {providers.map((p) => (
              <li key={p.name}>
                <span className="font-semibold">{p.name}</span>{" "}
                <span className="rounded bg-slate-800 px-2 py-0.5 text-xs">{p.configured ? "Enabled by the server operator" : "Not configured – never queried"}</span>
              </li>
            ))}
          </ul>
        )}
        <p className="mt-3 text-xs text-slate-500">API keys exist only on the server. When a provider is enabled, the submitted link (without credentials or #fragment, but including the query string) is sent to that provider for lookup.</p>
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 text-sm text-slate-300">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Privacy notice</h2>
        <ul className="list-disc space-y-1 pl-5">
          <li>PhishGuard never opens, loads or embeds the links you submit; it analyzes their text.</li>
          <li>Your history is stored only in this browser (localStorage), using a redacted form: no passwords, sensitive query values and fragments hidden. It is not uploaded anywhere.</li>
          <li>The server does not store scans and does not log submitted URLs. Hosting platforms may keep their own standard request logs.</li>
          <li>Query strings can contain personal data or session tokens. Avoid submitting links that contain them if you can remove those parts first.</li>
        </ul>
      </section>
    </div>
  );
}
