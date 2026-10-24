import { Search } from "lucide-react";
import { useState } from "react";
import { ApiRequestError, scanUrl } from "../api";
import ExportButtons from "../components/ExportButtons";
import ResultView from "../components/ResultView";
import { addToHistory, setLastResult } from "../store";
import type { ScanResponse } from "../types";

type State =
  | { phase: "idle" }
  | { phase: "loading" }
  | { phase: "error"; message: string }
  | { phase: "done"; result: ScanResponse };

// Synthetic examples on reserved documentation domains (RFC 2606): they cannot resolve to real sites.
export const EXAMPLES = [
  { label: "Plain synthetic URL", url: "https://www.example.com/docs/getting-started" },
  { label: "Look-alike synthetic URL", url: "http://paypal.com.account-verify.example.net/login?session=demo" },
];

export default function Home() {
  const [input, setInput] = useState("");
  const [state, setState] = useState<State>({ phase: "idle" });

  async function run(url: string) {
    if (!url.trim()) {
      setState({ phase: "error", message: "Please paste a URL to analyze." });
      return;
    }
    setState({ phase: "loading" });
    try {
      const result = await scanUrl(url);
      setLastResult(result);
      addToHistory(result);
      setState({ phase: "done", result });
    } catch (e) {
      setState({ phase: "error", message: e instanceof ApiRequestError ? e.message : "Unexpected error." });
    }
  }

  return (
    <div>
      <div className="mb-8 mt-2 text-center">
        <h1 className="sr-only">PhishGuard – Pause. Inspect. Stay protected.</h1>
        <img src="/logo.jpg" alt="PhishGuard logo: a shield with a fishing hook and the tagline Pause. Inspect. Stay protected."
          width={1200} height={800} className="mx-auto w-full max-w-md rounded-2xl" />
      </div>

      <form onSubmit={(e) => { e.preventDefault(); void run(input); }} className="space-y-3">
        <label htmlFor="url" className="block text-sm font-medium text-slate-300">Paste a suspicious link</label>
        <div className="flex flex-col gap-2 sm:flex-row">
          <input
            id="url" value={input} onChange={(e) => setInput(e.target.value)}
            placeholder="https://example.com/..." autoComplete="off" spellCheck={false}
            className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 font-mono text-sm outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/30"
          />
          <button
            type="submit" disabled={state.phase === "loading"}
            className="flex items-center justify-center gap-2 rounded-lg bg-cyan-500 px-5 py-3 font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-60"
          >
            {state.phase === "loading"
              ? <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950 border-t-transparent" aria-hidden />
              : <Search className="h-4 w-4" aria-hidden />}
            {state.phase === "loading" ? "Analyzing…" : "Analyze URL"}
          </button>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
          Try a synthetic example:
          {EXAMPLES.map((ex) => (
            <button key={ex.url} type="button" onClick={() => { setInput(ex.url); void run(ex.url); }}
              className="rounded-full border border-slate-700 px-3 py-1 hover:border-cyan-500 hover:text-cyan-300">
              {ex.label}
            </button>
          ))}
        </div>
      </form>

      <p className="mt-6 rounded-lg border border-slate-800 bg-slate-900/40 p-3 text-xs text-slate-400">
        <strong className="text-slate-300">Privacy:</strong> PhishGuard analyzes the text of the link and never opens it.
        The link is sent to the PhishGuard server; if the operator enabled a reputation provider (see Settings &amp; privacy),
        the link is also sent to that provider. Sensitive values are hidden in what is displayed and saved, and the server does not log submitted URLs.
        Never enter passwords, one-time codes or payment details into a page reached from a suspicious link.
      </p>

      <main className="mt-8">
        {state.phase === "idle" && (
          <ol className="list-decimal space-y-1 pl-5 text-sm text-slate-400">
            <li>The link is split into protocol, hostname, path and parameters.</li>
            <li>Documented rules look for known deception tricks and assign weighted points.</li>
            <li>You see exactly which signals fired, why they matter, and what was not checked.</li>
          </ol>
        )}
        {state.phase === "loading" && <p role="status" className="text-slate-400">Analyzing… (the first request can take a few seconds if the server was asleep)</p>}
        {state.phase === "error" && <p role="alert" className="rounded-lg border border-red-500/40 bg-red-950/40 p-4 text-red-200">{state.message}</p>}
        {state.phase === "done" && <ResultView r={state.result} actions={<ExportButtons r={state.result} />} />}
      </main>
    </div>
  );
}
