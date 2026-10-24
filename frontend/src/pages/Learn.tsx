import { useState } from "react";
import { ApiRequestError, scanUrl } from "../api";
import type { ScanResponse } from "../types";
import { EXAMPLES } from "./Home";

type Part = "protocol" | "userinfo" | "subdomain" | "domain" | "path" | "dot";

const PART_INFO: Record<Part, { label: string; text: string }> = {
  protocol: { label: "Protocol", text: "How the browser connects. https means the connection is encrypted; it says nothing about who runs the site." },
  userinfo: { label: "Username (ignored)", text: "Anything before '@' is a username, not the destination. Attackers put a trusted-looking name here." },
  subdomain: { label: "Subdomain", text: "Whoever owns a domain can create any subdomain they like, including ones that contain a brand name. Subdomains do not show who owns the site." },
  domain: { label: "Registered domain", text: "This is the part that identifies who controls the site. Read the address from here, not from the left." },
  path: { label: "Path", text: "Which page on the site. Attackers often make this look official (/login, /verify), but it is just text they control." },
  dot: { label: "Separator", text: "Dots separate sections of the hostname." },
};

interface Example { title: string; segments: { text: string; part: Part }[]; note: string }

// Synthetic, on reserved domains (.example / .test / .net via example.*): safe to inspect, not real sites.
const ANATOMY: Example[] = [
  { title: "Ordinary address", note: "The registered domain is example.com; 'www' is just a subdomain of it.",
    segments: [{ text: "https://", part: "protocol" }, { text: "www", part: "subdomain" }, { text: ".", part: "dot" }, { text: "example.com", part: "domain" }, { text: "/account", part: "path" }] },
  { title: "Subdomain deception", note: "Looks like paypal.com, but the registered domain is example.net. Everything to its left is just subdomains.",
    segments: [{ text: "https://", part: "protocol" }, { text: "paypal.com.account-verify", part: "subdomain" }, { text: ".", part: "dot" }, { text: "example.net", part: "domain" }, { text: "/login", part: "path" }] },
  { title: "The '@' trick", note: "The browser ignores 'paypal.com@' as a username and connects to evil.example.",
    segments: [{ text: "https://", part: "protocol" }, { text: "paypal.com@", part: "userinfo" }, { text: "evil.example", part: "domain" }, { text: "/", part: "path" }] },
  { title: "Lookalike characters", note: "'paypa1' uses the digit 1 in place of the letter l. Lookalike domains swap characters that are easy to misread.",
    segments: [{ text: "https://", part: "protocol" }, { text: "paypa1-login.example", part: "domain" }, { text: "/verify", part: "path" }] },
];

const LESSONS: { title: string; body: string }[] = [
  { title: "Phishing vs. legitimate URLs", body: "Look at the registered domain, the part just before the final suffix (like .com or .co.in). That decides who controls the site. A page can look perfect and still sit on a domain that belongs to someone else." },
  { title: "Domain spoofing and lookalikes", body: "Attackers register names that resemble a brand: swapped characters (paypa1), merged letters (rn for m), extra words (paypal-secure-login) or a brand name as a subdomain. PhishGuard flags these patterns against a small built-in brand list; it cannot know every brand." },
  { title: "Subdomain deception", body: "Domains read right to left. In paypal.com.account-verify.example.net the owner is example.net, not paypal.com. Anyone can create subdomains under a domain they own." },
  { title: "Punycode and internationalized domains", body: "Domain names can contain non-Latin letters, stored as punycode starting with 'xn--'. Many are legitimate, but some letters from other alphabets look identical to Latin ones, so a domain can imitate another. PhishGuard shows both forms." },
  { title: "URL shorteners", body: "Shortened links hide the real destination. They are widely used legitimately, so PhishGuard treats them as a weak signal and never follows redirects. Ask for the full address when you can." },
  { title: "What HTTPS does and doesn't prove", body: "HTTPS encrypts traffic between you and the site. Certificates are issued to whoever controls a domain name, including look-alike domains, and are easy to get. A padlock does not mean the site is trustworthy." },
  { title: "Why a valid TLS certificate isn't a trust badge", body: "A certificate authority checks that the requester controls the domain, not that their intentions are honest. That is why PhishGuard reports HTTPS as an observation, never as a reason to lower a risk score." },
];

type Compare = { phase: "idle" } | { phase: "loading" } | { phase: "error"; message: string } | { phase: "done"; a: ScanResponse; b: ScanResponse };

export default function Learn() {
  const [idx, setIdx] = useState(0);
  const [part, setPart] = useState<Part | null>(null);
  const [cmp, setCmp] = useState<Compare>({ phase: "idle" });
  const ex = ANATOMY[idx];

  async function runCompare() {
    setCmp({ phase: "loading" });
    try {
      const [a, b] = await Promise.all([scanUrl(EXAMPLES[0].url), scanUrl(EXAMPLES[1].url)]);
      setCmp({ phase: "done", a, b });
    } catch (e) {
      setCmp({ phase: "error", message: e instanceof ApiRequestError ? e.message : "Unexpected error." });
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Learning center</h1>

      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">URL anatomy (synthetic examples)</h2>
        <div className="mb-4 flex flex-wrap gap-2">
          {ANATOMY.map((a, i) => (
            <button key={a.title} type="button" aria-pressed={i === idx} onClick={() => { setIdx(i); setPart(null); }}
              className={`rounded-full border px-3 py-1 text-xs ${i === idx ? "border-cyan-500 text-cyan-300" : "border-slate-700 text-slate-300"}`}>{a.title}</button>
          ))}
        </div>
        <div className="overflow-x-auto">
          <div className="flex min-w-max items-start font-mono text-sm">
            {ex.segments.map((s, i) => (
              <button key={i} type="button" onClick={() => setPart(s.part)} aria-label={`${PART_INFO[s.part].label}: ${s.text}`}
                className={`flex flex-col items-center border-b-2 px-0.5 ${part === s.part ? "border-cyan-400 text-cyan-300" : "border-slate-600"}`}>
                <span>{s.text}</span>
                <span className="font-sans text-[10px] text-slate-400">{s.part === "dot" ? "" : PART_INFO[s.part].label}</span>
              </button>
            ))}
          </div>
        </div>
        <p className="mt-3 text-sm text-slate-300">{ex.note}</p>
        <p className="mt-2 min-h-[2.5rem] text-sm text-slate-400" aria-live="polite">
          {part ? `${PART_INFO[part].label}: ${PART_INFO[part].text}` : "Select a part of the address to learn what it means."}
        </p>
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">Side-by-side comparison</h2>
        <p className="mb-3 text-sm text-slate-400">Scan one plain and one look-alike synthetic URL with the real backend. These examples demonstrate how the rules work; they are not evidence of real-world detection accuracy.</p>
        <button type="button" onClick={() => void runCompare()} disabled={cmp.phase === "loading"}
          className="rounded-lg bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-60">
          {cmp.phase === "loading" ? "Scanning…" : "Run comparison"}
        </button>
        {cmp.phase === "error" && <p role="alert" className="mt-3 text-red-200">{cmp.message}</p>}
        {cmp.phase === "done" && (
          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            {[cmp.a, cmp.b].map((r, i) => (
              <div key={r.scan_id} className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                <div className="break-all font-mono text-xs text-slate-400">{EXAMPLES[i].url}</div>
                <div className="mt-2 text-3xl font-bold">{r.risk_score}<span className="text-base text-slate-500">/100</span></div>
                <div className="font-semibold">{r.risk_category}</div>
                <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-300">
                  {r.findings.length ? r.findings.slice(0, 4).map((f) => <li key={f.rule_id}>{f.title}</li>) : <li>No warning indicators triggered</li>}
                </ul>
              </div>
            ))}
          </div>
        )}
      </section>

      <section aria-label="Lessons" className="space-y-3">
        {LESSONS.map((l) => (
          <article key={l.title} className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <h2 className="font-semibold">{l.title}</h2>
            <p className="mt-1 text-sm text-slate-400">{l.body}</p>
          </article>
        ))}
      </section>
    </div>
  );
}
