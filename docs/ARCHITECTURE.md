# Architecture

```
Browser (React/Vite on Vercel)                FastAPI (Render)
  Scan / Dashboard / Learn / Settings  ──►  POST /api/scan
  history in localStorage (redacted)         ├ url_parser        normalize, redact, no network
                                             ├ feature_extractor structural features, brand look-alikes
                                             ├ rules_engine      findings: evidence / why / action
                                             ├ reputation/       Safe Browsing adapter (server-side key)
                                             ├ risk_scorer       best finding per group, cap 100
                                             └ explanation       deterministic text (no AI key needed)
```

Key decisions
- Static analysis only: submitted URLs are never fetched (no SSRF surface). Reputation lookups send the URL to the provider.
- Score = sum of the highest-weight finding per indicator group, capped at 100. Weights/thresholds in `backend/app/config.py`.
- Providers report match / no_match / not_checked / error / timeout / rate_limited; only `match` changes the score.
- History is browser-local and redacted; the server stores nothing.
- Add a provider: subclass `ReputationProvider` and register it in `reputation/registry.py`.
- Not implemented: optional AI explanations, browser extension, server-side history endpoints (`/api/history`), accounts.
