# 3-minute demo script

1. **Hook (20s)** – "Phishing links look convincing. PhishGuard doesn't just show a red warning; it explains *why*."
2. **Plain URL (30s)** – Click "Plain synthetic URL". Score 0. Point out the observation "Uses HTTPS" and the note that HTTPS doesn't prove trust, and the "Not checked" items.
3. **Look-alike URL (60s)** – Click "Look-alike synthetic URL". Walk through: brand name inside an unrelated domain, evidence text, why it matters, recommended action. Show that the `session=demo` value is redacted.
4. **Transparency (30s)** – Open "Reputation providers": "Not checked" vs "No match" vs "Match". Show the score breakdown (duplicate indicators not double-counted).
5. **Learn (30s)** – Learn → URL anatomy → "Subdomain deception", then "Run comparison".
6. **Privacy (20s)** – Settings & privacy: retention options, clear history, export JSON/Markdown from a report.
7. **Honesty close (10s)** – "Synthetic examples show how rules work, not real-world accuracy. We measured X on a small labeled set (see eval/)."
