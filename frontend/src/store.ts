import type { ScanResponse } from "./types";

// History lives only in this browser. It stores the server's REDACTED view of each scan
// (no credentials, sensitive query values hidden), never the raw URL typed by the user.
const HISTORY_KEY = "phishguard.history.v1";
const SETTINGS_KEY = "phishguard.settings.v1";
const DAY = 86_400_000;
const MAX_ITEMS = 200;

export type Retention = "off" | "7d" | "30d" | "forever";
export interface Settings { retention: Retention }

export const RETENTION_LABELS: Record<Retention, string> = {
  off: "Don't save history",
  "7d": "Keep for 7 days",
  "30d": "Keep for 30 days",
  forever: "Keep until I clear it",
};

let lastResult: ScanResponse | null = null;
export const setLastResult = (r: ScanResponse) => { lastResult = r; };

export function loadSettings(): Settings {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<Settings>;
      if (parsed.retention && parsed.retention in RETENTION_LABELS) return { retention: parsed.retention };
    }
  } catch { /* storage unavailable or corrupt */ }
  return { retention: "7d" };
}

export function saveSettings(s: Settings): void {
  try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(s)); } catch { /* ignore */ }
}

function maxAge(r: Retention): number {
  return r === "7d" ? 7 * DAY : r === "30d" ? 30 * DAY : Infinity;
}

function readAll(): ScanResponse[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    const list = raw ? (JSON.parse(raw) as ScanResponse[]) : [];
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function writeAll(list: ScanResponse[]): void {
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(list)); } catch { /* ignore */ }
}

export function loadHistory(): ScanResponse[] {
  const { retention } = loadSettings();
  if (retention === "off") return [];
  const limit = Date.now() - maxAge(retention);
  const kept = readAll().filter((r) => new Date(r.scanned_at).getTime() >= limit);
  writeAll(kept);
  return kept;
}

export function addToHistory(r: ScanResponse): void {
  if (loadSettings().retention === "off") return;
  writeAll([r, ...loadHistory()].slice(0, MAX_ITEMS));
}

export function clearHistory(): void {
  try { localStorage.removeItem(HISTORY_KEY); } catch { /* ignore */ }
  lastResult = null;
}

export function findScan(id: string): ScanResponse | undefined {
  if (lastResult?.scan_id === id) return lastResult;
  return loadHistory().find((r) => r.scan_id === id);
}
