import type { ProviderInfo, ScanResponse } from "./types";

const API_BASE: string = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8000";
const TIMEOUT_MS = 15000;

export type ApiErrorKind = "validation" | "rate_limited" | "timeout" | "network" | "server";

export class ApiRequestError extends Error {
  kind: ApiErrorKind;
  constructor(kind: ApiErrorKind, message: string) {
    super(message);
    this.kind = kind;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${API_BASE}${path}`, { ...init, signal: controller.signal });
    if (res.ok) return (await res.json()) as T;
    let message = "The request failed. Please try again.";
    try {
      const body = await res.json();
      if (body?.error?.message) message = body.error.message;
    } catch { /* non-JSON error body */ }
    if (res.status === 429) throw new ApiRequestError("rate_limited", message);
    if (res.status >= 500) throw new ApiRequestError("server", message);
    throw new ApiRequestError("validation", message);
  } catch (err) {
    if (err instanceof ApiRequestError) throw err;
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiRequestError("timeout", "The request took too long. The backend may be waking up (free hosting sleeps when idle). Wait a few seconds and try again.");
    }
    throw new ApiRequestError("network", "Could not reach the PhishGuard backend. Check that it is running and that VITE_API_BASE_URL is correct.");
  } finally {
    clearTimeout(timer);
  }
}

export const scanUrl = (url: string) =>
  request<ScanResponse>("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });

export const fetchProviders = () => request<ProviderInfo[]>("/api/providers");
