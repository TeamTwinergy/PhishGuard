export interface Finding {
  rule_id: string; group: string; title: string;
  severity: "low" | "medium" | "high"; weight: number;
  evidence: string; why_it_matters: string; recommended_action: string;
}
export interface Observation { id: string; title: string; detail: string }
export interface ScoreItem { rule_id: string; group: string; weight: number; counted: boolean; note: string }
export interface QueryParam { name: string; value: string; redacted: boolean }
export interface UrlBreakdown {
  scheme: string; scheme_assumed: boolean; hostname: string; hostname_unicode: string;
  is_ip: boolean; ip_address: string | null; port: number | null;
  registered_domain: string | null; suffix: string | null; subdomains: string[];
  domain_parsing: string; path: string; query_params: QueryParam[];
  fragment: string | null; has_userinfo: boolean; redacted_url: string;
  normalization_notes: string[];
}
export interface Reputation { provider: string; status: string; detail: string | null; threat_types?: string[] | null }
export interface ProviderInfo { name: string; configured: boolean }
export interface SkippedCheck { check: string; status: string; reason: string }
export interface Explanation {
  source: string; summary: string; evidence: string[]; limitations: string[]; next_steps: string[];
}
export interface ScanResponse {
  scan_id: string; scanned_at: string; hostname: string;
  risk_score: number; risk_category: string; thresholds: number[]; score_method: string;
  findings: Finding[]; positive_observations: Observation[]; score_breakdown: ScoreItem[];
  url_breakdown: UrlBreakdown; reputation: Reputation[]; skipped_checks: SkippedCheck[];
  explanation: Explanation; recommended_next_steps: string[];
}
