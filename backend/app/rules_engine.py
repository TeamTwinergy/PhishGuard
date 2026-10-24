"""Deterministic detection rules. Each rule returns zero or more Findings.

Findings are SIGNALS, not proof. `group` is used by the scorer so related
indicators are not counted twice.
"""
from __future__ import annotations

from dataclasses import dataclass

from .brands import BRANDS
from .config import (
    EXCESSIVE_SUBDOMAINS, LONG_URL_EXTREME, LONG_URL_MODERATE, MANY_HYPHENS, RULE_WEIGHTS,
)
from .url_parser import ParsedURL

ACTION_VERIFY = "Don't use this link. Go to the service by typing its official address or using its official app."


@dataclass
class Finding:
    rule_id: str
    group: str
    title: str
    severity: str
    weight: int
    evidence: str
    why_it_matters: str
    recommended_action: str


@dataclass
class Observation:
    id: str
    title: str
    detail: str


def _severity(weight: int) -> str:
    return "high" if weight >= 35 else "medium" if weight >= 15 else "low"


def _clip(text: str, n: int = 60) -> str:
    return text if len(text) <= n else text[:n] + "…"


def _f(w, rule_id, group, title, evidence, why, action=ACTION_VERIFY) -> Finding:
    weight = w[rule_id]
    return Finding(rule_id, group, title, _severity(weight), weight, evidence, why, action)


def rule_userinfo(p, f, w):
    if not p.has_userinfo:
        return []
    if f["userinfo_deceptive"]:
        return [_f(w, "userinfo_deceptive", "userinfo", "Deceptive text before '@'",
                   f"The text before '@' ({_clip(p.username)}) looks like a web address, but the browser connects to '{p.hostname}'.",
                   "Everything before '@' is read as a username, not the destination. Attackers use this to make a link look like it points to a trusted site.")]
    return [_f(w, "userinfo_present", "userinfo", "Username embedded in the URL",
               "The URL contains a username (and possibly a password) before '@'.",
               "Legitimate links rarely embed credentials, and the syntax can disguise the real destination.")]


def rule_ip(p, f, w):
    if not p.is_ip:
        return []
    if p.ip_obfuscated:
        return [_f(w, "ip_obfuscated", "ip_host", "Host is a disguised IP address",
                   f"'{_clip(p.host_as_typed)}' is an alternative way of writing the IP address {p.ip_address}.",
                   "Writing an IP in decimal, hex or octal hides it from casual inspection. Legitimate sites almost never do this.")]
    return [_f(w, "ip_host", "ip_host", "Host is a raw IP address",
               f"The link points to the IP address {p.ip_address} instead of a domain name.",
               "Brands use domain names. Raw IP links are common in throwaway phishing and malware hosting, though some internal tools use them legitimately.")]


_BRAND_RULES = {
    "official_embedded": ("brand_official_domain_embedded", "An official domain name appears inside an unrelated domain"),
    "idn_homograph": ("brand_idn_homograph", "Look-alike characters imitate a brand name"),
    "homoglyph": ("brand_homoglyph", "Brand name disguised with look-alike characters"),
    "typosquat": ("brand_typosquat", "Misspelling of a well-known brand name"),
    "unofficial_domain": ("brand_in_unofficial_domain", "Brand name used in a domain that isn't the brand's"),
}


def rule_brand(p, f, w):
    out = []
    for s in f["brand_signals"]:
        rule_id, title = _BRAND_RULES[s["kind"]]
        official = ", ".join(s["official_domains"][:4])
        out.append(_f(
            w, rule_id, "brand", f"{title} ({s['brand'].title()})",
            f"'{_clip(s['matched'])}' in '{p.hostname}' resembles {s['brand'].title()}, but the registered domain looks like '{p.registered_domain}'. Official domains in PhishGuard's built-in list: {official}.",
            "Attackers register look-alike domains to impersonate trusted services. This is a heuristic match against a small brand list, so legitimate partner or fan sites can trigger it.",
            f"Don't use this link. Open {s['brand'].title()} by typing its official address or using its app.",
        ))
    return out


def rule_idn(p, f, w):
    out = []
    if f["mixed_script_labels"]:
        lab = f["mixed_script_labels"][0]
        out.append(_f(w, "idn_mixed_script", "idn", "Hostname mixes alphabets",
                      f"The label '{_clip(lab)}' mixes characters from different writing systems.",
                      "Mixing alphabets (for example Cyrillic with Latin) is a classic way to build a domain that looks identical to another one."))
    elif f["punycode_labels"]:
        out.append(_f(w, "punycode", "idn", "Internationalized (punycode) domain",
                      f"The hostname '{p.hostname}' is the encoded form of '{p.hostname_unicode}'.",
                      "Non-Latin domains are legitimate, but punycode can also hide look-alike characters. On its own this is a weak signal.",
                      "Check that the displayed name is what you expect before trusting the link."))
    return out


def rule_shortener(p, f, w):
    if not f["is_shortener"]:
        return []
    return [_f(w, "url_shortener", "shortener", "Link-shortening service",
               f"'{p.hostname}' is a URL shortener, so the final destination is hidden.",
               "Shorteners are widely used legitimately, but they stop you from seeing where a link really leads. PhishGuard does not follow redirects.",
               "Ask the sender for the full address, or use the shortener's preview feature.")]


def rule_https(p, f, w):
    if p.scheme == "http":
        return [_f(w, "no_https", "transport", "Connection is not encrypted (HTTP)",
                   "The link uses http:// rather than https://.",
                   "Traffic can be read or altered in transit. HTTP alone doesn't make a site malicious, but sensitive information should never be entered on it.",
                   "Don't enter passwords or personal data on an HTTP page.")]
    return []


def rule_subdomains(p, f, w):
    if f["subdomain_count"] >= EXCESSIVE_SUBDOMAINS:
        return [_f(w, "excessive_subdomains", "subdomains", "Many subdomain levels",
                   f"The hostname has {f['subdomain_count']} subdomain levels: {_clip('.'.join(p.subdomains))}.",
                   "Long subdomain chains push the real domain to the end of the address, where people rarely look. The part that matters is the domain just before the final suffix.")]
    return []


def rule_length(p, f, w):
    n = f["url_length"]
    if n >= LONG_URL_EXTREME:
        rid = "long_url_extreme"
    elif n >= LONG_URL_MODERATE:
        rid = "long_url_moderate"
    else:
        return []
    return [_f(w, rid, "length", "Unusually long URL", f"The URL is {n} characters long.",
               "Very long URLs can hide the real destination or carry tracking data. Many legitimate links are long too, so this is a weak signal.",
               "Look at the domain, not the long tail of the address.")]


def rule_hyphens(p, f, w):
    if f["hyphen_count"] >= MANY_HYPHENS:
        return [_f(w, "many_hyphens", "hostname_shape", "Many hyphens in the hostname",
                   f"The hostname contains {f['hyphen_count']} hyphens.",
                   "Domains such as 'secure-account-verify-login' are often built to look official. Weak signal on its own.")]
    return []


def rule_port(p, f, w):
    if f["unusual_port"]:
        return [_f(w, "unusual_port", "port", "Unusual port number", f"The link uses port {p.port}.",
                   "Normal websites use the default web ports. Non-standard ports appear on test servers and some malicious hosts.")]
    return []


def rule_file(p, f, w):
    ext = f["file_extension"]
    if f["double_extension"]:
        return [_f(w, "file_double_extension", "file", "Executable disguised as a document",
                   f"The path ends in a document-like name followed by '.{ext}'.",
                   "Names like 'invoice.pdf.exe' trick people into running a program while thinking it is a document.",
                   "Do not download or open this file.")]
    if f["executable_file"]:
        return [_f(w, "file_executable", "file", "Link to an executable file", f"The path points to a '.{ext}' file.",
                   "Executable and script files can run code on your device.",
                   "Only download software from the vendor's official site.")]
    if f["archive_file"]:
        return [_f(w, "file_archive", "file", "Link to an archive or disk image", f"The path points to a '.{ext}' file.",
                   "Archives are common legitimately, but are also used to deliver malware past scanners.",
                   "Only open archives from sources you trust.")]
    return []


def rule_keywords(p, f, w):
    hits = f["keyword_hits"]
    if not hits:
        return []
    rid = "suspicious_keywords_many" if len(hits) >= 2 else "suspicious_keywords_one"
    return [_f(w, rid, "keywords", "Credential-related words in the address",
               f"Words found: {', '.join(hits)}.",
               "Phishing links often include words like 'login' or 'verify', but so do many legitimate pages. This is a weak signal that matters mainly alongside others.",
               "Reach the page through the official site rather than this link.")]


def rule_encoding(p, f, w):
    e = f["encoding"]
    out = []
    if f["host_percent_encoded"]:
        out.append(_f(w, "encoded_host", "encoded_host", "Hostname contains percent-encoding",
                      "The hostname part of the URL includes %XX sequences.",
                      "Domain names don't normally need percent-encoding; it can be used to obfuscate the destination."))
    reasons = []
    if e["double_encoded"]:
        reasons.append("double-encoded characters (%25xx)")
    if e["control"]:
        reasons.append("encoded control characters")
    if e["traversal"]:
        reasons.append("encoded path-traversal or backslash sequences")
    if e["alnum"] >= 3:
        reasons.append(f"{e['alnum']} ordinary letters/digits written as %XX")
    if reasons:
        out.append(_f(w, "suspicious_encoding", "encoding", "Suspicious URL encoding", "Found: " + "; ".join(reasons) + ".",
                      "Encoding ordinary characters is a way to hide words from filters and from people reading the link. (Encoded non-English text is normal and is not flagged.)"))
    return out


RULES = [rule_userinfo, rule_ip, rule_brand, rule_idn, rule_shortener, rule_https, rule_subdomains,
         rule_length, rule_hyphens, rule_port, rule_file, rule_keywords, rule_encoding]


def _observations(p: ParsedURL, f: dict) -> list[Observation]:
    obs = []
    if f["uses_https"]:
        obs.append(Observation("https", "Uses HTTPS",
                               "Traffic to this address is encrypted. This does not show the site is trustworthy: phishing sites can also have valid certificates."))
    if not p.has_userinfo:
        obs.append(Observation("no_userinfo", "No credentials embedded in the URL", "Nothing before '@' could disguise the destination."))
    if not p.is_ip:
        obs.append(Observation("named_host", "Host is a domain name, not a raw IP address", f"Hostname: {p.hostname}"))
    if not p.is_ip and not f["brand_signals"]:
        obs.append(Observation("no_brand_match", "No look-alike match in PhishGuard's built-in brand list",
                               f"Checked against {len(BRANDS)} well-known brands. The list is small and not exhaustive."))
    if p.port is None or not f["unusual_port"]:
        obs.append(Observation("standard_port", "Standard web port", "No unusual port number in the URL."))
    return obs


def evaluate(p: ParsedURL, f: dict, weights: dict | None = None) -> tuple[list[Finding], list[Observation]]:
    w = weights or RULE_WEIGHTS
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(p, f, w))
    findings.sort(key=lambda x: x.weight, reverse=True)
    return findings, _observations(p, f)
