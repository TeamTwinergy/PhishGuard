"""Structural URL characteristics. Pure functions; no network access."""
from __future__ import annotations

import re
import unicodedata
from urllib.parse import unquote

from .brands import BRANDS
from .url_parser import ParsedURL

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in",
}
EXECUTABLE_EXT = {"exe", "scr", "bat", "cmd", "msi", "apk", "jar", "vbs", "ps1", "lnk", "pif", "js", "hta", "dll"}
ARCHIVE_EXT = {"zip", "rar", "7z", "iso", "img", "dmg"}
DOC_LIKE_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt", "csv"}
KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "security", "account",
    "accounts", "update", "password", "wallet", "confirm", "banking", "billing",
    "suspend", "suspended", "unlock", "recover", "authenticate",
}
COMMON_PORTS = {80, 443, 8080, 8443}
PRIORITY = ["official_embedded", "idn_homograph", "homoglyph", "typosquat", "unofficial_domain"]

# Cyrillic/Greek characters that render like Latin letters.
_CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u0501": "d", "\u0261": "g", "\u04cf": "l", "\u04bb": "h", "\u03bf": "o",
    "\u03b1": "a", "\u03c1": "p", "\u03bd": "v",
}
_DIGIT_SUBS = {"0": ["o"], "1": ["l", "i"], "3": ["e"], "4": ["a"], "5": ["s"]}


def _script_of(ch: str) -> str:
    try:
        first = unicodedata.name(ch).split()[0]
    except ValueError:
        return "UNKNOWN"
    return "CJK" if first in {"HIRAGANA", "KATAKANA", "CJK"} else first


def _mixed_script_labels(unicode_labels: list[str]) -> list[str]:
    out = []
    for lab in unicode_labels:
        if lab.isascii():
            continue
        if len({_script_of(c) for c in lab if c.isalpha()}) > 1:
            out.append(lab)
    return out


def _skeleton(label: str) -> str:
    return unicodedata.normalize("NFKC", label).translate(str.maketrans(_CONFUSABLES))


def _within_one_edit(a: str, b: str) -> bool:
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = j = 0
    edited = False
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        if edited:
            return False
        edited = True
        if len(a) == len(b):
            i += 1
        j += 1
    return True


def _brand_in_token(brand: str, tok: str) -> bool:
    # Short brands (<6 chars) must match a whole token to avoid hits like "pineapple".
    return tok == brand or (len(brand) >= 6 and brand in tok)


def _homoglyph_variants(tok: str) -> set[str]:
    variants = {tok}
    if "rn" in tok:
        variants.add(tok.replace("rn", "m"))
    if "vv" in tok:
        variants.add(tok.replace("vv", "w"))
    for ch, subs in _DIGIT_SUBS.items():
        if ch in tok and len(variants) < 64:
            variants |= {v.replace(ch, s) for v in list(variants) for s in subs}
    variants.discard(tok)
    return variants


def detect_brand_signals(p: ParsedURL) -> list[dict]:
    if p.is_ip:
        return []
    n_suffix = len(p.suffix.split(".")) if p.suffix else 0
    n_name = len(p.labels) - n_suffix
    name_labels = p.labels[:n_name]
    unicode_labels = p.labels_unicode[:n_name]

    tokens: list[str] = []
    for lab in name_labels:
        tokens.append(lab)
        tokens.extend(t for t in lab.split("-") if t)
    skeleton_tokens: list[str] = []
    for lab in unicode_labels:
        if lab.isascii():
            continue
        sk = _skeleton(lab)
        if sk.isascii():
            skeleton_tokens.append(sk)
            skeleton_tokens.extend(t for t in sk.split("-") if t)

    host_dotted = f".{p.hostname}."
    results = []
    for brand, info in BRANDS.items():
        official = info["official"]
        if p.registered_domain in official:
            continue
        found: dict[str, str] = {}
        for od in sorted(official):
            if f".{od}." in host_dotted:
                found["official_embedded"] = od
                break
        for tok in skeleton_tokens:
            if _brand_in_token(brand, tok):
                found.setdefault("idn_homograph", tok)
        for tok in tokens:
            if tok.startswith("xn--"):
                continue
            if _brand_in_token(brand, tok):
                found.setdefault("unofficial_domain", tok)
            elif any(_brand_in_token(brand, v) for v in _homoglyph_variants(tok)):
                found.setdefault("homoglyph", tok)
            elif len(brand) >= 6 and len(tok) >= 6 and _within_one_edit(tok, brand):
                found.setdefault("typosquat", tok)
        for kind in PRIORITY:
            if kind in found:
                results.append({
                    "brand": brand, "kind": kind, "matched": found[kind],
                    "official_domains": sorted(official),
                })
                break
    return results


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if t}


def extract_features(p: ParsedURL) -> dict:
    segment = unquote(p.path).rsplit("/", 1)[-1].lower()
    exts = segment.split(".")[1:]
    last_ext = exts[-1] if exts else ""
    prev_ext = exts[-2] if len(exts) >= 2 else ""

    n_suffix = len(p.suffix.split(".")) if p.suffix else 0
    host_tokens = _tokens(".".join(p.labels[: len(p.labels) - n_suffix]))
    kw_text = " ".join([unquote(p.path)] + [q.name for q in p.query_params])
    keyword_hits = sorted((host_tokens | _tokens(kw_text)) & KEYWORDS)

    username = p.username.lower()
    userinfo_deceptive = bool(
        p.has_userinfo
        and (re.search(r"[a-z0-9-]+\.[a-z]{2,}", username) or username.startswith(("http", "www")))
    )
    shortener = (not p.is_ip) and (p.registered_domain in URL_SHORTENERS or p.hostname in URL_SHORTENERS)

    return {
        "url_length": p.input_length,
        "uses_https": p.scheme == "https",
        "subdomain_count": len(p.subdomains),
        "hyphen_count": p.hostname_unicode.count("-"),  # unicode form: "xn--" is not a real hyphen
        "has_userinfo": p.has_userinfo,
        "userinfo_deceptive": userinfo_deceptive,
        "is_ip_host": p.is_ip,
        "ip_obfuscated": p.ip_obfuscated,
        "punycode_labels": [l for l in p.labels if l.startswith("xn--")],
        "mixed_script_labels": _mixed_script_labels(p.labels_unicode),
        "port": p.port,
        "unusual_port": p.port is not None and p.port not in COMMON_PORTS,
        "is_shortener": shortener,
        "file_extension": last_ext,
        "executable_file": last_ext in EXECUTABLE_EXT,
        "archive_file": last_ext in ARCHIVE_EXT,
        "double_extension": last_ext in EXECUTABLE_EXT and prev_ext in DOC_LIKE_EXT,
        "keyword_hits": keyword_hits,
        "brand_signals": detect_brand_signals(p),
        "encoding": p.encoding,
        "host_percent_encoded": p.host_percent_encoded,
    }
