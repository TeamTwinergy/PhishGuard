"""Safe URL parsing and normalization.

Static analysis only: nothing here performs DNS lookups or network requests.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

from .config import MAX_INPUT_LENGTH

ALLOWED_SCHEMES = {"http", "https"}

# Tiny offline stand-in for the Public Suffix List. Registered-domain splitting is
# therefore a HEURISTIC (reported as such); swap in a real PSL for production.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "co.in", "net.in", "org.in", "ac.in", "gov.in", "edu.in", "res.in",
    "co.za", "com.br", "com.cn", "com.mx", "com.sg", "com.hk", "com.tr", "co.kr",
    "com.ar", "co.id",
}

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):(//)?")
_HOST_PORT_RE = re.compile(r"^[^/?#:@]*:\d+(?:[/?#]|$)")
_ASCII_LABEL_RE = re.compile(r"^[a-z0-9_-]+$")
_SENSITIVE_NAME_RE = re.compile(
    r"token|passw|pwd|secret|session|sess|auth|api[_-]?key|otp|signature|jwt|credential|ssn|cvv|card|bearer",
    re.I,
)
_SENSITIVE_EXACT = {"sid", "code", "key", "sig", "pin", "pw", "ticket"}
_TOKENISH_RE = re.compile(r"^[A-Za-z0-9_\-+/=.%]+$")
_EMAILISH_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class InvalidURLError(ValueError):
    """Raised for input PhishGuard cannot analyze. `code` is machine-readable."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class QueryParam:
    name: str
    value: str
    redacted: bool


@dataclass
class ParsedURL:
    input_length: int
    scheme: str
    scheme_assumed: bool
    hostname: str                 # normalized, ASCII (punycode) or normalized IP
    hostname_unicode: str
    host_as_typed: str
    is_ip: bool
    ip_obfuscated: bool
    ip_address: str | None
    port: int | None
    labels: list[str]
    labels_unicode: list[str]
    subdomains: list[str]
    registered_label: str
    registered_domain: str
    suffix: str
    domain_parsing: str           # "heuristic" | "not_applicable"
    has_userinfo: bool
    username: str
    has_password: bool
    host_percent_encoded: bool
    path: str
    query_params: list[QueryParam]
    fragment: str | None          # already redacted / truncated for display
    encoding: dict
    normalization_notes: list[str] = field(default_factory=list)
    # Normalized URL for reputation lookups: no userinfo, no fragment. Never stored or logged.
    lookup_url: str = ""

    @property
    def redacted_url(self) -> str:
        """URL safe to display or store: no credentials, sensitive values hidden."""
        host = f"[{self.hostname}]" if (self.is_ip and ":" in self.hostname) else self.hostname
        out = f"{self.scheme}://"
        if self.has_userinfo:
            out += "[userinfo hidden]@"
        out += host
        if self.port is not None:
            out += f":{self.port}"
        out += _clip(self.path, 200)
        if self.query_params:
            out += "?" + "&".join(f"{q.name}={q.value}" if q.value != "" else q.name for q in self.query_params)
        if self.fragment:
            out += "#" + self.fragment
        return out

    def to_breakdown(self) -> dict:
        return {
            "scheme": self.scheme,
            "scheme_assumed": self.scheme_assumed,
            "hostname": self.hostname,
            "hostname_unicode": self.hostname_unicode,
            "is_ip": self.is_ip,
            "ip_address": self.ip_address,
            "port": self.port,
            "registered_domain": self.registered_domain or None,
            "suffix": self.suffix or None,
            "subdomains": list(self.subdomains),
            "domain_parsing": self.domain_parsing,
            "path": _clip(self.path, 200),
            "query_params": [q.__dict__.copy() for q in self.query_params],
            "fragment": self.fragment,
            "has_userinfo": self.has_userinfo,
            "redacted_url": self.redacted_url,
            "normalization_notes": list(self.normalization_notes),
        }


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _is_sensitive(name: str, value: str) -> bool:
    n = name.lower()
    if n in _SENSITIVE_EXACT or _SENSITIVE_NAME_RE.search(n):
        return True
    if len(value) >= 24 and _TOKENISH_RE.match(value):
        return True
    return bool(_EMAILISH_RE.match(value))


def _redact_query(query: str) -> list[QueryParam]:
    if not query:
        return []
    try:
        pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=200)
    except ValueError:
        return [QueryParam("[too many parameters]", "", False)]
    out = []
    for name, value in pairs:
        if value and _is_sensitive(name, value):
            out.append(QueryParam(_clip(name, 40), "[redacted]", True))
        else:
            out.append(QueryParam(_clip(name, 40), _clip(value, 60), False))
    return out


def _redact_fragment(fragment: str) -> str | None:
    if not fragment:
        return None
    if "=" in fragment:
        pairs = parse_qsl(fragment, keep_blank_values=True)
        if any(_is_sensitive(n, v) for n, v in pairs):
            return "[redacted]"
    elif len(fragment) >= 24 and _TOKENISH_RE.match(fragment):
        return "[redacted]"
    return _clip(fragment, 60)


def _encoding_stats(text: str) -> dict:
    values = [int(h, 16) for h in re.findall(r"%([0-9A-Fa-f]{2})", text)]
    return {
        "total": len(values),
        "double_encoded": bool(re.search(r"%25[0-9A-Fa-f]{2}", text)),
        "control": any(v < 32 or v == 127 for v in values),
        "alnum": sum(1 for v in values if v < 128 and chr(v).isalnum()),
        "traversal": bool(re.search(r"%2e%2e|\.\.%2f|%2e\.|\.%2e|%5c", text, re.I)),
    }


def _parse_ipv4_part(part: str) -> int | None:
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", part):
        return int(part, 16)
    if re.fullmatch(r"0[0-7]+", part):
        return int(part, 8)
    if re.fullmatch(r"\d+", part) and not (len(part) > 1 and part.startswith("0")):
        return int(part)
    return None


def _classify_ip(host: str) -> tuple[str, bool] | None:
    """Return (ip, obfuscated) if `host` is an IPv4 literal in any browser-accepted form."""
    try:
        return str(ipaddress.ip_address(host)), False
    except ValueError:
        pass
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums = [_parse_ipv4_part(p) for p in parts]
    if any(n is None for n in nums):
        return None
    *head, last = nums  # type: ignore[misc]
    if any(n > 255 for n in head) or last >= 256 ** (5 - len(parts)):
        return None
    value = 0
    for n in head:
        value = (value << 8) | n
    value = (value << (8 * (5 - len(parts)))) | last
    return str(ipaddress.IPv4Address(value)), True


def _convert_labels(host: str) -> tuple[list[str], list[str]]:
    ascii_labels: list[str] = []
    unicode_labels: list[str] = []
    for lab in host.split("."):
        if not lab:
            raise InvalidURLError("malformed_host", "The hostname contains an empty section (two dots in a row).")
        if lab.isascii():
            ascii_lab = lab
            uni = lab
            if lab.startswith("xn--"):
                try:
                    uni = lab.encode("ascii").decode("idna")
                except UnicodeError:
                    uni = lab
        else:
            try:
                ascii_lab = lab.encode("idna").decode("ascii")
            except UnicodeError:
                raise InvalidURLError(
                    "invalid_idn",
                    "The hostname contains characters that cannot form a valid internationalized domain name.",
                )
            uni = lab
        if not _ASCII_LABEL_RE.match(ascii_lab):
            raise InvalidURLError("invalid_host_characters", "The hostname contains characters that are not allowed in domain names.")
        if len(ascii_lab) > 63:
            raise InvalidURLError("label_too_long", "A section of the hostname is longer than 63 characters.")
        ascii_labels.append(ascii_lab)
        unicode_labels.append(uni)
    return ascii_labels, unicode_labels


def _split_domain(labels: list[str]) -> tuple[list[str], str, str, str]:
    """Return (subdomains, registered_label, registered_domain, suffix) — heuristic."""
    if len(labels) == 1:
        return [], labels[0], labels[0], ""
    last2 = ".".join(labels[-2:])
    if last2 in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return labels[:-3], labels[-3], ".".join(labels[-3:]), last2
    return labels[:-2], labels[-2], last2, labels[-1]


def parse_url(raw: str) -> ParsedURL:
    notes: list[str] = []
    if not isinstance(raw, str):
        raise InvalidURLError("invalid_type", "The URL must be text.")
    text = raw.strip()
    if not text:
        raise InvalidURLError("empty_url", "Please enter a URL to analyze.")
    if len(text) > MAX_INPUT_LENGTH:
        raise InvalidURLError("url_too_long", f"The URL is longer than the {MAX_INPUT_LENGTH}-character limit.")
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise InvalidURLError("control_characters", "The URL contains control characters.")
    if any(c.isspace() for c in text):
        raise InvalidURLError("whitespace_in_url", "The URL contains spaces. Remove them or encode them as %20.")
    input_length = len(text)

    if "\\" in text:
        text = text.replace("\\", "/")
        notes.append("Backslashes were treated as '/', which is how browsers read them.")

    scheme_assumed = False
    m = _SCHEME_RE.match(text)
    if m and (m.group(2) or not _HOST_PORT_RE.match(text)):
        scheme = m.group(1).lower()
        if scheme not in ALLOWED_SCHEMES:
            raise InvalidURLError(
                "unsupported_scheme",
                f"The '{scheme[:20]}' protocol is not supported. PhishGuard analyzes http and https links only.",
            )
    else:
        scheme_assumed = True
        text = "https://" + text.lstrip("/")
        notes.append("No protocol was given, so https:// was assumed for analysis.")

    try:
        parts = urlsplit(text)
    except ValueError:
        raise InvalidURLError("malformed_url", "The URL is malformed and could not be parsed.")
    if not parts.netloc:
        raise InvalidURLError("missing_host", "The URL has no hostname.")

    userinfo, at, hostport = parts.netloc.rpartition("@")
    has_userinfo = bool(at)
    username = userinfo.split(":", 1)[0] if has_userinfo else ""
    has_password = has_userinfo and ":" in userinfo

    bracketed = hostport.startswith("[")
    if bracketed:
        end = hostport.find("]")
        if end == -1:
            raise InvalidURLError("malformed_url", "The IPv6 address is missing a closing bracket.")
        host_raw, rest = hostport[1:end], hostport[end + 1:]
        if rest and not rest.startswith(":"):
            raise InvalidURLError("malformed_url", "Unexpected text after the IPv6 address.")
        port_str = rest[1:]
    else:
        host_raw, _, port_str = hostport.partition(":")
        if ":" in port_str:
            raise InvalidURLError("malformed_url", "The hostname section contains too many ':' characters.")

    port: int | None = None
    if port_str:
        if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
            raise InvalidURLError("invalid_port", "The port must be a number between 1 and 65535.")
        port = int(port_str)

    host_encoded = "%" in host_raw
    host = unquote(host_raw) if host_encoded else host_raw
    host = host.strip().lower().rstrip(".")
    if not host:
        raise InvalidURLError("missing_host", "The URL has no hostname.")
    if len(host) > 253:
        raise InvalidURLError("host_too_long", "The hostname is longer than 253 characters.")

    is_ip = False
    ip_obfuscated = False
    ip_address: str | None = None
    if bracketed:
        try:
            ip_address = str(ipaddress.IPv6Address(host))
        except ValueError:
            raise InvalidURLError("malformed_url", "The IPv6 address is not valid.")
        is_ip = True
    else:
        found = _classify_ip(host)
        if found:
            ip_address, ip_obfuscated = found
            is_ip = True

    if is_ip:
        hostname = hostname_unicode = ip_address  # type: ignore[assignment]
        labels, labels_unicode = [], []
        subdomains, reg_label, reg_domain, suffix = [], "", "", ""
        domain_parsing = "not_applicable"
    else:
        labels, labels_unicode = _convert_labels(host)
        hostname = ".".join(labels)
        hostname_unicode = ".".join(labels_unicode)
        if len(hostname) > 253:
            raise InvalidURLError("host_too_long", "The hostname is longer than 253 characters.")
        subdomains, reg_label, reg_domain, suffix = _split_domain(labels)
        domain_parsing = "heuristic"

    host_for_lookup = f"[{hostname}]" if (is_ip and bracketed) else hostname
    lookup_url = f"{parts.scheme.lower()}://{host_for_lookup}"
    if port is not None:
        lookup_url += f":{port}"
    lookup_url += parts.path or "/"
    if parts.query:
        lookup_url += "?" + parts.query

    return ParsedURL(
        input_length=input_length,
        scheme=parts.scheme.lower(),
        scheme_assumed=scheme_assumed,
        hostname=hostname,
        hostname_unicode=hostname_unicode,
        host_as_typed=host_raw,
        is_ip=is_ip,
        ip_obfuscated=ip_obfuscated,
        ip_address=ip_address,
        port=port,
        labels=labels,
        labels_unicode=labels_unicode,
        subdomains=subdomains,
        registered_label=reg_label,
        registered_domain=reg_domain,
        suffix=suffix,
        domain_parsing=domain_parsing,
        has_userinfo=has_userinfo,
        username=username,
        has_password=has_password,
        host_percent_encoded=host_encoded,
        path=parts.path,
        query_params=_redact_query(parts.query),
        fragment=_redact_fragment(parts.fragment),
        encoding=_encoding_stats(text),
        normalization_notes=notes,
        lookup_url=lookup_url,
    )
