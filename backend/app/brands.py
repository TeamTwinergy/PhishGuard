"""Small built-in list of well-known brands and their official registered domains.

This list is deliberately small and NOT exhaustive: a brand missing here is simply
not checked, and an official domain missing here can cause a false positive.
"""
from __future__ import annotations


def _variants(name: str, suffixes: list[str]) -> set[str]:
    return {f"{name}.{s}" for s in suffixes}


_CC = ["com", "co.in", "co.uk", "ca", "de", "fr", "it", "es", "com.au", "co.jp", "com.br"]

BRANDS: dict[str, dict[str, set[str]]] = {
    "paypal": {"official": {"paypal.com", "paypal.me"}},
    "google": {"official": _variants("google", _CC) | {"googleapis.com", "gstatic.com", "googleusercontent.com"}},
    "microsoft": {"official": {"microsoft.com", "live.com", "office.com", "microsoftonline.com", "windows.com", "azure.com"}},
    "amazon": {"official": _variants("amazon", _CC + ["in"]) | {"amazonaws.com"}},
    "apple": {"official": {"apple.com", "icloud.com"}},
    "icloud": {"official": {"icloud.com", "apple.com"}},
    "netflix": {"official": {"netflix.com"}},
    "facebook": {"official": {"facebook.com", "fb.com", "messenger.com"}},
    "instagram": {"official": {"instagram.com"}},
    "whatsapp": {"official": {"whatsapp.com", "whatsapp.net"}},
    "linkedin": {"official": {"linkedin.com"}},
    "dropbox": {"official": {"dropbox.com"}},
    "github": {"official": {"github.com", "github.io", "githubusercontent.com"}},
    "paytm": {"official": {"paytm.com"}},
    "hdfcbank": {"official": {"hdfcbank.com"}},
    "icicibank": {"official": {"icicibank.com"}},
    "sbi": {"official": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"}},
}
