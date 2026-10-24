from __future__ import annotations


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str, headers: dict | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = headers or {}


def error_payload(code: str, message: str) -> dict:
    return {"error": {"code": code, "message": message}}
