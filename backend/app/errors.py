"""Structured API errors. Technical failures stay technical failures."""


class AppError(Exception):
    def __init__(self, status_code: int, code: str, message: str, retryable: bool = False):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.retryable = retryable

    def body(self) -> dict:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "retryable": self.retryable,
            }
        }


class RetryableUpstream(Exception):
    """One follow-up attempt is allowed. Never raised to the client directly."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def exhausted(exc: RetryableUpstream) -> AppError:
    text = exc.message.lower()
    if "time" in text:
        return AppError(504, "timeout", exc.message, False)
    return AppError(503, "upstream_unavailable", exc.message, False)
