class TrustSocLLMError(Exception):
    """Base class for SDK errors."""
    pass


class APIRequestError(TrustSocLLMError):
    """API 호출 실패."""
    def __init__(self, status_code: int, message: str):
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code


class SchemaValidationError(TrustSocLLMError):
    """서버 응답이 예상 스키마와 다를 때."""
    pass
