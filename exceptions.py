class ApiServiceError(Exception):
    """Api Service Error"""

    def __init__(self, status_code: int = None, message="response status code"):
        self.message = f"{self.__class__.__name__}: {message} {status_code}"
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


class BadApiRequest(ApiServiceError):
    """Bad Api Request"""


class BadApiKey(ApiServiceError):
    """Bad Api Key"""


class BadApiMethod(ApiServiceError):
    """Bad Api Method"""


class ObjectNotFound(ApiServiceError):
    """Object Not Found"""


class InternalServerError(ApiServiceError):
    """InternalServerError"""
