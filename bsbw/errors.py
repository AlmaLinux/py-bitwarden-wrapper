__all__ = [
    'BWCLIError',
    'BWCLIFetchError',
    'BWCLILoginError',
]


class BWCLIError(Exception):
    pass


class BWCLILoginError(BWCLIError):
    pass


class BWCLIFetchError(BWCLIError):
    pass
