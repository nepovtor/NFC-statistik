from __future__ import annotations


class ServiceError(Exception):
    pass


class ValidationError(ServiceError):
    pass


class ConflictError(ServiceError):
    pass


class NotFoundError(ServiceError):
    pass
