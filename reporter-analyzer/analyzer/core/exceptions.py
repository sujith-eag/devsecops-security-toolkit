"""Custom exceptions used by the reporter analyzer."""


class ReporterError(Exception):
    """Base exception for expected reporter failures."""


class InputValidationError(ReporterError):
    """Raised when required input data is missing or invalid."""
