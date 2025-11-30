"""OWASP Top 10 2021 vulnerability detection modules."""

from .a01_broken_access import BrokenAccessControl
from .a02_crypto_failures import CryptographicFailures
from .a03_injection import InjectionScanner
from .a04_insecure_design import InsecureDesignScanner
from .a05_misconfiguration import SecurityMisconfigurationScanner

__all__ = [
    'BrokenAccessControl',
    'CryptographicFailures',
    'InjectionScanner',
    'InsecureDesignScanner',
    'SecurityMisconfigurationScanner'
]