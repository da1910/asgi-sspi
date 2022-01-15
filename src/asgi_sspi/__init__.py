"""Provides Kerberos authentication support for ASGI applications on Windows using the SSPI"""
import logging

from .asgi_sspi import SPNEGOAuthMiddleware

__version__ = "0.0.1"

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

__all__ = ["SPNEGOAuthMiddleware"]
