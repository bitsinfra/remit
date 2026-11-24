"""Remit Sender SDK for Python."""

from .core import (
    Identity, Untrusted, RemitTypeError, canonicalize, capacity, capacity_ceil, did_key, public_key_from_did_key,
    remit_id, params_sha256, sign_manifest, sign_envelope, open_envelope, t, STATUS_BITS, STATUS_SET,
)
from .client import AsyncHolder, AsyncRemit, Holder, Receipt, Remit, RemitError, Result, sign_request

__all__ = [
    "Identity", "Untrusted", "RemitTypeError", "canonicalize", "capacity", "capacity_ceil", "did_key", "public_key_from_did_key",
    "remit_id", "params_sha256", "sign_manifest", "sign_envelope", "open_envelope", "t", "STATUS_BITS", "STATUS_SET",
    "Remit", "AsyncRemit", "Holder", "AsyncHolder", "Result", "Receipt", "RemitError", "sign_request", "EmbeddedHolder",
]
from .embedded import EmbeddedHolder

__version__ = "0.1.0"

try:  # Rust verifier core (PyO3), when installed: `maturin build -m crates/remit-py/Cargo.toml`
    import remit_native as native  # noqa: F401
except ImportError:  # pure-Python implementation is used
    native = None
