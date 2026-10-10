"""Sign, serialise and verify events. `to_wire` and `from_wire` are the only wire format."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from .envelope import (
    Algorithm,
    CloudEvent,
    EventProvenance,
    EventSignature,
    SignedEvent,
    signed_payload,
)

_DIGESTS = {"HS256": hashlib.sha256, "HS512": hashlib.sha512}

Keyring = Mapping[str, bytes]
"""key_id -> HMAC secret."""


class SignatureError(Exception):
    """The event is malformed, signed by an unknown key, or has been altered."""


def _mac(payload: dict[str, Any], secret: bytes, algorithm: Algorithm) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hmac.new(secret, canonical.encode("utf-8"), _DIGESTS[algorithm]).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


def sign_event(
    event: CloudEvent,
    provenance: EventProvenance,
    *,
    secret: bytes,
    key_id: str,
    algorithm: Algorithm = "HS256",
    execution_id: str | None = None,
) -> SignedEvent:
    if not secret:
        raise ValueError("signing secret must not be empty")
    execution_id = execution_id or event.id
    signature = _mac(signed_payload(event, provenance, execution_id), secret, algorithm)
    return SignedEvent(
        event=event,
        provenance=provenance,
        signature=EventSignature(algorithm=algorithm, key_id=key_id, signature=signature),
        execution_id=execution_id,
    )


def verify_event(signed: SignedEvent, keys: Keyring) -> None:
    """Raise SignatureError unless `signed` carries a valid signature from a key in `keys`."""
    secret = keys.get(signed.signature.key_id)
    if not secret:
        raise SignatureError(f"unknown key_id: {signed.signature.key_id}")
    expected = _mac(signed.signed_payload(), secret, signed.signature.algorithm)
    if not hmac.compare_digest(expected.encode(), signed.signature.signature.encode()):
        raise SignatureError("signature mismatch")


def to_wire(signed: SignedEvent) -> str:
    """Serialise the full envelope, signature included, for a queue or HTTP body."""
    return signed.model_dump_json(exclude_none=True)


def from_wire(payload: str | bytes, keys: Keyring) -> SignedEvent:
    """Parse and verify a `to_wire` payload. There is no unverified parse."""
    try:
        signed = SignedEvent.model_validate_json(payload)
    except ValidationError as exc:
        raise SignatureError(f"malformed event: {exc.error_count()} validation errors") from exc
    verify_event(signed, keys)
    return signed
