"""Pydantic models describing the signed CloudEvent envelope."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, Field, JsonValue, model_validator

TrustLevel = Literal["low", "medium", "high"]
Algorithm = Literal["HS256", "HS512"]


def _to_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


UtcDatetime = Annotated[datetime, AfterValidator(_to_utc)]


def _now() -> datetime:
    return datetime.now(UTC)


class CloudEvent(BaseModel):
    """Minimal CloudEvents 1.0 envelope."""

    model_config = {"extra": "forbid"}

    specversion: Literal["1.0"] = "1.0"
    id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    type: str = Field(min_length=1)
    subject: str | None = Field(default=None, min_length=1)
    time: UtcDatetime = Field(default_factory=_now)
    datacontenttype: str | None = None
    data: JsonValue | None = None
    extensions: dict[str, JsonValue] = Field(default_factory=dict)


class EventSignature(BaseModel):
    """Which key signed the event, and the signature itself."""

    model_config = {"extra": "forbid"}

    algorithm: Algorithm
    key_id: str = Field(min_length=1)
    signature: str = Field(min_length=1)


class EventProvenance(BaseModel):
    """Where an event entered the system. Covered by the signature."""

    model_config = {"extra": "forbid"}

    ingress: str = Field(min_length=1)
    trace_id: str = Field(min_length=1)
    zone: str = Field(default="unknown", min_length=1)
    caller_id: str = Field(default="unknown", min_length=1)
    trust_level: TrustLevel = "low"
    received_at: UtcDatetime = Field(default_factory=_now)
    extra: dict[str, JsonValue] = Field(default_factory=dict)


class SignedEvent(BaseModel):
    """A CloudEvent with its provenance and a signature over both."""

    model_config = {"extra": "forbid"}

    event: CloudEvent
    provenance: EventProvenance
    signature: EventSignature
    # Idempotency key for consumers that act on the event; defaults to the event id.
    execution_id: str = ""

    @model_validator(mode="after")
    def _default_execution_id(self) -> SignedEvent:
        if not self.execution_id:
            self.execution_id = self.event.id
        return self

    def signed_payload(self) -> dict[str, Any]:
        """Everything the signature covers: the whole envelope except the signature."""
        return signed_payload(self.event, self.provenance, self.execution_id)


def signed_payload(
    event: CloudEvent, provenance: EventProvenance, execution_id: str
) -> dict[str, Any]:
    return {
        "event": event.model_dump(mode="json", exclude_none=True),
        "provenance": provenance.model_dump(mode="json", exclude_none=True),
        "execution_id": execution_id,
    }
