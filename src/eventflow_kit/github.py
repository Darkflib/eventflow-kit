"""Verify GitHub webhooks and normalise them into CloudEvents."""

from __future__ import annotations

import hashlib
import hmac

from pydantic import BaseModel, Field, JsonValue

from .envelope import CloudEvent, EventProvenance, TrustLevel


def compute_signature(secret: str, raw_body: bytes) -> str:
    """The `sha256=...` value GitHub sends in X-Hub-Signature-256."""
    return "sha256=" + hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()


def verify_signature(secret: str, raw_body: bytes, header: str | None) -> bool:
    """Check X-Hub-Signature-256 against the raw request body."""
    if not secret or not header:
        return False
    expected = compute_signature(secret, raw_body)
    # Compare bytes: compare_digest raises on a non-ASCII str, which a caller controls.
    return hmac.compare_digest(expected.encode(), header.encode("utf-8", "replace"))


class GitHubWebhook(BaseModel):
    """A verified webhook: the delivery and event headers plus the JSON body."""

    delivery: str = Field(min_length=1, description="X-GitHub-Delivery")
    event: str = Field(min_length=1, description="X-GitHub-Event")
    body: dict[str, JsonValue]

    @property
    def repository(self) -> str | None:
        repository = self.body.get("repository")
        if isinstance(repository, dict):
            full_name = repository.get("full_name")
            if isinstance(full_name, str) and full_name:
                return full_name
        return None

    @property
    def action(self) -> str | None:
        action = self.body.get("action")
        return action if isinstance(action, str) and action.strip() else None


def build_cloudevent(webhook: GitHubWebhook) -> CloudEvent:
    """The delivery id becomes the event id, so redeliveries deduplicate downstream."""
    extensions: dict[str, JsonValue] = {
        "github_delivery": webhook.delivery,
        "github_event": webhook.event,
    }
    if webhook.repository:
        extensions["github_repository"] = webhook.repository
    installation = webhook.body.get("installation")
    if isinstance(installation, dict) and isinstance(installation.get("id"), int):
        extensions["github_installation_id"] = installation["id"]
    return CloudEvent(
        id=webhook.delivery,
        source=f"urn:github:{webhook.repository or 'unknown'}",
        type=f"github.{webhook.event}",
        subject=webhook.action,
        datacontenttype="application/json",
        data=webhook.body,
        extensions=extensions,
    )


def build_provenance(
    webhook: GitHubWebhook,
    *,
    zone: str,
    caller_id: str = "github-ingress",
    trust_level: TrustLevel = "low",
) -> EventProvenance:
    return EventProvenance(
        ingress="github-webhook",
        trace_id=webhook.delivery,
        zone=zone,
        caller_id=caller_id,
        trust_level=trust_level,
    )
