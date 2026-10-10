"""Default-deny message policy: may this event go to that zone for that class of action?"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from fnmatch import fnmatchcase
from typing import Any, Literal

from pydantic import BaseModel, Field

from .envelope import SignedEvent, TrustLevel

ActionClass = Literal["observe", "notify", "control"]


class MessagePolicyRule(BaseModel):
    """One rule. Zones and event types are fnmatch patterns; first matching rule wins."""

    model_config = {"extra": "forbid"}

    source_zone: str = Field(min_length=1)
    source_trust: TrustLevel | None = None
    event_pattern: str = Field(min_length=1)
    dest_zone: str = Field(min_length=1)
    action_class: ActionClass
    allow: bool = True
    reason: str | None = None


class PolicyResult(BaseModel):
    allowed: bool
    reason: str
    matched_rule: int | None = None


class MessagePolicyEngine:
    def __init__(self, rules: Iterable[MessagePolicyRule] = ()) -> None:
        self.rules = list(rules)

    def evaluate(
        self,
        *,
        source_zone: str,
        source_trust: str,
        event_type: str,
        dest_zone: str,
        action_class: str,
    ) -> PolicyResult:
        for index, rule in enumerate(self.rules):
            if (
                fnmatchcase(source_zone, rule.source_zone)
                and (rule.source_trust is None or rule.source_trust == source_trust)
                and fnmatchcase(event_type, rule.event_pattern)
                and fnmatchcase(dest_zone, rule.dest_zone)
                and rule.action_class == action_class
            ):
                return PolicyResult(
                    allowed=rule.allow,
                    reason=rule.reason or f"matched rule {index}: {rule.event_pattern}",
                    matched_rule=index,
                )
        return PolicyResult(
            allowed=False,
            reason=(
                f"default deny: no rule for {event_type} from {source_zone} "
                f"to {dest_zone} ({action_class})"
            ),
        )

    def evaluate_event(
        self, signed: SignedEvent, *, dest_zone: str, action_class: ActionClass
    ) -> PolicyResult:
        """Evaluate a verified event. Trust and zone come from its signed provenance."""
        return self.evaluate(
            source_zone=signed.provenance.zone,
            source_trust=signed.provenance.trust_level,
            event_type=signed.event.type,
            dest_zone=dest_zone,
            action_class=action_class,
        )


def load_rules(config: Mapping[str, Any]) -> list[MessagePolicyRule]:
    """Load rules from `{"rules": [...]}`. An invalid rule raises: a policy file that
    half-loads is worse than one that refuses to start."""
    return [MessagePolicyRule.model_validate(rule) for rule in config.get("rules", [])]
