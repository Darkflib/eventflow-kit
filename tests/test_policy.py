import pytest
from pydantic import ValidationError

from eventflow_kit import (
    CloudEvent,
    EventProvenance,
    MessagePolicyEngine,
    load_rules,
    sign_event,
)

RULES = {
    "rules": [
        {
            "source_zone": "*",
            "event_pattern": "deploy.prod.*",
            "dest_zone": "prod",
            "action_class": "control",
            "allow": False,
            "reason": "no prod deploys by event",
        },
        {
            "source_zone": "staging",
            "source_trust": "high",
            "event_pattern": "deploy.*",
            "dest_zone": "*",
            "action_class": "control",
        },
        {
            "source_zone": "*",
            "event_pattern": "github.*",
            "dest_zone": "homelab",
            "action_class": "notify",
        },
    ]
}


def _evaluate(engine, **overrides):
    args = {
        "source_zone": "staging",
        "source_trust": "high",
        "event_type": "deploy.started",
        "dest_zone": "staging",
        "action_class": "control",
    }
    return engine.evaluate(**{**args, **overrides})


def test_empty_engine_denies():
    result = _evaluate(MessagePolicyEngine())
    assert not result.allowed and result.matched_rule is None
    assert result.reason.startswith("default deny")


def test_allow_and_each_mismatch_denies():
    engine = MessagePolicyEngine(load_rules(RULES))
    assert _evaluate(engine).matched_rule == 1
    assert _evaluate(engine).allowed
    assert not _evaluate(engine, source_zone="homelab").allowed
    assert not _evaluate(engine, source_trust="medium").allowed
    assert not _evaluate(engine, event_type="balance.checked").allowed
    assert not _evaluate(engine, action_class="notify").allowed


def test_first_match_wins_so_explicit_deny_precedes_allow():
    engine = MessagePolicyEngine(load_rules(RULES))
    result = _evaluate(engine, event_type="deploy.prod.api", dest_zone="prod")
    assert not result.allowed
    assert result.reason == "no prod deploys by event" and result.matched_rule == 0


def test_patterns_are_case_sensitive():
    engine = MessagePolicyEngine(load_rules(RULES))
    assert not _evaluate(engine, event_type="DEPLOY.started").allowed


def test_evaluate_event_uses_signed_provenance():
    engine = MessagePolicyEngine(load_rules(RULES))
    event = CloudEvent(id="d1", source="urn:github:a/b", type="github.push")
    provenance = EventProvenance(ingress="github-webhook", trace_id="d1", zone="ams01")
    signed = sign_event(event, provenance, secret=b"supersecret", key_id="k1")
    assert engine.evaluate_event(signed, dest_zone="homelab", action_class="notify").allowed
    assert not engine.evaluate_event(signed, dest_zone="homelab", action_class="control").allowed


@pytest.mark.parametrize(
    "bad",
    [
        {"source_zone": "a", "event_pattern": "*", "dest_zone": "b"},
        {"source_zone": "a", "event_pattern": "*", "dest_zone": "b", "action_class": "destroy"},
        {
            "source_zone": "a",
            "event_pattern": "*",
            "dest_zone": "b",
            "action_class": "notify",
            "alow": True,
        },
    ],
)
def test_invalid_rule_fails_the_whole_load(bad):
    with pytest.raises(ValidationError):
        load_rules({"rules": [RULES["rules"][1], bad]})
