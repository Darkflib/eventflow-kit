import json

import pytest

from eventflow_kit import (
    CloudEvent,
    EventProvenance,
    SignatureError,
    from_wire,
    sign_event,
    to_wire,
    verify_event,
)

KEYS = {"k1": b"supersecret-one", "k2": b"supersecret-two"}


def _signed(**kwargs):
    event = CloudEvent(id="d1", source="urn:test", type="test.thing", data={"n": 1, "s": "naïve ☃"})
    provenance = EventProvenance(ingress="test", trace_id="d1", zone="homelab", trust_level="high")
    return sign_event(event, provenance, secret=KEYS["k1"], key_id="k1", **kwargs)


def test_wire_round_trip_verifies():
    signed = _signed()
    assert from_wire(to_wire(signed), KEYS) == signed
    assert from_wire(to_wire(signed).encode(), KEYS).execution_id == "d1"


def test_hs512_and_explicit_execution_id():
    signed = _signed(algorithm="HS512", execution_id="run-7")
    assert from_wire(to_wire(signed), KEYS).execution_id == "run-7"


@pytest.mark.parametrize(
    "path, value",
    [
        (("event", "type"), "test.other"),
        (("event", "data"), {"n": 2}),
        (("provenance", "zone"), "prod"),
        (("provenance", "trust_level"), "low"),
        (("execution_id",), "other"),
        (("signature", "algorithm"), "HS512"),
    ],
)
def test_any_altered_field_fails(path, value):
    wire = json.loads(to_wire(_signed()))
    target = wire
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(SignatureError, match="mismatch"):
        from_wire(json.dumps(wire), KEYS)


def test_unknown_key_and_wrong_key():
    signed = _signed()
    with pytest.raises(SignatureError, match="unknown key_id"):
        verify_event(signed, {"k2": KEYS["k2"]})
    with pytest.raises(SignatureError, match="mismatch"):
        verify_event(signed, {"k1": KEYS["k2"]})
    with pytest.raises(SignatureError, match="unknown key_id"):
        verify_event(signed, {"k1": b""})


@pytest.mark.parametrize("payload", ["not json", "{}", '{"event": {"id": "x"}}'])
def test_malformed_wire_is_a_signature_error(payload):
    with pytest.raises(SignatureError, match="malformed"):
        from_wire(payload, KEYS)


def test_unsigned_flattened_payload_is_rejected():
    # The old eventflow-core sinks published the signed payload without the signature.
    with pytest.raises(SignatureError):
        from_wire(json.dumps(_signed().signed_payload()), KEYS)


def test_empty_secret_refused():
    event = CloudEvent(id="d1", source="urn:test", type="t")
    with pytest.raises(ValueError):
        sign_event(event, EventProvenance(ingress="t", trace_id="d1"), secret=b"", key_id="k1")


def test_naive_time_is_treated_as_utc():
    event = CloudEvent(id="d1", source="urn:test", type="t", time="2025-01-02T03:04:05")
    assert event.time.utcoffset().total_seconds() == 0
