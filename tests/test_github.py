import json

from eventflow_kit import from_wire, sign_event, to_wire
from eventflow_kit.github import (
    GitHubWebhook,
    build_cloudevent,
    build_provenance,
    compute_signature,
    verify_signature,
)

SECRET = "webhook-secret"
BODY = {
    "action": "opened",
    "repository": {"id": 1, "full_name": "darkflib/example"},
    "installation": {"id": 42},
}
RAW = json.dumps(BODY).encode()


def test_verify_signature():
    header = compute_signature(SECRET, RAW)
    # GitHub's documented test vector shape: sha256=<64 hex chars>
    assert header.startswith("sha256=") and len(header) == 71
    assert verify_signature(SECRET, RAW, header)
    assert not verify_signature(SECRET, RAW + b" ", header)
    assert not verify_signature("other", RAW, header)


def test_verify_signature_rejects_bad_input_without_raising():
    assert not verify_signature(SECRET, RAW, None)
    assert not verify_signature(SECRET, RAW, "")
    assert not verify_signature(SECRET, RAW, "sha256=ünïcode")
    assert not verify_signature("", RAW, compute_signature("", RAW))


def test_known_vector():
    # From GitHub's "Validating webhook deliveries" docs.
    expected = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    assert compute_signature("It's a Secret to Everybody", b"Hello, World!") == expected


def test_build_cloudevent():
    webhook = GitHubWebhook(delivery="abc-123", event="pull_request", body=BODY)
    event = build_cloudevent(webhook)
    assert event.id == "abc-123"
    assert event.type == "github.pull_request"
    assert event.source == "urn:github:darkflib/example"
    assert event.subject == "opened"
    assert event.extensions == {
        "github_delivery": "abc-123",
        "github_event": "pull_request",
        "github_repository": "darkflib/example",
        "github_installation_id": 42,
    }


def test_ping_without_repository():
    event = build_cloudevent(GitHubWebhook(delivery="p1", event="ping", body={"zen": "x"}))
    assert event.source == "urn:github:unknown" and event.subject is None
    assert "github_repository" not in event.extensions


def test_webhook_to_wire_and_back():
    webhook = GitHubWebhook(delivery="abc-123", event="push", body=BODY)
    provenance = build_provenance(webhook, zone="ams01")
    signed = sign_event(build_cloudevent(webhook), provenance, secret=b"sign-secret", key_id="in")
    received = from_wire(to_wire(signed), {"in": b"sign-secret"})
    assert received.event.data == BODY
    assert received.provenance.trace_id == "abc-123" and received.provenance.trust_level == "low"
