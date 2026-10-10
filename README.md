# eventflow-kit

The parts of `eventflow-core` worth keeping, as a library to import into a service rather
than a platform to run. One dependency (pydantic).

| Module | What it does |
|---|---|
| `envelope`, `signing` | A CloudEvent with provenance and an HMAC signature over both. |
| `policy` | Default-deny rules: may this event go to that zone for that class of action? |
| `github` | Verify a GitHub webhook and normalise it into a CloudEvent. |
| `notify` | Post to the notification hub (apprise-api), as the gitops units do. |

## Events

```python
from eventflow_kit import CloudEvent, EventProvenance, sign_event, to_wire, from_wire

signed = sign_event(
    CloudEvent(id="d1", source="urn:balance-monitor", type="balance.low", data={"usd": "4.20"}),
    EventProvenance(ingress="balance-monitor", trace_id="d1", zone="ams01"),
    secret=secret,
    key_id="monitor-2026",
)
payload = to_wire(signed)  # publish this string
event = from_wire(payload, {"monitor-2026": secret})  # raises SignatureError
```

`to_wire` and `from_wire` are the only wire format, and `from_wire` always verifies: there
is no way to read an event off a queue without checking it. The signature covers the event,
its provenance and `execution_id`. Rotate keys by adding a new `key_id` to the keyring.

## GitHub webhooks

```python
from eventflow_kit.github import GitHubWebhook, build_cloudevent, build_provenance, verify_signature

if not verify_signature(webhook_secret, raw_body, request.headers.get("X-Hub-Signature-256")):
    raise HTTPException(403)
webhook = GitHubWebhook(delivery=delivery, event=event, body=json.loads(raw_body))
signed = sign_event(build_cloudevent(webhook), build_provenance(webhook, zone="ams01"), ...)
```

The delivery id becomes the event id, so GitHub redeliveries deduplicate downstream.

## Policy

```python
from eventflow_kit import MessagePolicyEngine, load_rules

engine = MessagePolicyEngine(load_rules(json.load(open("policy.json"))))
result = engine.evaluate_event(event, dest_zone="homelab", action_class="notify")
if not result.allowed:
    ...
```

First matching rule wins; no match is a deny. An invalid rule fails the whole load.

## Notifications

```python
from eventflow_kit import notify

notify("Namecheap balance low", "$4.20 remaining", type="warning")
```

Posts `{title, body, type, tag: "alerts"}` to `$NOTIFY_URL`, the same contract as
`quadlet/bin/alert.py` in gitops. On `ops.network` that is `http://notify:8000/notify/infra`;
on the host, `http://127.0.0.1:8094/notify/infra`. `type` is `info`, `success`, `warning` or
`failure`. With no URL set it does nothing; it returns `False` rather than raising. It
blocks, so from async code use `await asyncio.to_thread(notify, ...)`.

## Development

```bash
uv run pytest && uv run ruff check . && uv run mypy
```
