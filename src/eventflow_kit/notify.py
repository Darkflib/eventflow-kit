"""Post to the notification hub (apprise-api), the one place alerts go.

Same contract as gitops' quadlet/bin/alert.py: a JSON POST of title, body, type and tag to
the hub's /notify/<key> URL. Standard library only; a failure to notify is logged and
never raises.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from typing import Literal

logger = logging.getLogger(__name__)

NotifyType = Literal["info", "success", "warning", "failure"]

URL_ENV = "NOTIFY_URL"
# apprise-api refuses untagged requests; every line of the hub's config carries this tag.
DEFAULT_TAG = "alerts"
MAX_BODY_CHARS = 3000


def notify(
    title: str,
    body: str = "",
    *,
    type: NotifyType = "info",
    tag: str = DEFAULT_TAG,
    url: str | None = None,
    timeout: float = 10.0,
) -> bool:
    """Send one notification. Returns False, without raising, if it could not be sent.

    `url` defaults to $NOTIFY_URL, e.g. http://notify:8000/notify/infra on ops.network.
    With no URL configured this is a no-op. Blocking: from async code, call it through
    `asyncio.to_thread`.
    """
    url = url or os.environ.get(URL_ENV)
    if not url:
        return False
    if not url.startswith(("http://", "https://")):
        logger.error("notify: %s must be an http(s) URL", URL_ENV)
        return False
    if len(body) > MAX_BODY_CHARS:
        body = body[: MAX_BODY_CHARS - 1] + "…"
    payload = {"title": title, "body": body or title, "type": type, "tag": tag}
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(request, timeout=timeout).close()  # noqa: S310
    except (OSError, ValueError) as exc:
        logger.warning("notify: couldn't reach the hub: %s", exc)
        return False
    return True
