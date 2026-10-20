import json
from datetime import datetime, timezone
from typing import Any

from flask import current_app

from ..extensions import db
from ..models import EventOutbox


def relay_pending(limit: int = 50) -> dict[str, Any]:
    stream_url = current_app.config.get("REDIS_URL", "")
    pending_query = EventOutbox.query.filter_by(status="pending").order_by(EventOutbox.occurred_at.asc())
    pending_before = pending_query.count()
    if not stream_url:
        return {"configured": False, "connected": False, "published": 0, "pending": pending_before, "error": None}

    try:
        from redis import Redis

        client = Redis.from_url(stream_url, socket_connect_timeout=0.4, socket_timeout=0.6, decode_responses=True)
        client.ping()
    except Exception as exc:
        return {"configured": True, "connected": False, "published": 0, "pending": pending_before, "error": str(exc)[:180]}

    rows = pending_query.limit(max(1, min(limit, 200))).all()
    published = 0
    for item in rows:
        try:
            entry_id = client.xadd(
                current_app.config.get("REDIS_STREAM", "zerotrace:events"),
                {
                    "event_id": item.id,
                    "event_type": item.event_type,
                    "schema_version": str(item.schema_version),
                    "entity_type": item.entity_type,
                    "entity_id": item.entity_id,
                    "occurred_at": item.occurred_at.isoformat(),
                    "correlation_id": item.correlation_id,
                    "payload": json.dumps(item.payload or {}, sort_keys=True, separators=(",", ":")),
                },
            )
            item.status = "published"
            item.redis_entry_id = entry_id
            item.published_at = datetime.now(timezone.utc)
            item.attempts += 1
            item.last_error = None
            published += 1
        except Exception as exc:
            item.attempts += 1
            item.last_error = str(exc)[:512]
            break
    db.session.commit()
    pending_after = EventOutbox.query.filter_by(status="pending").count()
    return {"configured": True, "connected": True, "published": published, "pending": pending_after, "error": None}


def bus_status() -> dict[str, Any]:
    configured = bool(current_app.config.get("REDIS_URL"))
    pending = EventOutbox.query.filter_by(status="pending").count()
    if not configured:
        return {"configured": False, "connected": False, "state": "not_configured", "pending": pending}
    try:
        from redis import Redis

        client = Redis.from_url(current_app.config["REDIS_URL"], socket_connect_timeout=0.4, socket_timeout=0.6, decode_responses=True)
        client.ping()
        state = "connected"
    except Exception:
        state = "degraded"
    return {"configured": True, "connected": state == "connected", "state": state, "pending": pending}
