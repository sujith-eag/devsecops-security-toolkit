"""Stable ID helpers for production index records.

Indexes keep canonical IDs from org-data, but also add route-safe and display
IDs so UI/API consumers do not need to handle raw PURLs directly in URLs.
"""

import base64
import hashlib
from urllib.parse import unquote


def canonical_id(value):
    return str(value or "")


def display_id(value):
    return unquote(canonical_id(value))


def route_id(value):
    raw = canonical_id(value).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def id_hash(value):
    return hashlib.sha256(canonical_id(value).encode("utf-8")).hexdigest()[:16]


def id_fields(value, entity_type):
    cid = canonical_id(value)
    return {
        "canonical_id": cid,
        "display_id": display_id(cid),
        "route_id": route_id(cid),
        "id_hash": id_hash(cid),
        "entity_type": entity_type,
    }