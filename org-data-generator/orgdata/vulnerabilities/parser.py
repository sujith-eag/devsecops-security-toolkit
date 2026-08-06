"""
Small parser helpers for Grype JSON vulnerability output.

Currently exposes Grype match extraction while keeping raw Grype parsing details
separate from vulnerability normalization logic.
"""

def grype_matches(grype_data):
    matches = grype_data.get("matches") or []
    return matches if isinstance(matches, list) else []
