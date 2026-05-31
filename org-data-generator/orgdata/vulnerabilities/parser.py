def grype_matches(grype_data):
    matches = grype_data.get("matches") or []
    return matches if isinstance(matches, list) else []
