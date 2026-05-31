"""
Shared severity normalization helpers.

Provides normalized severity values, severity ranking, highest-severity logic,
and empty severity count templates used by findings and indexes.
"""

SEVERITIES = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]

SEVERITY_RANK = {
    "Unknown": 0,
    "Negligible": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5,
}


def normalize_severity(value):
    if not value:
        return "Unknown"
    text = str(value).strip().capitalize()
    return text if text in SEVERITY_RANK else "Unknown"


def severity_rank(value):
    return SEVERITY_RANK.get(normalize_severity(value), 0)


def highest_severity(values):
    values = [normalize_severity(v) for v in values if v]
    return sorted(values or ["Unknown"], key=severity_rank, reverse=True)[0]


def empty_severity_counts():
    return {severity: 0 for severity in SEVERITIES}
