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
    return text if text in SEVERITY_RANK else str(value)


def severity_rank(value):
    return SEVERITY_RANK.get(normalize_severity(value), 0)


def highest_severity(values):
    values = [normalize_severity(v) for v in values if v]
    return sorted(values or ["Unknown"], key=severity_rank, reverse=True)[0]
