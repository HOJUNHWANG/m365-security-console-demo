def finding(severity: str, en: str, ko: str) -> dict:
    return {"severity": severity, "text": en, "textEn": en, "textKo": ko}


def unavailable(en: str, ko: str) -> dict:
    return {"available": False, "reason": en, "reasonEn": en, "reasonKo": ko}
