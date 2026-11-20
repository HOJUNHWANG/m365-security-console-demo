from urllib.parse import urlparse

LOCAL_NAMES = {"127.0.0.1", "localhost", "::1"}
LOOPBACK = {"127.0.0.1", "::1"}
REMOTE_MARKERS = ("cf-ray", "cf-connecting-ip", "cf-access-jwt-assertion", "cf-access-authenticated-user-email",
                  "cf-ipcountry", "cf-visitor", "x-forwarded-for", "x-forwarded-host", "forwarded")
EDIT_HEADER = "x-dashboard-edit"


def _host(value: str) -> str:
    v = (value or "").strip().lower()
    if v.startswith("["):
        return v[1:v.find("]")] if "]" in v else v.strip("[]")
    return v.rsplit(":", 1)[0] if v.count(":") == 1 else v


def is_local(headers: dict, client_host: str) -> bool:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    if any(m in h for m in REMOTE_MARKERS):
        return False
    return _host(h.get("host", "")) in LOCAL_NAMES and (client_host or "") in LOOPBACK


def check_write(headers: dict, client_host: str) -> tuple[bool, str]:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    if not is_local(h, client_host):
        return False, "remote"
    if h.get(EDIT_HEADER) != "1":
        return False, "missing-edit-header"
    origin = h.get("origin")
    if origin and (urlparse(origin).hostname or "").lower() not in LOCAL_NAMES:
        return False, "cross-origin"
    return True, "local"
