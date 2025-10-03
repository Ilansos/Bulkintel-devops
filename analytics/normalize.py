import ipaddress, re
from urllib.parse import urlsplit, urlunsplit

def normalize_ip(ip_str: str):
    ip = ipaddress.ip_address(ip_str.strip())
    return ip.compressed, (6 if ip.version == 6 else 4)

def normalize_domain(dom: str):
    s = dom.strip().rstrip(".").lower()
    # cheap sanity; you already have validators elsewhere
    return s

def normalize_url(u: str):
    u = u.strip()
    p = urlsplit(u)
    # normalize scheme/host case + drop default ports
    scheme = (p.scheme or "http").lower()
    netloc = p.hostname.lower() if p.hostname else ""
    if p.port and not ((scheme == "http" and p.port == 80) or (scheme == "https" and p.port == 443)):
        netloc = f"{netloc}:{p.port}"
    path   = p.path or "/"
    return urlunsplit((scheme, netloc, path, p.query, ""))

def normalize_user_agent(ua: str):
    # keep as-is or `.strip()` only; case is meaningful in UA strings
    return ua.strip()

def normalize_hash(hash: str):
    return hash.strip()
