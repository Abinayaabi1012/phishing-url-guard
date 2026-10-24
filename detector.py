import re
import ipaddress
from urllib.parse import urlparse, unquote

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"
}
SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account", "update",
    "password", "wallet", "banking", "signin", "confirm", "gift", "free",
    "prize", "urgent", "suspend", "recover", "invoice", "payment"
}
BRANDS = {
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "instagram", "netflix", "whatsapp", "outlook", "bank"
}

def _normalise(raw):
    raw = raw.strip()
    if not raw:
        raise ValueError("Please enter a URL.")
    if any(ch.isspace() for ch in raw):
        raise ValueError("The URL contains spaces. Paste a complete URL.")
    candidate = raw if "://" in raw else "https://" + raw
    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid web URL, such as https://example.com.")
    try:
        parsed.hostname.encode("idna")
    except Exception:
        raise ValueError("The domain name does not look valid.")
    return candidate, parsed

def analyze_url(raw):
    url, parsed = _normalise(raw)
    host = (parsed.hostname or "").lower().rstrip(".")
    path_query = unquote((parsed.path or "") + "?" + (parsed.query or "")).lower()
    full = url.lower()
    flags = []
    score = 0

    def flag(points, message):
        nonlocal score
        score += points
        flags.append(message)

    if parsed.scheme == "http":
        flag(12, "Uses HTTP instead of encrypted HTTPS.")
    if "@" in parsed.netloc:
        flag(25, "Contains an @ symbol in the URL authority, which can disguise the destination.")
    try:
        ipaddress.ip_address(host)
        flag(25, "Uses a raw IP address instead of a domain name.")
    except ValueError:
        pass
    if len(url) > 100:
        flag(10, "Unusually long URL.")
    if len(host) > 35:
        flag(8, "Unusually long domain name.")
    if host.count(".") >= 4:
        flag(10, "Contains many subdomains.")
    if re.search(r"xn--", host):
        flag(15, "Contains an internationalized/punycode domain that may be used for lookalike names.")
    if re.search(r"\d{5,}", host):
        flag(8, "Domain contains a long sequence of digits.")
    if any(ch in host for ch in ["-", "_"]):
        flag(5, "Domain contains unusual punctuation.")
    if host in SHORTENERS:
        flag(12, "Uses a URL-shortening service, which hides the final destination.")
    found_words = sorted(word for word in SUSPICIOUS_WORDS if word in host or word in path_query)
    if found_words:
        flag(min(24, 6 + 3 * len(found_words)), "Contains potentially deceptive terms: " + ", ".join(found_words[:5]) + ".")
    brand_matches = [brand for brand in BRANDS if brand in host and not host == brand + ".com"]
    if brand_matches:
        flag(18, "Mentions a recognizable brand in a domain that is not its exact common .com domain: " + ", ".join(brand_matches[:3]) + ".")
    if host.count("-") >= 2:
        flag(8, "Domain uses multiple hyphens.")
    if parsed.username or parsed.password:
        flag(25, "Includes user-information before the host name, a common URL deception technique.")

    score = min(score, 100)
    if score >= 35:
        verdict, level = "Potential Phishing", "high"
        summary = "This URL has multiple warning signs. Avoid entering passwords, payment details, or personal information."
    elif score >= 18:
        verdict, level = "Suspicious — Be Careful", "medium"
        summary = "Some warning signs were detected. Verify the domain independently before continuing."
    else:
        verdict, level = "No Obvious Warning Signs", "low"
        summary = "The basic URL checks did not find strong warning signs. This does not prove the site is safe."

    if not flags:
        flags = ["No obvious warning patterns were found by the basic URL checks."]
    return {
        "input_url": raw,
        "normalized_url": url,
        "hostname": host,
        "verdict": verdict,
        "risk_level": level,
        "risk_score": score,
        "summary": summary,
        "signals": flags,
        "disclaimer": "Prototype screening only. It does not visit the URL or query a live threat-intelligence database. Never treat a low-risk result as a guarantee of safety."
    }
