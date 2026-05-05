import re
import socket
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup


REQUEST_TIMEOUT = 6

KNOWN_DOMAINS = [
    "google", "youtube", "facebook", "twitter", "instagram",
    "microsoft", "apple", "amazon", "github", "linkedin",
    "wikipedia", "reddit", "netflix", "stackoverflow", "paypal",
    "ebay", "yahoo", "bing", "dropbox", "icloud", "adobe",
    "wordpress", "shopify", "whatsapp", "telegram"
]


def check_dns(domain):
    try:
        socket.setdefaulttimeout(5)
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False


def fetch_page(url):
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        redirect_count = len(response.history)
        return response.text, response.url, redirect_count
    except requests.RequestException:
        return None, None, 0


def extract_url_only_features(url, parsed, domain, path, full):
    """
    Extracts features using URL structure only — used when page
    cannot be fetched (e.g. site is down or blocking requests).
    Page-level features are set to neutral (0) since we have no HTML.
    """
    features = {}

    features["having_IPhaving_IP_Address"] = (
        -1 if re.search(r'\d{1,3}(\.\d{1,3}){3}', domain) else 1
    )

    url_len = len(url)
    features["URLURL_Length"] = 1 if url_len < 54 else (0 if url_len <= 75 else -1)

    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "rb.gy"]
    features["Shortining_Service"] = -1 if any(s in full for s in shorteners) else 1

    features["having_At_Symbol"] = -1 if "@" in url else 1

    features["double_slash_redirecting"] = -1 if "//" in path else 1

    features["Prefix_Suffix"] = -1 if "-" in domain else 1

    dot_count = domain.count(".")
    features["having_Sub_Domain"] = 1 if dot_count == 1 else (0 if dot_count == 2 else -1)

    features["SSLfinal_State"] = 1 if url.startswith("https") else -1

    has_digits_in_domain = bool(re.search(r'\d', domain.split(".")[0]))
    features["Domain_registeration_length"] = -1 if has_digits_in_domain else 1

    features["Favicon"] = 1

    port = parsed.port
    features["port"] = -1 if (port and port not in [80, 443]) else 1

    features["HTTPS_token"] = -1 if "https" in domain.lower() else 1

    # Page content features — neutral since no HTML available
    features["Request_URL"] = 0
    features["URL_of_Anchor"] = 0
    features["Links_in_tags"] = 0
    features["SFH"] = 0
    features["Submitting_to_email"] = 1
    features["Abnormal_URL"] = 0
    features["Redirect"] = 0
    features["on_mouseover"] = 1
    features["RightClick"] = 1
    features["popUpWidnow"] = 1
    features["Iframe"] = 1

    suspicious_domain_pattern = bool(re.search(r'(\d{4,}|[a-z]+-[a-z]+-[a-z]+)', domain))
    features["age_of_domain"] = -1 if suspicious_domain_pattern else 1

    features["DNSRecord"] = 1

    is_known = any(k in domain for k in KNOWN_DOMAINS)
    features["web_traffic"] = 1 if is_known else 0
    features["Page_Rank"] = 1 if is_known else 0
    features["Google_Index"] = 1 if is_known else 0
    features["Links_pointing_to_page"] = 0

    phishing_keywords = ["phish", "malware", "spyware", "ransomware"]
    features["Statistical_report"] = (
        -1 if any(k in full for k in phishing_keywords) else 1
    )

    features["_status"] = "ok"
    return features


def extract_features(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "")
        path = parsed.path
        full = url.lower()
    except Exception:
        return {"_status": "invalid_url"}

    if not domain:
        return {"_status": "invalid_url"}

    # Gate 1: DNS check — does this domain exist at all?
    if not check_dns(domain):
        return {"_status": "dns_fail"}

    # Gate 2: Fetch live page
    html, final_url, redirect_count = fetch_page(url)

    # If page can't be fetched, fall back to URL-only feature extraction
    # instead of returning fetch_fail — this way we still get a classification
    if html is None:
        return extract_url_only_features(url, parsed, domain, path, full)

    # Full feature extraction with live page content
    soup = BeautifulSoup(html, "html.parser")
    features = {}

    # 1. IP address in URL
    features["having_IPhaving_IP_Address"] = (
        -1 if re.search(r'\d{1,3}(\.\d{1,3}){3}', domain) else 1
    )

    # 2. URL length
    url_len = len(url)
    features["URLURL_Length"] = 1 if url_len < 54 else (0 if url_len <= 75 else -1)

    # 3. Shortening service
    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "rb.gy"]
    features["Shortining_Service"] = -1 if any(s in full for s in shorteners) else 1

    # 4. @ symbol
    features["having_At_Symbol"] = -1 if "@" in url else 1

    # 5. Double slash redirect
    features["double_slash_redirecting"] = -1 if "//" in path else 1

    # 6. Hyphen in domain
    features["Prefix_Suffix"] = -1 if "-" in domain else 1

    # 7. Sub-domain count
    dot_count = domain.count(".")
    features["having_Sub_Domain"] = 1 if dot_count == 1 else (0 if dot_count == 2 else -1)

    # 8. SSL — highest importance feature (32.6%)
    features["SSLfinal_State"] = 1 if url.startswith("https") else -1

    # 9. Domain registration length
    has_digits_in_domain = bool(re.search(r'\d', domain.split(".")[0]))
    features["Domain_registeration_length"] = -1 if has_digits_in_domain else 1

    # 10. Favicon
    favicon_tag = soup.find("link", rel=lambda r: r and "icon" in r)
    if favicon_tag and favicon_tag.get("href"):
        fav_href = favicon_tag["href"]
        features["Favicon"] = -1 if fav_href.startswith("http") and domain not in fav_href else 1
    else:
        features["Favicon"] = 1

    # 11. Port
    port = parsed.port
    features["port"] = -1 if (port and port not in [80, 443]) else 1

    # 12. HTTPS token in domain name
    features["HTTPS_token"] = -1 if "https" in domain.lower() else 1

    # 13. Request URL — ratio of external resources
    total_resources = 0
    external_resources = 0
    for tag in soup.find_all(["img", "script", "link"]):
        src = tag.get("src") or tag.get("href") or ""
        if src:
            total_resources += 1
            if src.startswith("http") and domain not in src:
                external_resources += 1
    if total_resources > 0:
        ext_ratio = external_resources / total_resources
        features["Request_URL"] = 1 if ext_ratio < 0.22 else (0 if ext_ratio <= 0.61 else -1)
    else:
        features["Request_URL"] = 1

    # 14. URL of Anchor — second highest importance (24.5%)
    anchors = soup.find_all("a", href=True)
    suspicious_anchors = 0
    for a in anchors:
        href = a["href"].strip().lower()
        if (href in ["#", "#content", "#skip", "javascript::void(0)", ""]
                or href.startswith("javascript")
                or (href.startswith("http") and domain not in href)):
            suspicious_anchors += 1
    if anchors:
        anchor_ratio = suspicious_anchors / len(anchors)
        features["URL_of_Anchor"] = 1 if anchor_ratio < 0.31 else (0 if anchor_ratio <= 0.67 else -1)
    else:
        features["URL_of_Anchor"] = 0

    # 15. Links in tags
    meta_script_link = soup.find_all(["meta", "script", "link"])
    ext_tag_count = sum(
        1 for t in meta_script_link
        if (t.get("src") or t.get("href") or "")
        and domain not in (t.get("src") or t.get("href") or "")
        and (t.get("src") or t.get("href") or "").startswith("http")
    )
    tag_ratio = ext_tag_count / len(meta_script_link) if meta_script_link else 0
    features["Links_in_tags"] = 1 if tag_ratio < 0.17 else (0 if tag_ratio <= 0.81 else -1)

    # 16. Server form handler
    forms = soup.find_all("form")
    sfh_suspicious = False
    for form in forms:
        action = form.get("action", "").strip().lower()
        if action in ["", "about:blank"]:
            sfh_suspicious = True
        elif action.startswith("http") and domain not in action:
            sfh_suspicious = True
    features["SFH"] = -1 if sfh_suspicious else 1

    # 17. Submitting to email
    features["Submitting_to_email"] = (
        -1 if any("mailto:" in (f.get("action", "").lower()) for f in forms) else 1
    )

    # 18. Abnormal URL — domain mismatch after redirect
    if final_url:
        final_domain = urlparse(final_url).netloc.replace("www.", "")
        features["Abnormal_URL"] = -1 if final_domain != domain else 1
    else:
        features["Abnormal_URL"] = 1

    # 19. Redirect count
    features["Redirect"] = 0 if redirect_count == 0 else (1 if redirect_count == 1 else -1)

    # 20. onMouseOver
    features["on_mouseover"] = (
        -1 if "onmouseover" in html.lower() and "window.status" in html.lower() else 1
    )

    # 21. Right click disabled
    features["RightClick"] = (
        -1 if "contextmenu" in html.lower() and "return false" in html.lower() else 1
    )

    # 22. Popup window
    features["popUpWidnow"] = (
        -1 if "window.open" in html.lower() and "prompt(" in html.lower() else 1
    )

    # 23. iFrame
    iframes = soup.find_all("iframe")
    hidden_iframe = any(
        "display:none" in (f.get("style") or "").replace(" ", "").lower()
        or f.get("width") == "0" or f.get("height") == "0"
        for f in iframes
    )
    features["Iframe"] = -1 if hidden_iframe else (0 if iframes else 1)

    # 24. Age of domain
    suspicious_domain_pattern = bool(re.search(r'(\d{4,}|[a-z]+-[a-z]+-[a-z]+)', domain))
    features["age_of_domain"] = -1 if suspicious_domain_pattern else 1

    # 25. DNS record — already passed DNS check
    features["DNSRecord"] = 1

    # 26. Web traffic
    is_known = any(k in domain for k in KNOWN_DOMAINS)
    features["web_traffic"] = 1 if is_known else 0

    # 27. Page rank
    features["Page_Rank"] = 1 if is_known else 0

    # 28. Google index
    google_signals = ["google-analytics", "googletagmanager", "gtag(", "UA-", "G-"]
    features["Google_Index"] = 1 if any(s in html for s in google_signals) else 0

    # 29. Links pointing to page
    internal_links = sum(1 for a in anchors if domain in (a.get("href") or ""))
    features["Links_pointing_to_page"] = (
        1 if internal_links > 2 else (0 if internal_links > 0 else -1)
    )

    # 30. Statistical report
    phishing_keywords = ["phish", "malware", "spyware", "ransomware"]
    features["Statistical_report"] = (
        -1 if any(k in full for k in phishing_keywords) else 1
    )

    features["_status"] = "ok"
    return features
