import os
import re
import base64
from typing import Optional
from urllib.parse import urlparse
from datetime import datetime
import tldextract
import whois
import requests
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY", "")

SUSPICIOUS_BRANDS = [
    "paypal", "chase", "bankofamerica", "wellsfargo", "apple",
    "microsoft", "netflix", "google", "amazon", "facebook", "instagram"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "banking", "signin",
    "account", "wallet", "confirm", "security", "recover"
]

def resolve_redirects(url: str) -> tuple[str, list[str]]:
    """Follows HTTP redirects to unmask shortened or cloaked URLs."""
    redirect_history = []
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }
    try:
        response = requests.head(url, allow_redirects=True, timeout=4, headers=headers)
        if response.history:
            redirect_history = [r.url for r in response.history]
        return response.url, redirect_history
    except Exception:
        try:
            response = requests.get(url, allow_redirects=True, timeout=4, stream=True, headers=headers)
            if response.history:
                redirect_history = [r.url for r in response.history]
            return response.url, redirect_history
        except Exception:
            return url, []

def get_domain_age_days(domain: str) -> Optional[int]:
    """Fetches domain age using local WHOIS or HTTPS REST API fallback."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            return (datetime.now() - creation_date.replace(tzinfo=None)).days
    except Exception:
        pass

    try:
        api_url = f"https://networkcalc.com/api/dns/whois/{domain}"
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "OK":
                creation_str = data.get("whois", {}).get("creation_date")
                if creation_str:
                    creation_date = datetime.fromisoformat(creation_str.replace('Z', '+00:00')).replace(tzinfo=None)
                    return (datetime.now() - creation_date).days
    except Exception as e:
        print(f"API WHOIS error: {e}")

    return None

def check_urlhaus(url: str) -> bool:
    """Queries URLhaus (Abuse.ch) database. Free, open, no billing required."""
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        response = requests.post(api_url, data={"url": url}, timeout=4)
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "ok":
                return True
    except Exception as e:
        print(f"URLhaus lookup error: {e}")
    return False

def check_virustotal(url: str) -> dict:
    """Queries VirusTotal API v3 across 70+ security vendors."""
    if not VT_API_KEY:
        return {"scanned": False, "malicious_count": 0, "total_engines": 0}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json"
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=6)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            return {"scanned": True, "malicious_count": malicious, "total_engines": total}
        elif response.status_code == 404:
            return {"scanned": False, "malicious_count": 0, "total_engines": 0}
        else:
            print(f"VirusTotal API status {response.status_code}: {response.text}")
    except Exception as e:
        print(f"VirusTotal API error: {e}")

    return {"scanned": False, "malicious_count": 0, "total_engines": 0}

def analyze_url(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    findings = []
    risk_score = 0

    # 1. Unmask redirects
    final_url, redirects = resolve_redirects(url)
    if redirects:
        findings.append(f"Redirect chain detected ({len(redirects)} jump(s)): Unmasked to '{final_url}'.")
        risk_score += 15

    eval_url = final_url

    try:
        parsed = urlparse(eval_url)
        extracted = tldextract.extract(eval_url)
    except ValueError as e:
        return {
            "url": url,
            "final_url": final_url,
            "domain": "Invalid",
            "risk_score": 100,
            "verdict": "MALICIOUS",
            "findings": [f"Malformed URL structure detected: {str(e)}"]
        }

    domain = extracted.registered_domain
    subdomain = extracted.subdomain
    path = parsed.path
    hostname = parsed.hostname or ""

    # 2. Hostname uses raw IP address
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pattern, hostname):
        findings.append("Hostname uses raw IP address instead of a domain name.")
        risk_score += 40

    # 3. Presence of '@' character
    if "@" in eval_url:
        findings.append("URL contains '@' character, often used to obscure true destination.")
        risk_score += 30

    # 4. Excessive URL length
    if len(eval_url) > 75:
        findings.append(f"URL is unusually long ({len(eval_url)} characters).")
        risk_score += 10

    # 5. Excessive subdomains
    subdomain_parts = [p for p in subdomain.split(".") if p]
    if len(subdomain_parts) >= 3:
        findings.append(f"Excessive subdomains detected: '{subdomain}'.")
        risk_score += 20

    # 6. Suspicious keywords in path/subdomain
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in (path.lower() + subdomain.lower())]
    if found_keywords:
        findings.append(f"Suspicious security/login keywords present: {', '.join(found_keywords)}.")
        risk_score += 15

    # 7. Brand spoofing in subdomain
    for brand in SUSPICIOUS_BRANDS:
        if brand in subdomain.lower() and brand != extracted.domain.lower():
            findings.append(f"Target brand '{brand}' found in subdomain while registered domain is '{domain}'.")
            risk_score += 40

    # 8. Domain age check via WHOIS / REST API fallback
    if domain:
        age_days = get_domain_age_days(domain)
        if age_days is not None:
            if age_days < 30:
                findings.append(f"Domain is brand new (registered {age_days} days ago).")
                risk_score += 35
            elif age_days < 90:
                findings.append(f"Domain is relatively new (registered {age_days} days ago).")
                risk_score += 15
            else:
                findings.append(f"Domain is established (registered {age_days} days ago).")
        else:
            findings.append("Domain registration age could not be verified.")

    # 9. URLhaus Threat Database Lookup
    if check_urlhaus(url) or (eval_url != url and check_urlhaus(eval_url)):
        findings.append("CRITICAL: URL flagged in URLhaus threat database as active malware/phishing.")
        risk_score = 100

    # 10. VirusTotal multi-engine scan
    vt_result = check_virustotal(eval_url)
    if vt_result["scanned"]:
        flagged = vt_result["malicious_count"]
        total = vt_result["total_engines"]
        if flagged >= 3:
            findings.append(f"CRITICAL: VirusTotal flagged by {flagged}/{total} security vendors.")
            risk_score = 100
        elif flagged > 0:
            findings.append(f"WARNING: VirusTotal flagged by {flagged}/{total} security vendor(s).")
            risk_score += 40
        else:
            findings.append(f"VirusTotal clean ({total} vendors checked).")

    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        verdict = "MALICIOUS"
    elif risk_score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY_SAFE"

    return {
        "url": url,
        "final_url": final_url,
        "domain": domain,
        "risk_score": risk_score,
        "verdict": verdict,
        "findings": findings
    }