# ============================================================
# Malicious URL Detector — Flask Backend
# Nivedhitha KS | Cybersecurity Portfolio
# Analyses URLs for phishing, malware, typosquatting & more
# ============================================================

from flask import Flask, render_template, request, jsonify
import re
import urllib.parse
import datetime
import math

app = Flask(__name__)

# ── Known malicious / suspicious patterns ───────────────────

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'confirm', 'banking', 'paypal', 'amazon', 'google', 'apple',
    'microsoft', 'netflix', 'support', 'helpdesk', 'reset',
    'password', 'credential', 'suspended', 'urgent', 'alert',
    'free', 'winner', 'prize', 'lucky', 'claim', 'invoice',
    'tracked', 'delivery', 'parcel', 'dhl', 'fedex'
]

LEGITIMATE_DOMAINS = {
    'google.com', 'gmail.com', 'youtube.com', 'amazon.com', 'amazon.in',
    'paypal.com', 'microsoft.com', 'apple.com', 'netflix.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com',
    'wikipedia.org', 'yahoo.com', 'bing.com', 'dhl.com', 'fedex.com',
    'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com',
    'irctc.co.in', 'flipkart.com', 'myntra.com', 'zomato.com'
}

KNOWN_BAD_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
                  '.click', '.download', '.zip', '.loan', '.work']

KNOWN_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
                    'is.gd', 'buff.ly', 'short.link', 'rb.gy', 'tiny.cc']

IP_PATTERN = re.compile(
    r'https?://(\d{1,3}\.){3}\d{1,3}'
)

HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '@': 'a', 'vv': 'w', 'rn': 'm'
}

def extract_domain(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain, parsed
    except Exception:
        return '', None

def get_root_domain(domain):
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

def check_typosquatting(domain, legit_domains):
    hits = []
    root = get_root_domain(domain)
    for legit in legit_domains:
        legit_root = get_root_domain(legit)
        # Check if legit brand name is embedded in a longer domain
        brand = legit_root.split('.')[0]
        if brand in domain and root != legit_root and len(domain) > len(legit_root):
            hits.append(f"Contains brand '{brand}' but is not {legit_root}")
    return hits

def calculate_entropy(s):
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def analyze_url(url):
    url = url.strip()
    findings = []
    score = 0
    domain, parsed = extract_domain(url)

    if not domain:
        return {"error": "Invalid URL"}

    root_domain = get_root_domain(domain)

    # ── Check 1: HTTPS ──────────────────────────────────────
    if url.startswith('http://'):
        findings.append({
            "type": "NO_HTTPS",
            "severity": "MEDIUM",
            "detail": "URL uses HTTP — data is transmitted unencrypted. Modern phishing sites often use HTTP to avoid SSL certificate checks.",
            "indicator": url[:7]
        })
        score += 15

    # ── Check 2: IP address as host ─────────────────────────
    if IP_PATTERN.match(url):
        findings.append({
            "type": "IP_ADDRESS_HOST",
            "severity": "HIGH",
            "detail": "URL uses a raw IP address instead of a domain name. Legitimate services never do this. Common in malware C2 infrastructure.",
            "indicator": domain
        })
        score += 30

    # ── Check 3: URL shortener ──────────────────────────────
    if any(s in domain for s in KNOWN_SHORTENERS):
        findings.append({
            "type": "URL_SHORTENER",
            "severity": "MEDIUM",
            "detail": f"URL uses a shortening service ({domain}). The real destination is hidden. Shorteners are frequently used in phishing and spam campaigns.",
            "indicator": domain
        })
        score += 20

    # ── Check 4: Suspicious TLD ─────────────────────────────
    for bad_tld in KNOWN_BAD_TLDS:
        if domain.endswith(bad_tld):
            findings.append({
                "type": "SUSPICIOUS_TLD",
                "severity": "HIGH",
                "detail": f"Domain uses TLD '{bad_tld}' — these free/cheap TLDs are heavily associated with malicious infrastructure. Over 60% of phishing domains use these TLDs.",
                "indicator": bad_tld
            })
            score += 25
            break

    # ── Check 5: Typosquatting ──────────────────────────────
    typo_hits = check_typosquatting(domain, LEGITIMATE_DOMAINS)
    for hit in typo_hits[:2]:
        findings.append({
            "type": "TYPOSQUATTING",
            "severity": "CRITICAL",
            "detail": f"Typosquatting detected: {hit}. This is a classic phishing technique — the domain mimics a trusted brand to deceive users.",
            "indicator": domain
        })
        score += 35

    # ── Check 6: Suspicious keywords in path/domain ─────────
    full_url_lower = url.lower()
    kw_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url_lower]
    if len(kw_hits) >= 2:
        findings.append({
            "type": "PHISHING_KEYWORDS",
            "severity": "MEDIUM",
            "detail": f"URL contains {len(kw_hits)} phishing-related keywords: {', '.join(kw_hits[:5])}. Phishing URLs frequently include these words to appear legitimate.",
            "indicator": ', '.join(kw_hits[:5])
        })
        score += min(len(kw_hits) * 8, 30)

    # ── Check 7: Excessive subdomains ───────────────────────
    subdomain_count = len(domain.split('.')) - 2
    if subdomain_count >= 3:
        findings.append({
            "type": "EXCESSIVE_SUBDOMAINS",
            "severity": "MEDIUM",
            "detail": f"Domain has {subdomain_count} subdomains. Attackers use deep subdomain chains like 'secure.login.verify.attacker.com' to hide the true root domain.",
            "indicator": domain
        })
        score += 20

    # ── Check 8: Extremely long URL ─────────────────────────
    if len(url) > 120:
        findings.append({
            "type": "LONG_URL",
            "severity": "LOW",
            "detail": f"URL is {len(url)} characters long. Legitimate URLs are rarely this long. Phishing URLs are often padded to obscure the real destination.",
            "indicator": f"{len(url)} chars"
        })
        score += 10

    # ── Check 9: @ symbol in URL ────────────────────────────
    if '@' in url:
        findings.append({
            "type": "AT_SYMBOL",
            "severity": "HIGH",
            "detail": "URL contains '@' symbol. Browsers ignore everything before '@' — 'http://google.com@evil.com' actually goes to evil.com. Classic misdirection trick.",
            "indicator": "@"
        })
        score += 30

    # ── Check 10: High path entropy (randomness) ────────────
    path = parsed.path if parsed else ''
    if len(path) > 10:
        entropy = calculate_entropy(path)
        if entropy > 4.0:
            findings.append({
                "type": "HIGH_ENTROPY_PATH",
                "severity": "MEDIUM",
                "detail": f"URL path has high randomness (entropy: {entropy:.2f}). Random-looking paths are used in malware campaigns to avoid detection and create unique tracking links.",
                "indicator": path[:40] + '...' if len(path) > 40 else path
            })
            score += 15

    # ── Check 11: Double extension ──────────────────────────
    if re.search(r'\.(pdf|doc|xls|txt|img)\.(exe|php|js|bat|sh|vbs)', url.lower()):
        findings.append({
            "type": "DOUBLE_EXTENSION",
            "severity": "CRITICAL",
            "detail": "URL has double file extension (e.g., invoice.pdf.exe). This is a malware delivery technique — disguises executables as documents.",
            "indicator": re.search(r'(\w+\.\w+\.\w+)', url).group() if re.search(r'(\w+\.\w+\.\w+)', url) else ''
        })
        score += 40

    # ── Clamp score ─────────────────────────────────────────
    score = min(score, 100)

    # ── Verdict ─────────────────────────────────────────────
    if score >= 70:
        verdict = "MALICIOUS"
        verdict_color = "critical"
    elif score >= 40:
        verdict = "SUSPICIOUS"
        verdict_color = "warning"
    elif score >= 15:
        verdict = "POTENTIALLY UNSAFE"
        verdict_color = "low"
    else:
        verdict = "LIKELY SAFE"
        verdict_color = "safe"

    # ── Count severities ────────────────────────────────────
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    return {
        "url": url,
        "domain": domain,
        "root_domain": root_domain,
        "score": score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "findings": findings,
        "finding_count": len(findings),
        "severities": sev_counts,
        "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "checks_performed": 11
    }

# ── Sample URLs for demo ─────────────────────────────────────
SAMPLE_URLS = {
    "phishing": "http://secure-login.paypal.verify-account.tk/confirm?user=admin&token=a8f3k2",
    "typosquat": "http://www.amazon-security-alert.com/login/verify",
    "malware":   "http://185.234.219.5/invoice.pdf.exe",
    "safe":      "https://www.github.com/NivedhithaKS-SEC"
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    result = analyze_url(url)
    return jsonify(result)

@app.route('/api/samples')
def api_samples():
    return jsonify(SAMPLE_URLS)

if __name__ == '__main__':
    print("\n" + "="*55)
    print("  MALICIOUS URL DETECTOR")
    print("  Nivedhitha KS | Cybersecurity Portfolio")
    print("  Open: http://127.0.0.1:5000")
    print("="*55 + "\n")
    app.run(debug=False, host='0.0.0.0', port=5000)
