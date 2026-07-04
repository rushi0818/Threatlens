import re

try:
    import pdfplumber
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


SUSPICIOUS_KEYWORDS = [
    "verify", "confirm", "suspended", "urgent", "click here",
    "login", "password", "update payment", "account locked",
    "prize", "winner", "congratulations", "claim now"
]


def extract_urls_from_text(text):
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(pattern, text)


def scan_pdf(file_path):
    """
    Opens a PDF file, reads all text, extracts links,
    and checks for phishing indicators.
    """
    if not PDF_AVAILABLE:
        return {"error": "pdfplumber not installed. Run: pip install pdfplumber"}

    try:
        full_text = ""
        page_count = 0

        with pdfplumber.open(file_path) as pdf:
            page_count = len(pdf.pages)
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    full_text += text + "\n"

    except Exception as e:
        return {"error": f"Could not read PDF: {str(e)}"}

    if not full_text.strip():
        return {"error": "PDF appears to be empty or image-based (no readable text found)"}

    text_lower = full_text.lower()
    reasons    = []
    score      = 0

    # Check URLs inside PDF
    urls = extract_urls_from_text(full_text)
    suspicious_urls = []
    for url in urls:
        url_lower = url.lower()
        if any(tld in url_lower for tld in [".xyz", ".tk", ".ml", ".ga", ".cf"]):
            suspicious_urls.append(url)
            score += 3
        if not url_lower.startswith("https"):
            score += 1
        if re.search(r"(\d{1,3}\.){3}\d{1,3}", url):
            suspicious_urls.append(url)
            score += 3

    if suspicious_urls:
        reasons.append(f"Suspicious URLs found in PDF: {suspicious_urls[0][:60]}")
    if urls:
        http_count = sum(1 for u in urls if u.startswith("http://"))
        if http_count > 0:
            reasons.append(f"{http_count} unencrypted HTTP links found in PDF")

    # Check suspicious keywords
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_lower]
    if found_keywords:
        score += len(found_keywords)
        reasons.append(f"Suspicious words in PDF: {', '.join(found_keywords[:4])}")

    # Check if PDF pretends to be from a known brand
    brands = ["paypal", "amazon", "apple", "microsoft", "google",
              "netflix", "bank", "chase", "fedex", "dhl"]
    found_brands = [b for b in brands if b in text_lower]
    if found_brands:
        score += 2
        reasons.append(f"Mentions brands commonly impersonated: {', '.join(found_brands)}")

    # Verdict
    if score >= 5:
        verdict     = "PHISHING"
        is_phishing = True
        confidence  = min(97, 55 + score * 3)
    elif score >= 2:
        verdict     = "SUSPICIOUS"
        is_phishing = True
        confidence  = min(70, 40 + score * 5)
    else:
        verdict     = "LEGITIMATE"
        is_phishing = False
        confidence  = 85

    return {
        "verdict"      : verdict,
        "is_phishing"  : is_phishing,
        "confidence"   : confidence,
        "score"        : score,
        "reasons"      : reasons,
        "urls_found"   : urls,
        "page_count"   : page_count,
        "text_preview" : full_text[:300].strip(),
        "scan_type"    : "PDF"
    }