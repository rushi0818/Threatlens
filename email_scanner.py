import re


# Words that appear very often in phishing emails
PHISHING_WORDS = [
    "verify your account", "confirm your identity", "suspended",
    "unusual activity", "click here immediately", "update your payment",
    "your account will be closed", "login immediately", "validate your email",
    "you have won", "claim your prize", "urgent action required",
    "dear customer", "dear user", "kindly verify", "reset your password now",
    "limited time", "act now", "your account has been compromised"
]

# Legitimate companies that phishers love to impersonate
IMPERSONATED_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "bank of america", "chase", "wells fargo", "ebay", "instagram",
    "facebook", "whatsapp", "dhl", "fedex", "ups"
]


def extract_urls_from_text(text):
    """Pull all URLs out of a block of text."""
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(pattern, text)


def scan_email(email_text):
    """
    Takes raw email text (subject + body pasted together).
    Returns a result dictionary with verdict and reasons.
    """
    if not email_text or len(email_text.strip()) < 10:
        return {"error": "Email text is too short or empty"}

    text_lower = email_text.lower()
    reasons    = []
    score      = 0

    # Check 1 - phishing keyword presence
    found_keywords = []
    for word in PHISHING_WORDS:
        if word in text_lower:
            found_keywords.append(word)
            score += 2

    if found_keywords:
        reasons.append(f"Contains phishing phrases: {', '.join(found_keywords[:3])}")

    # Check 2 - brand impersonation
    found_brands = []
    for brand in IMPERSONATED_BRANDS:
        if brand in text_lower:
            found_brands.append(brand)
            score += 1

    if found_brands:
        reasons.append(f"Mentions known impersonated brands: {', '.join(found_brands)}")

    # Check 3 - URLs inside email
    urls = extract_urls_from_text(email_text)
    suspicious_urls = []
    for url in urls:
        url_lower = url.lower()
        if any(tld in url_lower for tld in [".xyz", ".tk", ".ml", ".ga", ".cf"]):
            suspicious_urls.append(url)
            score += 3
        if re.search(r"(\d{1,3}\.){3}\d{1,3}", url):
            suspicious_urls.append(url)
            score += 3

    if suspicious_urls:
        reasons.append(f"Contains suspicious URLs: {suspicious_urls[0][:60]}...")

    # Check 4 - urgency language
    urgency_words = ["immediately", "urgent", "asap", "right now",
                     "within 24 hours", "expire", "last chance"]
    found_urgency = [w for w in urgency_words if w in text_lower]
    if found_urgency:
        score += 2
        reasons.append(f"Uses urgency language: {', '.join(found_urgency[:2])}")

    # Check 5 - generic greeting (phishing rarely uses your real name)
    generic_greetings = ["dear customer", "dear user", "dear account holder",
                         "dear member", "hello user", "valued customer"]
    if any(g in text_lower for g in generic_greetings):
        score += 2
        reasons.append("Uses generic greeting instead of your real name")

    # Check 6 - asking for sensitive info
    sensitive_asks = ["password", "credit card", "social security",
                      "bank account", "pin number", "otp", "cvv"]
    found_sensitive = [s for s in sensitive_asks if s in text_lower]
    if found_sensitive:
        score += 3
        reasons.append(f"Asks for sensitive information: {', '.join(found_sensitive)}")

    # Final verdict based on score
    if score >= 6:
        verdict     = "PHISHING"
        is_phishing = True
        confidence  = min(99, 60 + score * 2)
    elif score >= 3:
        verdict     = "SUSPICIOUS"
        is_phishing = True
        confidence  = min(75, 40 + score * 3)
    else:
        verdict     = "LEGITIMATE"
        is_phishing = False
        confidence  = max(60, 90 - score * 5)

    return {
        "verdict"     : verdict,
        "is_phishing" : is_phishing,
        "confidence"  : confidence,
        "score"       : score,
        "reasons"     : reasons,
        "urls_found"  : urls,
        "scan_type"   : "Email"
    }