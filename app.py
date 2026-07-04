import os
import re
import joblib
import numpy as np
from flask import Flask, render_template, request
from urllib.parse import urlparse

from scanner.email_scanner   import scan_email
from scanner.pdf_scanner     import scan_pdf
from scanner.doc_scanner     import scan_doc
from scanner.hash_checker    import scan_file_hash
from scanner.static_analyzer import run_static_analysis
from scanner.yara_scanner    import scan_with_yara
from scanner.malware_reporter import generate_report

app = Flask(__name__)

UPLOAD_FOLDER     = "uploads"
ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "msg", "exe", "dll", "ps1", "bat", "vbs"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load ML model
model         = joblib.load("outputs/model.pkl")
scaler        = joblib.load("processed/scaler.pkl")
feature_names = joblib.load("processed/feature_names.pkl")
print("[app] Model loaded!")


def extract_url_features(url):
    features = {}
    features["url_length"]    = len(url)
    features["dot_count"]     = url.count(".")
    features["slash_count"]   = url.count("/")
    features["hyphen_count"]  = url.count("-")
    features["at_count"]      = url.count("@")
    features["double_slash"]  = url.count("//") - 1
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        path   = parsed.path
        query  = parsed.query
    except Exception:
        domain = path = query = ""
    features["domain_length"]             = len(domain)
    features["path_length"]               = len(path)
    features["subdomain_count"]           = domain.count(".") - 1
    features["path_depth"]                = path.count("/")
    features["has_https"]                 = 1 if url.lower().startswith("https") else 0
    features["has_http"]                  = 1 if url.lower().startswith("http://") else 0
    features["has_ip_address"]            = 1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", domain) else 0
    features["has_at_symbol"]             = 1 if "@" in url else 0
    features["has_double_slash_redirect"] = 1 if "//" in path else 0
    features["has_dash_in_domain"]        = 1 if "-" in domain else 0
    phishing_keywords = ["secure","login","verify","update","account","banking",
                         "paypal","amazon","apple","google","microsoft","ebay",
                         "signin","password","confirm","wallet","support"]
    url_lower = url.lower()
    features["suspicious_keyword_count"] = sum(1 for kw in phishing_keywords if kw in url_lower)
    suspicious_tlds = [".xyz",".tk",".ml",".ga",".cf",".gq",".top",".click",".link",".online",".site"]
    features["has_suspicious_tld"]   = 1 if any(url_lower.endswith(t) for t in suspicious_tlds) else 0
    features["digit_ratio_domain"]   = sum(c.isdigit() for c in domain) / len(domain) if domain else 0
    features["query_length"]         = len(query)
    features["param_count"]          = query.count("&") + (1 if query else 0)
    return features


def preprocess_url(url):
    features = extract_url_features(url)
    x = np.array([features.get(f, 0) for f in feature_names]).reshape(1, -1)
    return scaler.transform(x)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan/url", methods=["POST"])
def scan_url():
    url = request.form.get("url", "").strip()
    if not url:
        return render_template("index.html", error="Please enter a URL", tab="url")
    if not url.startswith("http"):
        url = "http://" + url
    features   = extract_url_features(url)
    x          = preprocess_url(url)
    prediction = model.predict(x)[0]
    if hasattr(model, "predict_proba"):
        confidence = round(max(model.predict_proba(x)[0]) * 100, 1)
    else:
        confidence = 90.0
    is_phishing = int(prediction) == 1
    reasons = []
    if is_phishing:
        if features.get("has_ip_address"):      reasons.append("Uses IP address instead of domain name")
        if features.get("has_suspicious_tld"):  reasons.append("Suspicious TLD (.xyz, .tk etc)")
        if not features.get("has_https"):       reasons.append("No HTTPS encryption")
        if features.get("url_length", 0) > 75: reasons.append(f"Very long URL ({features['url_length']} chars)")
        if features.get("suspicious_keyword_count", 0) >= 2:
            reasons.append("Multiple suspicious keywords found")
    result = {
        "url": url, "verdict": "PHISHING" if is_phishing else "LEGITIMATE",
        "is_phishing": is_phishing, "confidence": confidence,
        "reasons": reasons, "scan_type": "URL",
        "features": {
            "URL Length": features["url_length"],
            "Has HTTPS": "Yes" if features["has_https"] else "No",
            "Has IP": "Yes" if features["has_ip_address"] else "No",
            "Keywords": features["suspicious_keyword_count"],
            "Bad TLD": "Yes" if features["has_suspicious_tld"] else "No",
            "Subdomains": max(0, features["subdomain_count"]),
        }
    }
    return render_template("index.html", result=result, tab="url")


@app.route("/scan/email", methods=["POST"])
def scan_email_route():
    email_text = request.form.get("email_text", "").strip()
    if not email_text:
        return render_template("index.html", error="Please paste email content", tab="email")
    result = scan_email(email_text)
    return render_template("index.html", result=result, tab="email")


@app.route("/scan/file", methods=["POST"])
def scan_file_route():
    scan_mode = request.form.get("scan_mode", "phishing")

    if "file" not in request.files:
        return render_template("index.html", error="No file uploaded", tab="file")
    file = request.files["file"]
    if file.filename == "":
        return render_template("index.html", error="No file selected", tab="file")

    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    save_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(save_path)

    if scan_mode == "malware":
        # Full malware analysis pipeline
        static_result  = run_static_analysis(save_path)
        yara_result    = scan_with_yara(save_path)
        hash_result    = scan_file_hash(save_path)
        report         = generate_report(static_result, yara_result, hash_result)
        report["filename"] = file.filename
        return render_template("index.html", result=report, tab="file",
                               scan_mode="malware", static=static_result,
                               yara=yara_result)
    else:
        # Phishing content analysis
        if ext == "pdf":
            result = scan_pdf(save_path)
        elif ext == "docx":
            result = scan_doc(save_path)
        else:
            result = {"verdict": "UNKNOWN", "is_phishing": False,
                      "confidence": 0, "reasons": [], "scan_type": ext.upper()}
        hash_result      = scan_file_hash(save_path)
        result["hash_check"] = hash_result
        result["filename"]   = file.filename
        return render_template("index.html", result=result, tab="file", scan_mode="phishing")


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  Phishing + Malware Detector — Full Platform")
    print("  By: secoprush")
    print("  Open: http://127.0.0.1:5000")
    print("="*55 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)