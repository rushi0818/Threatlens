import hashlib
import os
import requests


# Paste your free VirusTotal API key here
# Get it free at: https://www.virustotal.com → Sign up → Profile → API Key
VT_API_KEY = "779e7cf2c5ace3a2e772780e09fb5a3195bc1da9a2e9407ea5929558a8c6d93b"
VT_URL     = "https://www.virustotal.com/api/v3/files/"


def compute_hashes(file_path):
    """Compute MD5 and SHA256 of a file."""
    md5    = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha256.hexdigest()


def check_virustotal(file_hash):
    """
    Send a file hash to VirusTotal API and get detection results.
    Returns number of detections and vendor results.
    """
    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return {
            "error"  : "VirusTotal API key not set. Add your key in hash_checker.py",
            "md5"    : file_hash,
            "checked": False
        }

    headers  = {"x-apikey": VT_API_KEY}
    response = requests.get(VT_URL + file_hash, headers=headers, timeout=10)

    if response.status_code == 404:
        return {
            "checked"    : True,
            "found"      : False,
            "message"    : "File not found in VirusTotal database (may be new/unknown)",
            "hash"       : file_hash
        }

    if response.status_code != 200:
        return {"error": f"VirusTotal API error: {response.status_code}"}

    data       = response.json()
    stats      = data["data"]["attributes"]["last_analysis_stats"]
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total      = sum(stats.values())

    return {
        "checked"    : True,
        "found"      : True,
        "malicious"  : malicious,
        "suspicious" : suspicious,
        "total"      : total,
        "verdict"    : "MALICIOUS" if malicious > 3 else
                       "SUSPICIOUS" if malicious > 0 or suspicious > 2 else
                       "CLEAN",
        "is_phishing": malicious > 3,
        "confidence" : round((malicious / total) * 100, 1) if total > 0 else 0,
        "hash"       : file_hash,
        "scan_type"  : "File Hash"
    }


def scan_file_hash(file_path):
    """
    Main function — compute hash of file then check on VirusTotal.
    This is what app.py calls.
    """
    if not os.path.exists(file_path):
        return {"error": "File not found"}

    md5, sha256 = compute_hashes(file_path)
    file_size   = os.path.getsize(file_path)

    result = check_virustotal(sha256)
    result["md5"]       = md5
    result["sha256"]    = sha256
    result["file_size"] = f"{round(file_size / 1024, 1)} KB"

    return result