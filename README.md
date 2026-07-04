# 🔍 ThreatLens — Cyber Threat Intelligence Platform

> AI-powered phishing detection and malware analysis platform built for SOC analysts.
> Combines Machine Learning, Static Analysis, YARA Rules, and VirusTotal API.

![Python](https://img.shields.io/badge/Python-3.14-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)
![ML](https://img.shields.io/badge/ML-Scikit--Learn-orange?logo=scikit-learn)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 📌 What is ThreatLens?

ThreatLens is a multi-engine cyber threat analysis platform that helps SOC analysts
investigate suspicious URLs, emails, documents, and files — all from one interface.

It was built as part of a SOC Analyst Internship project and demonstrates real-world
threat detection workflows used in Security Operations Centers.

---

## ⚡ Features

| Feature | Description |
|--------|-------------|
| 🔗 URL Scanner | ML model trained on 11,000+ URLs detects phishing links |
| 📧 Email Analyzer | Keyword, urgency, and brand impersonation detection |
| 📄 PDF / DOCX Scanner | Extracts links and content from documents |
| 🦠 Static Malware Analysis | Strings, entropy, PE header, suspicious API detection |
| 📌 YARA Scanner | Rule-based malware family identification |
| 🔍 Hash Intelligence | VirusTotal + MalwareBazaar hash reputation check |
| 🌐 Network IOC Extractor | Auto-extracts IPs, URLs, domains from files |
| 📋 SOC Report Generator | Structured verdict with recommended actions |

---

## 🖥️ Screenshots

### URL Scanner
> Paste any suspicious URL — ML model gives instant verdict with feature breakdown

![URL Scanner](screenshots/url_scan.png)

### Email Analyzer
> Paste full email content — detects phishing phrases, urgency language, brand impersonation

![Email Scanner](screenshots/email_scan.png)

### Malware Static Analysis
> Upload any file — extracts strings, checks entropy, finds suspicious API calls

![Malware Analysis](screenshots/malware_scan.png)

### YARA Rule Matches
> Matches files against custom YARA rules for known malware families

![YARA Scan](screenshots/yara_scan.png)

---

## 🏗️ Project Structure

```
threatlens/
├── app.py                    # Flask web application (main entry point)
├── preprocess.py             # Feature extraction & data preprocessing
├── train_model.py            # ML model training & evaluation
├── requirements.txt          # Python dependencies
├── scanner/
│   ├── email_scanner.py      # Email phishing detection
│   ├── pdf_scanner.py        # PDF content analysis
│   ├── doc_scanner.py        # Word document analysis
│   ├── hash_checker.py       # VirusTotal hash reputation
│   ├── static_analyzer.py    # Static malware analysis
│   ├── yara_scanner.py       # YARA rules engine
│   ├── network_extractor.py  # Network IOC extraction
│   └── malware_reporter.py   # SOC report generator
├── yara_rules/
│   └── general.yar           # Custom YARA rules
└── templates/
    └── index.html            # ThreatLens UI
```

---

## 🚀 How to Run Locally

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/threatlens.git
cd threatlens
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Download dataset
Download the phishing URL dataset from Kaggle:
[Web Page Phishing Detection Dataset](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset)

Place the CSV file as `webpagedataset_phishing.csv` in the root folder.

### 4. Train the model
```bash
python preprocess.py
python train_model.py
```

### 5. Run the app
```bash
python app.py
```

Open your browser and go to: **http://127.0.0.1:5000**

---

## 🤖 ML Model Performance

Trained on 11,430 URLs with 88 features using multiple algorithms:

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
|-------|----------|-----------|--------|----------|---------|
| **Gradient Boosting** ⭐ | **96.2%** | **95.8%** | **96.8%** | **96.3%** | **99.4%** |
| Random Forest | 96.1% | 95.7% | 96.6% | 96.1% | 99.3% |
| Linear SVM | 93.7% | 93.9% | 93.4% | 93.7% | 98.2% |
| Logistic Regression | 93.6% | 93.9% | 93.3% | 93.6% | 98.1% |

**Best Model: Gradient Boosting with 96.2% accuracy**

---

## 🛡️ YARA Rules Included

| Rule | Detects |
|------|---------|
| `Ransomware_Generic` | Ransomware indicators and payment demands |
| `Phishing_Document` | Phishing phrases in documents |
| `Suspicious_PowerShell` | Obfuscated PowerShell execution |
| `Malware_Process_Injection` | Code injection techniques |
| `Keylogger_Indicators` | Keyboard hooking and monitoring |
| `Suspicious_Network_Activity` | C2 communication patterns |
| `EICAR_Test_File` | Standard AV test file |

---

## 🔧 Tech Stack

- **Backend** — Python 3.14, Flask
- **Machine Learning** — Scikit-learn, Pandas, NumPy
- **Malware Analysis** — pefile, yara-python
- **Document Parsing** — pdfplumber, python-docx
- **Threat Intel** — VirusTotal API, MalwareBazaar API
- **Frontend** — HTML5, CSS3, Vanilla JavaScript

---

## 📦 Requirements

```
flask
pandas
numpy
scikit-learn
joblib
matplotlib
pdfplumber
python-docx
pefile
requests
extract-msg
```

Install all:
```bash
pip install -r requirements.txt
```

---

## 🔑 API Keys Setup

For VirusTotal integration, add your free API key:

1. Sign up at [virustotal.com](https://www.virustotal.com)
2. Go to Profile → API Key
3. Open `scanner/hash_checker.py`
4. Replace `YOUR_VIRUSTOTAL_API_KEY_HERE` with your key

Free tier: 500 requests/day — sufficient for testing.

---

## 📚 Skills Demonstrated

- ✅ IOC Analysis & Threat Intelligence
- ✅ Machine Learning for Cybersecurity
- ✅ Static Malware Analysis
- ✅ YARA Rule Writing
- ✅ OSINT Investigation
- ✅ Flask Web Development
- ✅ SOC Analyst Workflow Automation
- ✅ VirusTotal & MalwareBazaar API Integration

---

## ⚠️ Disclaimer

ThreatLens is built for **educational and security research purposes only**.
Do not use it to analyze files on production systems without proper authorization.
Always analyze malware samples in an isolated environment (VM).

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.

