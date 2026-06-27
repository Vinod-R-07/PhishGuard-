# PhishGuard — AI-Based Phishing Website Detection System

A machine learning web application that detects phishing websites in real-time using a Random Forest classifier, VirusTotal API integration, and live threat intelligence feeds.

> **NPS Lab Project** — Network Programming and Security

---

## Overview

PhishGuard analyzes any URL by extracting 30 network-level security features in real-time — including DNS records, SSL state, WHOIS domain age, HTTP headers, and page content — and classifies it as legitimate or phishing using a trained Random Forest model. Results are cross-validated against VirusTotal's database of 90+ security engines.

---

## Features

| Page | Description |
|---|---|
| **Scanner** | Analyze any URL using 30 live network features |
| **Bulk Scanner** | Scan up to 20 URLs simultaneously |
| **Threat Feed** | Live phishing URLs from OpenPhish in real-time |
| **Scan History** | All scans logged with PDF export and delete |
| **System Design** | Browser extension deployment concept |
| **About** | Model explanation and architecture |

---

## Detection Architecture
User enters URL
↓
Feature Extractor — 30 live network checks
(DNS, WHOIS, SSL, HTTP, page content analysis)
↓
Random Forest ML Model — instant prediction
↓
VirusTotal API — cross-validates against 90+ engines
↓
Override Rules — catches borderline cases
↓
Final verdict with confidence score

---

## Why Two Layers

| | ML Model | VirusTotal |
|---|---|---|
| Zero-day URLs | ✅ Analyzes structure instantly | ❌ Not in database yet |
| Known threats | ⚠️ May miss modern ones | ✅ Flagged by 90+ engines |
| Works offline | ✅ Yes | ❌ Needs internet |
| Explains why | ✅ Shows 30 features | ❌ Just flags it |
| API limit | ✅ Unlimited | ⚠️ 500/day free tier |

---

## ML Model

- **Dataset** — UCI Phishing Websites Dataset (11,055 records, 30 features)
- **Algorithm** — Random Forest Classifier (100 decision trees)
- **Accuracy** — ~96-97% on test set
- **Split** — 80% train / 20% test, stratified

---

## 30 Security Features

| Category | Features |
|---|---|
| URL-Based | IP in URL, URL length, shortener, @ symbol, double slash, prefix/suffix dash, subdomain depth, HTTPS token |
| Domain-Based | SSL state, domain registration length, favicon, port, domain age, DNS record |
| Page Content | Request URL ratio, anchor ratio, tag link ratio, form handler, email submission, iframe, mouseover, right-click, popup |
| External | Abnormal URL, redirect count, web traffic, page rank, Google index, inbound links, statistical report |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| ML Model | scikit-learn — Random Forest |
| Feature Extraction | requests, BeautifulSoup4, python-whois, tldextract |
| Threat Intelligence | VirusTotal API, OpenPhish |
| Database | SQLite |
| Rate Limiting | Flask-Limiter |
| PDF Reports | fpdf2 |
| Frontend | HTML, CSS, JavaScript |

---

## REST API

```bash
POST /api/scan
Content-Type: application/json
{"url": "example.com"}
```

```json
{
  "url": "example.com",
  "result": "Legitimate",
  "confidence": 91.2,
  "risk_flags": 3,
  "safe_features": 22,
  "virustotal": "VirusTotal: Clean — scanned by 89 engines"
}
```

---

## Project Structure
```text
PhishGuard/
├── app.py                  # Flask application and routes
├── feature_extractor.py    # 30 feature extraction logic
├── train_model.py          # Model training script
├── requirements.txt        # Dependencies
├── model/
│   └── phishing_model.pkl  # Trained Random Forest model
├── templates/              # HTML pages
└── static/
└── style.css           # Stylesheet
```

---

## Dataset

UCI Machine Learning Repository — [Phishing Websites Dataset](https://archive.ics.uci.edu/ml/datasets/phishing+websites)

---

## Author

**Vinod R** — NPS Lab Project, 2026

Push it:
bashgit add README.md
git commit -m "Add README"
git pushYou said: if you give like this small small chunk what should i think like does all includes in readme or what 'if you give like this small small chunk what should i think like does all includes in readme or what '4:05 AMClaude responded: Fair point — here's the complete README.Fair point — here's the complete README.md as one single file, copy the entire thing at once:
markdown# PhishGuard — AI-Based Phishing Website Detection System

A machine learning web application that detects phishing websites in real-time using a Random Forest classifier, VirusTotal API integration, and live threat intelligence feeds.

> **NPS Lab Project** — Network Programming and Security

---

## Overview

PhishGuard analyzes any URL by extracting 30 network-level security features in real-time — including DNS records, SSL state, WHOIS domain age, HTTP headers, and page content — and classifies it as legitimate or phishing using a trained Random Forest model. Results are cross-validated against VirusTotal's database of 90+ security engines.

---

## Features

| Page | Description |
|---|---|
| **Scanner** | Analyze any URL using 30 live network features |
| **Bulk Scanner** | Scan up to 20 URLs simultaneously |
| **Threat Feed** | Live phishing URLs from OpenPhish in real-time |
| **Scan History** | All scans logged with PDF export and delete |
| **System Design** | Browser extension deployment concept |
| **About** | Model explanation and architecture |

---

## Detection Architecture
User enters URL
↓
Feature Extractor — 30 live network checks
(DNS, WHOIS, SSL, HTTP, page content analysis)
↓
Random Forest ML Model — instant prediction
↓
VirusTotal API — cross-validates against 90+ engines
↓
Override Rules — catches borderline cases
↓
Final verdict with confidence score

---

## Why Two Layers

| | ML Model | VirusTotal |
|---|---|---|
| Zero-day URLs | ✅ Analyzes structure instantly | ❌ Not in database yet |
| Known threats | ⚠️ May miss modern ones | ✅ Flagged by 90+ engines |
| Works offline | ✅ Yes | ❌ Needs internet |
| Explains why | ✅ Shows 30 features | ❌ Just flags it |
| API limit | ✅ Unlimited | ⚠️ 500/day free tier |

---

## ML Model

- **Dataset** — UCI Phishing Websites Dataset (11,055 records, 30 features)
- **Algorithm** — Random Forest Classifier (100 decision trees)
- **Accuracy** — ~96-97% on test set
- **Split** — 80% train / 20% test, stratified

---

## 30 Security Features

| Category | Features |
|---|---|
| URL-Based | IP in URL, URL length, shortener, @ symbol, double slash, prefix/suffix dash, subdomain depth, HTTPS token |
| Domain-Based | SSL state, domain registration length, favicon, port, domain age, DNS record |
| Page Content | Request URL ratio, anchor ratio, tag link ratio, form handler, email submission, iframe, mouseover, right-click, popup |
| External | Abnormal URL, redirect count, web traffic, page rank, Google index, inbound links, statistical report |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| ML Model | scikit-learn — Random Forest |
| Feature Extraction | requests, BeautifulSoup4, python-whois, tldextract |
| Threat Intelligence | VirusTotal API, OpenPhish |
| Database | SQLite |
| Rate Limiting | Flask-Limiter |
| PDF Reports | fpdf2 |
| Frontend | HTML, CSS, JavaScript |

---

## REST API

**Endpoint:** `POST /api/scan`

**Request:**
```json
{
  "url": "example.com"
}
```

**Response:**
```json
{
  "url": "example.com",
  "result": "Legitimate",
  "confidence": 91.2,
  "risk_flags": 3,
  "safe_features": 22,
  "virustotal": "VirusTotal: Clean — scanned by 89 engines"
}
```

---

## Project Structure
PhishGuard/
├── app.py                  # Flask application and all routes
├── feature_extractor.py    # 30 feature extraction logic
├── train_model.py          # Model training script
├── requirements.txt        # Python dependencies
├── .gitignore
├── model/
│   └── phishing_model.pkl  # Trained Random Forest model
├── templates/
│   ├── base.html           # Base layout with navbar
│   ├── index.html          # Scanner page
│   ├── result.html         # Scan result page
│   ├── history.html        # Scan history page
│   ├── bulk.html           # Bulk scanner input
│   ├── bulk_result.html    # Bulk scanner results
│   ├── threats.html        # Live threat feed
│   ├── extension.html      # System design page
│   └── about.html          # About and documentation
└── static/
└── style.css           # Dark theme stylesheet

---

## Dataset

UCI Machine Learning Repository — [Phishing Websites Dataset](https://archive.ics.uci.edu/ml/datasets/phishing+websites)

11,055 website records with 30 features each, labeled as phishing (-1) or legitimate (1).

---

## How VirusTotal Fits In

VirusTotal is a reactive system — it only knows about URLs that have already been reported. A brand new phishing URL created today will not exist in its database until someone reports it. That gap — between URL creation and VirusTotal detection — is exactly where the ML model operates. The ML model performs behavioral analysis on URL structure and network features, detecting zero-day phishing attempts that no database has seen yet. VirusTotal then acts as a secondary verification layer for known threats.

---

## Author

**Vinod R** — NPS Lab Project, 2026
