# Phishing Email Detector (PhishGuard) 🛡️

An automated, explainable, and multi-layered phishing email triage and awareness platform built in Python. Designed for rapid detection, transparency, and education following the **VETS Framework** (Value, Efficiency, Technology, Scalability).

---

## 🌟 Key Features & Objectives

| Objective | Module | Core Functionality |
| :--- | :--- | :--- |
| **1. Email Ingestion** | `src/ingestion.py` | Parses raw text / `.eml` files using Python's MIME `email` library; separates headers, body, extracted links, and attachment metadata. |
| **2. Sender & Headers** | `src/header_analyzer.py` | Detects display-name spoofing, embedded addresses, Levenshtein & homoglyph typosquatting, and validates SPF / DKIM / DMARC authentication. |
| **3. URL & Link Analysis** | `src/url_analyzer.py` | Identifies masked links (anchor text vs href target), queries blacklists / PhishTank feeds, detects URL shorteners, and flags raw IP hostnames. |
| **4. Linguistic & NLP** | `src/content_analyzer.py` | Analyzes urgency cues, threats, coercion, credential harvesting prompts, financial lures, generic greetings, and capitalization anomalies. |
| **5. ML Engine** | `src/ml_engine.py` | Combines 29 multi-modal security signals with TF-IDF text features into a trained **Random Forest** classifier (benchmarked against Logistic Regression). |
| **6. Risk Aggregation** | `src/risk_aggregator.py` | Blends ML probabilities with deterministic hard security overrides into three labels: **Safe**, **Suspicious**, or **Phishing**. |
| **7. Web UI & Reports** | `src/web/app.py` | Interactive Flask interface with real-time risk gauges, color-coded badges, plain-language breakdown, downloadable JSON reports, and REST API. |

---

## 🏗️ System Architecture

```
                                  +-----------------------+
                                  | Raw Email / .EML File |
                                  +-----------+-----------+
                                              |
                                              v
                                 +-------------------------+
                                 | Layer 1: MIME Ingestion |
                                 +------------+------------+
                                              |
                     +------------------------+------------------------+
                     |                        |                        |
                     v                        v                        v
          +--------------------+    +--------------------+    +--------------------+
          | Sender & Header    |    | URL & Link         |    | NLP Content        |
          | Authenticity Check |    | Reputation Check   |    | Urgency Analysis   |
          +---------+----------+    +---------+----------+    +---------+----------+
                    |                         |                         |
                    +--------------------+----+-------------------------+
                                         |
                                         v
                         +-------------------------------+
                         | Multi-Modal Feature Vector    |
                         | (29 Engineered Signals+TF-IDF)|
                         +---------------+---------------+
                                         |
                                         v
                         +-------------------------------+
                         | Layer 5: ML Classifier Engine |
                         | (Random Forest Champion Model)|
                         +---------------+---------------+
                                         |
                                         v
                         +-------------------------------+
                         | Layer 6: Risk Aggregator      |
                         | (Deterministic Security Rules)|
                         +---------------+---------------+
                                         |
                                         v
                         +-------------------------------+
                         | Layer 7: Result & Explanation |
                         | [ SAFE / SUSPICIOUS / PHISH ] |
                         | Plain-Language Threat Summary |
                         +-------------------------------+
```

---

## 📊 ML Model Benchmark Results

Trained and evaluated on balanced phishing datasets (Nazario corpus patterns, APWG templates) and legitimate corporate/personal communications (Enron corpus):

| Model | Accuracy | Precision | Recall | F1-Score | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 83.33% | 100.0% | 66.67% | 80.00% | Benchmark Baseline |
| **Random Forest** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | 🏆 **Champion Model** |

---

## 🚀 Quickstart Guide

### 1. Prerequisites & Virtual Environment
Ensure Python 3.8+ is installed. Using `uv` or standard `python -m venv`:

```bash
# Activate virtual environment (Windows PowerShell)
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Launch the Web Application
```bash
python run_server.py
```
Open **`http://127.0.0.1:5000`** in your web browser.
- Use the **Paste Raw Email** tab or **Upload .EML File** tab.
- Or click one of the **Quick Test Presets** (`PayPal Spoof`, `Masked Link`, `Trojan Attachment`, `Safe GitHub`) to run instant scans.

### 3. Command Line Interface (CLI)
You can scan emails directly from your terminal:

```bash
# Analyze a sample email file
python cli.py --file data/sample_emails/paypal_phishing.eml

# Analyze a legitimate email file
python cli.py --file data/sample_emails/legitimate_github.eml

# Output structured JSON result
python cli.py --file data/sample_emails/masked_link_phishing.eml --json
```

### 4. Retrain / Benchmark ML Models
```bash
python train.py
```

### 5. Run the Automated Test Suite
```bash
pytest -v
```
All 21 comprehensive test suites covering ingestion, headers, URLs, NLP, attachments, risk scoring, and web API pass automatically.

---

## 🔌 REST API Documentation

### Analyze Email
`POST /api/analyze`

**Request (JSON):**
```json
{
  "email_text": "From: \"PayPal Security\" <service@paypal-account-verify.xyz>\nSubject: Urgent: Verify Account\n\nDear Customer,\nYour account is restricted. Verify immediately at http://paypal-account-verify.xyz/login"
}
```

**Response (JSON):**
```json
{
  "status": "success",
  "data": {
    "execution_time_ms": 35.2,
    "final_verdict": {
      "final_label": "Phishing",
      "risk_score": 94.6,
      "confidence": 0.95,
      "plain_language_reasons": [
        "Security Alert: Email contains known blacklisted / PhishTank malicious domains.",
        "Security Alert: Brand display name spoofing combined with active call-to-action.",
        "Sender claims to represent 'PayPal' in display name, but email is sent from unrelated domain 'paypal-account-verify.xyz'."
      ],
      "recommendation": "HIGH THREAT DETECTED. Do not click any links, enter credentials, or open attachments."
    },
    "ml_classification": {
      "model_name": "RandomForestClassifier",
      "phishing_percentage": 99.0
    }
  }
}
```

---

## 📁 Project Structure

```
Project/
├── data/
│   ├── blacklist_domains.txt       # Known phishing / malware domain feeds
│   ├── target_brands.json          # Target brands & legitimate domain references
│   ├── create_training_corpus.py   # Corpus generator script
│   ├── training_corpus.json        # Curated balanced dataset
│   └── sample_emails/              # Real-world test emails (.eml format)
│       ├── paypal_phishing.eml
│       ├── masked_link_phishing.eml
│       ├── malware_attachment.eml
│       └── legitimate_github.eml
├── models/
│   ├── phishing_detector.joblib    # Serialized trained model & TF-IDF vectorizer
│   └── model_metrics.json          # Benchmark evaluation metrics
├── src/
│   ├── __init__.py
│   ├── ingestion.py                # Objective 1: MIME parsing & extraction
│   ├── header_analyzer.py          # Objective 2: SPF/DKIM/DMARC & lookalikes
│   ├── url_analyzer.py             # Objective 3: Masked links & blacklists
│   ├── content_analyzer.py         # Objective 4: NLP urgency & threat cues
│   ├── attachment_analyzer.py      # Module 9.5: Double extensions & risky files
│   ├── ml_engine.py                # Objective 5: Supervised ML classifier
│   ├── risk_aggregator.py          # Objective 6: Hybrid risk aggregation
│   ├── pipeline.py                 # End-to-end detection pipeline
│   └── web/                        # Objective 7: Flask web interface
│       ├── app.py
│       ├── templates/
│       │   ├── base.html
│       │   └── index.html
│       └── static/
│           ├── css/styles.css
│           └── js/main.js
├── tests/                          # Pytest test suite (21 unit & integration tests)
├── cli.py                          # Terminal CLI utility
├── run_server.py                   # Web app launcher
├── train.py                        # Model trainer and benchmark runner
├── pytest.ini                      # Test runner configuration
├── requirements.txt                # Python dependencies
└── README.md                       # Comprehensive documentation
```
