# 🛡️ TrustVeil

### AI-Powered Web Trust Layer

TrustVeil is an explainable web security system that analyzes websites using multiple independent security signals and provides a trust/risk assessment before users interact with potentially suspicious pages.

Instead of relying on a single indicator such as HTTPS or reputation, TrustVeil combines domain intelligence, URL characteristics, browser-level signals, security checks, and contextual page evidence to explain **why** a website may be trustworthy or risky.

---

## 🚨 Problem

Modern phishing websites can closely imitate legitimate websites and may use:

- Valid HTTPS certificates
- Newly registered domains
- Trusted-looking page designs
- Brand impersonation
- Login and payment forms
- Suspicious redirects or navigation
- Social-engineering content

Therefore, a single security check is not sufficient to determine whether a website should be trusted.

---

## 💡 Solution

TrustVeil acts as a web trust layer between the user and the website.

It collects multiple observable signals and combines them into an explainable risk assessment.

### TrustVeil analyzes signals such as:

- 🔗 URL characteristics
- 🌐 Domain information
- 📅 Domain age
- 🔒 SSL/TLS certificate status
- 🛡️ Google Safe Browsing status
- 🔑 Permission requests
- 📝 Page-level content and forms
- 💳 Login/payment-related indicators
- 🤖 AI-assisted contextual analysis

The system then provides:

- Trust score
- Risk level
- Confidence
- Warning signals
- Positive signals
- Recommendation

---

## 🏗️ Architecture

```text
                    ┌─────────────────────┐
                    │      Website        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Chrome Extension    │
                    │ Browser Signals     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Flask Backend     │
                    │   /analyze API      │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
        ┌───────────┐    ┌────────────┐   ┌───────────┐
        │   WHOIS   │    │    SSL     │   │   Safe    │
        │ Domain Age│    │ Certificate│   │ Browsing  │
        └───────────┘    └────────────┘   └───────────┘
              │                │                │
              └────────────────┼────────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    AI Service       │
                    │     FastAPI         │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ TrustVeil Assessment │
                    │ Score + Risk + Why   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Chrome Extension    │
                    │ User Result          │
                    └─────────────────────┘

                    HIGH-RISK RESULTS
                           │
                           ▼
                    ┌─────────────────────┐
                    │       n8n           │
                    │ Security Logging    │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Google Sheets    │
                    │ Security Log        │
                    └─────────────────────┘

✨ Key Features
🔍 Multi-Signal Website Analysis

TrustVeil does not depend on a single security indicator. It combines multiple signals to produce a more contextual assessment.

🧠 Explainable AI Analysis

The AI service converts the collected evidence into an understandable security assessment instead of simply returning a binary safe/unsafe result.

🔒 SSL/TLS Analysis

TrustVeil checks the website's SSL/TLS certificate status.

A valid certificate indicates an encrypted connection but does not, by itself, establish that a website is trustworthy.

🌐 Domain Intelligence

WHOIS information is used to obtain domain information such as domain age.

🛡️ Google Safe Browsing

TrustVeil checks whether the URL is identified by Google Safe Browsing as an unsafe resource.

A URL that is not flagged should not automatically be interpreted as trusted.

🧩 Browser Extension

The Chrome extension provides the user with a convenient interface for analyzing the current website.

📊 Risk Assessment

The result includes information such as:

Trust Score
Risk Level
Confidence
Warning Signals
Positive Signals
Recommendation

🚨 High-Risk Security Logging

High-risk results can be sent to an n8n workflow for structured logging and downstream automation.

The current workflow stores security events in Google Sheets.

🛠️ Tech Stack

Frontend / Browser
JavaScript
HTML
CSS
Chrome Extension Manifest V3
Backend
Python
Flask
Flask-CORS
WHOIS
Requests
AI Service
Python
FastAPI
OpenAI API
Security Services
Google Safe Browsing API
SSL/TLS certificate inspection
WHOIS domain information
Automation
n8n
Google Sheets
Deployment
Render
Development
Git
GitHub
GitHub Actions

📁 Project Structure

TrustVeil/
│
├── .github/
│   └── workflows/
│       └── ...
│
├── ai-service/
│   └── ...
│
├── extension/
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   ├── popup.css
│   ├── content.js
│   ├── content.css
│   └── background.js
│
├── app.py
├── requirements.txt
├── test.json
├── .gitignore
└── README.md

🔄 How TrustVeil Works

1. User visits a website

The Chrome extension operates on the current browser page.

2. Browser-level signals are collected

The extension can provide contextual information such as:

Current URL
Permissions
Page text
Login indicators
Payment-related indicators

3. Flask backend enriches the request

The backend performs additional security checks including:

Domain extraction
WHOIS/domain age lookup
SSL status check
Google Safe Browsing lookup

4. Evidence is sent to the AI service

The collected information is passed to the TrustVeil AI service for contextual analysis.

5. TrustVeil generates an assessment

The system returns an explainable result containing risk information and supporting signals.

6. Result is displayed to the user

The Chrome extension presents the assessment through the TrustVeil interface.

7. High-risk results can be logged

High-risk security events can be sent to n8n and recorded in Google Sheets.

🔌 API

POST /analyze

Analyzes a website using the supplied security context.

Example request:

{
  "url": "https://example.com",
  "permissions": [],
  "page_text": "Example website content",
  "login_required": false,
  "payment_information_requested": false
}

The backend enriches the request with additional information such as:

domain
domain_age_days
safe_browsing
ssl_status

The final response contains the TrustVeil assessment.

🔐 Security & Privacy

TrustVeil is designed around observable website and browser signals.

Sensitive credentials, passwords, payment details, and API keys should not be included in the repository.

Environment variables are used for service credentials such as API keys and service URLs.

Example:

GOOGLE_SAFE_BROWSING_API_KEY=...
SANA_API_URL=...

Never commit actual secret values to GitHub.

🚀 Local Setup

1. Clone the repository
git clone https://github.com/tanushreebrao/TrustVeil.git
cd TrustVeil
2. Create a virtual environment
python -m venv venv
3. Activate the environment
Windows
venv\Scripts\activate
4. Install dependencies
pip install -r requirements.txt
5. Configure environment variables
Create a .env file or configure the required environment variables.
Do not commit the .env file.
6. Run the Flask backend
python app.py
🌐 Loading the Chrome Extension
Open Chrome.
Navigate to:
chrome://extensions/
Enable Developer mode.
Select Load unpacked.
Select the extension folder.
Open a website and launch TrustVeil.

🔁 CI/CD

TrustVeil uses GitHub Actions to perform basic backend validation.

The CI workflow checks that:

Dependencies can be installed.
Python syntax is valid.
Backend code can be compiled successfully.

📈 Future Scope

Potential future improvements include:

More advanced URL and domain similarity detection
Typosquatting and brand-impersonation analysis
Redirect-chain analysis
Form submission destination analysis
Permission-risk analysis
Improved behavioral browser signals
Additional reputation sources
More detailed security provenance
Improved local fallback analysis
Expanded automated security workflows

🎯 Project Vision

TrustVeil aims to make website security more understandable and contextual.

Instead of simply asking:

"Is this website safe?"

TrustVeil aims to answer:

"What signals were observed, what do they indicate, and why should I be cautious?"

👥 Team
Team VALKYRIE CORE

TrustVeil — AI-Powered Web Trust Layer

Built for DSU DevHack 3.0.
