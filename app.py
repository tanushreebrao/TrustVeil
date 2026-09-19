from flask import Flask, jsonify, request
from flask_cors import CORS
from urllib.parse import urlparse
import whois
import os
import requests
import socket
import ssl

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/analyze": {
            "origins": "chrome-extension://kkgodlkeaepdngnbfkaecnebceocikio"
        }
    },
    methods=["POST", "OPTIONS"],
    allow_headers=["Content-Type"]
)

SANA_API_URL = os.getenv("SANA_API_URL")


@app.route("/")
def home():
    return jsonify({
        "message": "TrustVeil server is running!"
    })

def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)

        creation_date = domain_info.creation_date

        if not creation_date:
            return None

        # Some domains can return multiple creation dates
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)

        # Make creation date timezone-aware if necessary
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age = now - creation_date

        return age.days

    except Exception as e:
        print("WHOIS lookup failed:", e)
        return None



def check_safe_browsing(url):
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

    if not api_key:
        print("Safe Browsing API key not found")
        return "unknown"

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={api_key}"
    )

    payload = {
        "client": {
            "clientId": "trustveil",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": [
                "ANY_PLATFORM"
            ],
            "threatEntryTypes": [
                "URL"
            ],
            "threatEntries": [
                {
                    "url": url
                }
            ]
        }
    }

    try:
        response = requests.post(endpoint, json=payload)

        if response.status_code != 200:
            print("Safe Browsing error:", response.status_code)
            print(response.text)
            return "unknown"

        result = response.json()

        if "matches" in result:
            return "flagged"

        return "not_flagged"

    except Exception as e:
        print("Safe Browsing request failed:", e)
        return "unknown"

def check_ssl_status(url):
    parsed_url = urlparse(url)

    # SSL/TLS only applies to HTTPS
    if parsed_url.scheme != "https":
        return "not_applicable"

    hostname = parsed_url.hostname

    if not hostname:
        return "unknown"

    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return "valid"

    except ssl.CertificateError:
        return "invalid"

    except ssl.SSLError:
        return "invalid"

    except Exception as e:
        print("SSL check failed:", e)
        return "unknown"
    

def send_to_ai(enriched_data):
    try:
        response = requests.post(
            SANA_API_URL,
            json=enriched_data,
            timeout=30
        )

        if response.status_code != 200:
            print("AI API error:", response.status_code)
            print(response.text)
            return None

        return response.json()

    except requests.exceptions.RequestException as e:
        print("AI API request failed:", e)
        return None

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No JSON data received"
        }), 400

    required_fields = [
        "url",
        "https",
        "permissions",
        "page_text",
        "login_required",
        "payment_information_requested"
    ]

    missing_fields = []

    for field in required_fields:
        if field not in data:
            missing_fields.append(field)

    if missing_fields:
        return jsonify({
            "error": "Missing required fields",
            "fields": missing_fields
        }), 400
    
    parsed_url = urlparse(data["url"])
    domain = parsed_url.hostname

    print("Extracted domain:", domain)
    domain_age_days = get_domain_age(domain)

    print("Domain age:", domain_age_days, "days")

    safe_browsing = check_safe_browsing(data["url"])

    print("Safe Browsing:", safe_browsing)
    ssl_status = check_ssl_status(data["url"])

    print("SSL status:", ssl_status)

    print("Received valid TrustVeil data:")
    print(data)

    data["domain_age_days"] = domain_age_days
    data["safe_browsing"] = safe_browsing
    data["ssl_status"] = ssl_status
    data["domain"] = domain
    data["page_content"] = data.get("page_text", "")

    ai_result = send_to_ai(data)

    ai_result = send_to_ai(data)

    if ai_result is None:
      print("AI unavailable — using local TrustVeil fallback")

    score = 50
    warnings = []
    positives = []

    # Safe Browsing
    if data.get("safe_browsing") == "flagged":
        score -= 60
        warnings.append("The website was flagged by Safe Browsing.")
    elif data.get("safe_browsing") == "not_flagged":
        score += 5
        positives.append("The website is not currently flagged by Safe Browsing.")

    # SSL
    if data.get("ssl_status") == "valid":
        score += 15
        positives.append("The website has a valid SSL certificate.")
    elif data.get("ssl_status") == "invalid":
        score -= 25
        warnings.append("The website has an invalid SSL certificate.")

    # Domain age
    age = data.get("domain_age_days")

    if age is not None:
        if age < 30:
            score -= 20
            warnings.append("The domain is very new.")
        elif age >= 365:
            score += 15
            positives.append("The domain has been registered for more than a year.")

    # Login / payment requests
    if data.get("login_required"):
        score -= 5
        warnings.append("The website requests login credentials.")

    if data.get("payment_information_requested"):
        score -= 10
        warnings.append("The website requests payment information.")

    # URL checks
    url = data.get("url", "").lower()

    if "xn--" in url:
        score -= 20
        warnings.append("The URL contains punycode, which can be associated with lookalike domains.")

    # Page-content checks
    page_content = data.get("page_content", "").lower()

    suspicious_terms = [
        "verify your account",
        "urgent action",
        "confirm your password",
        "account suspended",
        "claim your reward",
        "click here immediately"
    ]

    found_terms = [term for term in suspicious_terms if term in page_content]

    if found_terms:
        score -= min(30, len(found_terms) * 10)
        warnings.append("The page contains suspicious or urgent language.")

    # Keep score between 0 and 100
    score = max(0, min(100, score))

    if score >= 70:
        risk_level = "LOW"
    elif score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    ai_result = {
        "trust_score": score,
        "score": score,
        "risk_level": risk_level,
        "confidence": 65,
        "reason": "AI analysis was temporarily unavailable. This result was generated using TrustVeil's rule-based security signals.",
        "warnings": warnings,
        "positives": positives,
        "recommendation": (
            "The website appears relatively low risk based on the available signals."
            if risk_level == "LOW"
            else
            "Review the warnings carefully before entering sensitive information."
            if risk_level == "MEDIUM"
            else
            "Avoid entering sensitive information until the website can be verified."
        )
    }

# Send high-risk results to n8n
    is_high_risk = (
    ai_result.get("risk_level") == "HIGH"
    or "amts" in data.get("url", "").lower()
)

    if is_high_risk:
        try:
           requests.post(
            "https://tanushreebrao.app.n8n.cloud/webhook/trustveil",
            json={
                "domain": data.get("domain"),
                "trust_score": ai_result.get("trust_score"),
                "risk_level": ai_result.get("risk_level"),
                "confidence": ai_result.get("confidence")
            },
            timeout=5
        )
        except Exception as e:
            print("n8n logging failed:", e)

    return jsonify(ai_result)