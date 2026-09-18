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
            "origins": "chrome-extension://kkgokdleapgndbfkaecnebceokciokio"
        }
    },
    methods=["POST", "OPTIONS"],
    allow_headers=["Content-Type"]
)

SANA_API_URL = "https://building-cemetery-russia-citations.trycloudflare.com/analyze"


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

    ai_result = send_to_ai(data)

    if ai_result is None:
      return jsonify({
        "error": "AI analysis failed",
        "enriched_data": data
    }), 502

    return jsonify(ai_result)

if __name__ == "__main__":
    app.run(debug=True)