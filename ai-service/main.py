import os
import json

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from openai import OpenAI
from pydantic import BaseModel


# Load environment variables
load_dotenv()


# Create FastAPI application
app = FastAPI(title="TrustVeil AI Service")


# Load OpenAI API key
api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    raise RuntimeError("OPENAI_API_KEY is not configured")


# Create OpenAI client
client = OpenAI(api_key=api_key)


# Data received from the TrustVeil backend
class AnalyzeRequest(BaseModel):
    url: str | None = None
    domain: str | None = None
    domain_age_days: int | None = None
    safe_browsing: str | None = None
    ssl_status: str | None = None
    permissions: list[str] | None = None
    page_content: str | None = None


# Calculate a deterministic baseline score
def calculate_base_score(data):
    score = 0
    evidence_count = 0
    maximum_possible_score = 0

    # Safe Browsing
    if data.safe_browsing:
        evidence_count += 1
        maximum_possible_score += 40

        status = data.safe_browsing.upper()

        if status == "SAFE":
            score += 40

        elif status == "UNSAFE":
            score -= 40

    # SSL
    if data.ssl_status:
        evidence_count += 1
        maximum_possible_score += 25

        status = data.ssl_status.upper()

        if status == "VALID":
            score += 25

        elif status == "INVALID":
            score -= 25

    # Domain age
    if data.domain_age_days is not None:
        evidence_count += 1
        maximum_possible_score += 15

        if data.domain_age_days >= 365:
            score += 15

        elif data.domain_age_days < 30:
            score -= 10

    # Permissions
    if data.permissions is not None:
        evidence_count += 1
        maximum_possible_score += 10

        if len(data.permissions) == 0:
            score += 10

        elif len(data.permissions) >= 3:
            score -= 10

    # Page content
    if data.page_content:
        evidence_count += 1
        maximum_possible_score += 10

        content = data.page_content.lower()

        suspicious_terms = [
            "enter your bank details",
            "claim your prize",
            "you have won",
            "send money",
            "verify your account"
        ]

        if any(term in content for term in suspicious_terms):
            score -= 10
        else:
            score += 10

    # No security evidence available
    if maximum_possible_score == 0:
        return 50, 0

    # Convert the evidence score into a 0–100 range
    normalized_score = (
        50 + (score / maximum_possible_score) * 50
    )

    normalized_score = round(
        max(0, min(100, normalized_score))
    )

    # Keep the score aligned with TrustVeil risk bands
    if 71 <= normalized_score <= 89:
        if normalized_score >= 80:
            normalized_score = 70
        else:
            normalized_score = 40

    return normalized_score, evidence_count


# Instructions given to the AI
SYSTEM_PROMPT = """
You are the AI analysis engine for TrustVeil.

TrustVeil receives security information collected by its backend.
Your job is to interpret those signals and produce a trust analysis.

Rules:

1. Only use information supplied in the input.
2. Never invent security evidence.
3. Never claim that you personally performed WHOIS, SSL,
   Safe Browsing, permission, or internet checks.
4. If information is missing, treat it as unavailable.
5. Missing information must reduce confidence, not automatically
   be treated as a warning signal.
6. Consider both positive and warning signals.
7. Do not classify a website as dangerous only because
   its domain is new.
8. Give an evidence-based explanation.
9. A URL using HTTPS does not by itself prove that the SSL
   certificate is valid. Use ssl_status when available.
10. Use the supplied deterministic baseline score as the
    starting point.
11. Do not arbitrarily invent a completely different score.
12. Return only the requested JSON structure.

Risk categories:

LOW:
score 90 or above

MEDIUM:
score 40 through 70

HIGH:
score below 40

Confidence:

HIGH confidence requires several meaningful security signals.

MEDIUM confidence means some useful security evidence is available
but important signals are missing.

LOW confidence means very little security evidence is available.
"""


# Required TrustVeil AI response structure
OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "score": {
            "type": "integer",
            "minimum": 0,
            "maximum": 100
        },
        "risk_level": {
            "type": "string",
            "enum": ["LOW", "MEDIUM", "HIGH"]
        },
        "confidence": {
            "type": "string",
            "enum": ["LOW", "MEDIUM", "HIGH"]
        },
        "reason": {
            "type": "string"
        },
        "warning_signals": {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
        "positive_signals": {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
        "recommendation": {
            "type": "string"
        }
    },
    "required": [
        "score",
        "risk_level",
        "confidence",
        "reason",
        "warning_signals",
        "positive_signals",
        "recommendation"
    ],
    "additionalProperties": False
}


# Basic service check
@app.get("/")
def root():
    return {
        "message": "TrustVeil AI Service is running"
    }


# Health check
@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# Main AI analysis endpoint
@app.post("/analyze")
def analyze(data: AnalyzeRequest):

    # Convert incoming request into a dictionary
    input_data = data.model_dump(exclude_none=True)

    # Don't process an empty request
    if not input_data:
        raise HTTPException(
            status_code=400,
            detail="No security signals were provided"
        )

    # Calculate deterministic baseline score
    base_score, evidence_count = calculate_base_score(data)

    # Prompt containing the backend's security information
    user_prompt = f"""
Analyze the following website security information.

INPUT:

{json.dumps(input_data, indent=2)}

DETERMINISTIC BASELINE SCORE:

{base_score}

NUMBER OF AVAILABLE SECURITY SIGNALS:

{evidence_count}

Use the deterministic baseline score as the starting point.

The final score must remain exactly equal to the deterministic
baseline score.

Do not adjust, increase, decrease, or invent a different score.

Interpret the supplied evidence and explain the result.

Do not invent missing security information.

If important security signals are unavailable, reflect that
primarily through the confidence level and explanation.

Make sure the reason is consistent with the final score.

Return the TrustVeil analysis using the required JSON schema.
"""

    try:

        response = client.responses.create(
            model="gpt-5.6-luna",
            input=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ],
            text={
                "format": {
                    "type": "json_schema",
                    "name": "trust_analysis",
                    "strict": True,
                    "schema": OUTPUT_SCHEMA
                }
            }
        )

        # Convert AI JSON response into Python dictionary
        result = json.loads(response.output_text)

        # Keep our deterministic score as the final score
        result["score"] = base_score

        # Keep risk level consistent with the final score
        if base_score >= 90:
            result["risk_level"] = "LOW"

        elif base_score < 40:
            result["risk_level"] = "HIGH"

        else:
            result["risk_level"] = "MEDIUM"

        return result

    except Exception as error:

        # Print the complete error in the Uvicorn terminal
        print("OPENAI ERROR:", repr(error))

        raise HTTPException(
            status_code=500,
            detail=f"AI analysis failed: {str(error)}"
        )