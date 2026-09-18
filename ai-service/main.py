import os
import json
import uuid
import logging
from typing import List
from datetime import datetime
from xml.sax.saxutils import escape

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from openai import OpenAI

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import mm


logger = logging.getLogger(__name__)


# ==================================================
# ENVIRONMENT
# ==================================================

load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    raise RuntimeError("OPENAI_API_KEY not found in .env file")

client = OpenAI(
    api_key=api_key,
    timeout=30.0,
    max_retries=0
)


# ==================================================
# FASTAPI APP
# ==================================================

app = FastAPI(
    title="TrustVeil AI Service",
    description="AI-powered website trust analysis service",
    version="1.0.0"
)


# ==================================================
# INPUT MODEL
# ==================================================

class WebsiteData(BaseModel):
    url: str
    domain: str
    domain_age_days: int
    safe_browsing: str
    ssl_status: str
    permissions: List[str]
    page_content: str


# ==================================================
# OUTPUT MODEL
# ==================================================

class TrustAnalysis(BaseModel):
    score: int
    risk_level: str
    confidence: str
    reason: str
    warning_signals: List[str]
    positive_signals: List[str]
    recommendation: str


def pdf_text(value):
    """Escape dynamic text before placing it in a ReportLab Paragraph."""
    return escape(str(value))


# ==================================================
# DETERMINISTIC TRUST SCORE
# ==================================================

def calculate_score(data: WebsiteData):

    score = 50

    warning_signals = []
    positive_signals = []

    # --------------------------------------------------
    # SAFE BROWSING
    # --------------------------------------------------

    if data.safe_browsing.upper() == "SAFE":

        score += 30

        positive_signals.append(
            "Safe Browsing did not flag the website."
        )

    elif data.safe_browsing.upper() == "UNSAFE":

        score -= 40

        warning_signals.append(
            "Safe Browsing flagged the website as unsafe."
        )

    # --------------------------------------------------
    # SSL
    # --------------------------------------------------

    if data.ssl_status.upper() == "VALID":

        score += 20

        positive_signals.append(
            "The website has a valid SSL/TLS certificate."
        )

    elif data.ssl_status.upper() == "INVALID":

        score -= 30

        warning_signals.append(
            "The website has an invalid SSL/TLS certificate."
        )

    # --------------------------------------------------
    # DOMAIN AGE
    # --------------------------------------------------

    if data.domain_age_days >= 365:

        score += 15

        positive_signals.append(
            f"The domain has existed for {data.domain_age_days} days."
        )

    elif data.domain_age_days < 30:

        score -= 10

        warning_signals.append(
            f"The domain is very new ({data.domain_age_days} days old)."
        )

    else:

        score += 5

    # --------------------------------------------------
    # PERMISSIONS
    # --------------------------------------------------

    permission_count = len(data.permissions)

    if permission_count == 0:

        score += 10

        positive_signals.append(
            "The website requested no browser permissions."
        )

    elif permission_count >= 3:

        score -= 10

        warning_signals.append(
            f"The website requested {permission_count} browser permissions."
        )

    # --------------------------------------------------
    # PAGE CONTENT
    # --------------------------------------------------

    suspicious_patterns = {

        "bank details":
            "The page asks for bank details.",

        "credit card":
            "The page asks for credit card information.",

        "password":
            "The page asks for a password.",

        "verify your account":
            "The page asks the user to verify an account.",

        "urgent action":
            "The page uses urgent-action language.",

        "you have won":
            "The page claims that the user has won something.",

        "prize":
            "The page contains prize-related language.",

        "claim your":
            "The page asks the user to claim something.",

        "login":
            "The page contains login-related language."
    }

    page_text = data.page_content.lower()

    content_warning_count = 0

    for pattern, message in suspicious_patterns.items():

        if pattern in page_text:

            warning_signals.append(message)

            content_warning_count += 1

    # Maximum page-content penalty = 25

    score -= min(
        content_warning_count * 5,
        25
    )

    # --------------------------------------------------
    # SCORE LIMIT
    # --------------------------------------------------

    score = max(
        0,
        min(100, score)
    )

    # --------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------

    if score >= 75:

        risk_level = "LOW"

    elif score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "HIGH"

    # --------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------

    evidence_count = 0

    if data.safe_browsing.upper() in ["SAFE", "UNSAFE"]:
        evidence_count += 1

    if data.ssl_status.upper() in ["VALID", "INVALID"]:
        evidence_count += 1

    if data.domain_age_days >= 0:
        evidence_count += 1

    if data.permissions is not None:
        evidence_count += 1

    if data.page_content.strip():
        evidence_count += 1

    if evidence_count >= 4:

        confidence = "HIGH"

    elif evidence_count >= 2:

        confidence = "MEDIUM"

    else:

        confidence = "LOW"

    return (
        score,
        risk_level,
        confidence,
        warning_signals,
        positive_signals
    )


# ==================================================
# AI EXPLANATION
# ==================================================

def generate_ai_explanation(
    data: WebsiteData,
    score: int,
    risk_level: str
):

    prompt = f"""
You are the explanation engine for TrustVeil.

TrustVeil analyzes websites using security evidence collected
by other components of the system.

Your job is ONLY to interpret the supplied evidence.

IMPORTANT RULES:

1. Use ONLY the supplied evidence.
2. Do NOT perform internet searches.
3. Do NOT invent security information.
4. Do NOT invent security checks.
5. Do NOT change the deterministic score.
6. Do NOT change the deterministic risk level.
7. A new domain is NOT automatically malicious.
8. HTTPS or SSL alone does NOT prove that a website is trustworthy.
9. Explain technical signals in simple language.
10. Do not exaggerate the evidence.
11. Mention the most important positive and negative signals.
12. Give a practical recommendation to the user.

SUPPLIED EVIDENCE

URL:
{data.url}

DOMAIN:
{data.domain}

DOMAIN AGE:
{data.domain_age_days} days

SAFE BROWSING:
{data.safe_browsing}

SSL STATUS:
{data.ssl_status}

PERMISSIONS:
{data.permissions}

PAGE CONTENT:
{data.page_content}

DETERMINISTIC TRUSTVEIL RESULT

SCORE:
{score}/100

RISK LEVEL:
{risk_level}

Return JSON containing:

reason:
A concise explanation of the result.

warning_signals:
Important warning signs supported by the evidence.

positive_signals:
Important positive signals supported by the evidence.

recommendation:
A practical recommendation for the user.

The deterministic score and risk level are authoritative.
"""

    try:

        response = client.responses.create(

            model="gpt-5.6-luna",

            input=prompt,

            text={
                "format": {

                    "type": "json_schema",

                    "name": "trust_analysis",

                    "schema": {

                        "type": "object",

                        "properties": {

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
                            "reason",
                            "warning_signals",
                            "positive_signals",
                            "recommendation"
                        ],

                        "additionalProperties": False
                    },

                    "strict": True
                }
            }
        )

        return response.output_text

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"AI explanation failed: {str(e)}"
        )


# ==================================================
# ROOT
# ==================================================

@app.get("/")
def root():

    return {
        "service": "TrustVeil AI",
        "status": "running"
    }


# ==================================================
# HEALTH
# ==================================================

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# ==================================================
# ANALYZE
# ==================================================

@app.post(
    "/analyze",
    response_model=TrustAnalysis
)
def analyze(data: WebsiteData):

    (
        score,
        risk_level,
        confidence,
        warning_signals,
        positive_signals
    ) = calculate_score(data)

    ai_result = generate_ai_explanation(
        data,
        score,
        risk_level
    )

    try:

        ai_data = json.loads(ai_result)

    except json.JSONDecodeError:

        raise HTTPException(
            status_code=500,
            detail="AI returned invalid JSON."
        )

    return TrustAnalysis(

        score=score,

        risk_level=risk_level,

        confidence=confidence,

        reason=ai_data["reason"],

        warning_signals=ai_data["warning_signals"],

        positive_signals=ai_data["positive_signals"],

        recommendation=ai_data["recommendation"]
    )


# ==================================================
# DOWNLOAD TRUSTVEIL REPORT
# ==================================================

@app.post("/report")
def generate_report(data: WebsiteData):
    # ----------------------------------------------
    # Calculate deterministic result
    # ----------------------------------------------

    (
        score,
        risk_level,
        confidence,
        warning_signals,
        positive_signals
    ) = calculate_score(data)

    # ----------------------------------------------
    # Generate AI explanation
    # ----------------------------------------------

    ai_result = generate_ai_explanation(
        data,
        score,
        risk_level
    )

    try:
        ai_data = json.loads(ai_result)
    except json.JSONDecodeError as error:
        logger.exception("AI returned invalid JSON for report")
        raise HTTPException(
            status_code=500,
            detail="AI returned invalid JSON."
        ) from error

    # ----------------------------------------------
    # Create report filename
    # ----------------------------------------------

    filename = (
        f"TrustVeil_Report_"
        f"{uuid.uuid4().hex[:8]}.pdf"
    )

    filepath = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        filename
    )

    # ----------------------------------------------
    # Create PDF
    # ----------------------------------------------

    document = SimpleDocTemplate(

        filepath,

        pagesize=A4,

        rightMargin=18 * mm,

        leftMargin=18 * mm,

        topMargin=18 * mm,

        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]

    title_style.alignment = TA_CENTER

    heading_style = styles["Heading2"]

    body_style = styles["BodyText"]

    story = []

    # ----------------------------------------------
    # HEADER
    # ----------------------------------------------

    story.append(
        Paragraph(
            "TRUSTVEIL SECURITY REPORT",
            title_style
        )
    )

    story.append(
        Spacer(1, 10)
    )

    story.append(
        Paragraph(
            f"Generated: "
            f"{datetime.now().strftime('%d %B %Y, %I:%M %p')}",
            body_style
        )
    )

    story.append(
        Spacer(1, 18)
    )

    # ----------------------------------------------
    # WEBSITE INFORMATION
    # ----------------------------------------------

    story.append(
        Paragraph(
            "Website Information",
            heading_style
        )
    )

    website_data = [

        ["URL", pdf_text(data.url)],

        ["Domain", pdf_text(data.domain)],

        [
            "Domain Age",
            pdf_text(f"{data.domain_age_days} days")
        ],

        [
            "Safe Browsing",
            pdf_text(data.safe_browsing)
        ],

        [
            "SSL Status",
            pdf_text(data.ssl_status)
        ],

        [
            "Permissions",
            pdf_text(len(data.permissions))
        ]
    ]

    website_table = Table(

        website_data,

        colWidths=[
            45 * mm,
            125 * mm
        ]
    )

    website_table.setStyle(

        TableStyle([

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),

            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )

    story.append(
        website_table
    )

    story.append(
        Spacer(1, 18)
    )

    # ----------------------------------------------
    # TRUST ASSESSMENT
    # ----------------------------------------------

    story.append(
        Paragraph(
            "TrustVeil Assessment",
            heading_style
        )
    )

    result_data = [

        ["Trust Score", f"{score} / 100"],

        ["Risk Level", risk_level],

        ["Confidence", confidence]
    ]

    result_table = Table(

        result_data,

        colWidths=[
            60 * mm,
            110 * mm
        ]
    )

    result_table.setStyle(

        TableStyle([

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),

            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(
        result_table
    )

    story.append(
        Spacer(1, 18)
    )

    # ----------------------------------------------
    # AI EXPLANATION
    # ----------------------------------------------

    story.append(
        Paragraph(
            "AI Analysis",
            heading_style
        )
    )

    story.append(
        Paragraph(
            pdf_text(ai_data["reason"]),
            body_style
        )
    )

    story.append(
        Spacer(1, 15)
    )

    # ----------------------------------------------
    # WARNING SIGNALS
    # ----------------------------------------------

    story.append(
        Paragraph(
            "Warning Signals",
            heading_style
        )
    )

    if ai_data["warning_signals"]:

        for warning in ai_data["warning_signals"]:

            story.append(
                Paragraph(
                    f"- {pdf_text(warning)}",
                    body_style
                )
            )

            story.append(
                Spacer(1, 4)
            )

    else:

        story.append(
            Paragraph(
                "No significant warning signals were identified.",
                body_style
            )
        )

    story.append(
        Spacer(1, 12)
    )

    # ----------------------------------------------
    # POSITIVE SIGNALS
    # ----------------------------------------------

    story.append(
        Paragraph(
            "Positive Signals",
            heading_style
        )
    )

    if ai_data["positive_signals"]:

        for positive in ai_data["positive_signals"]:

            story.append(
                Paragraph(
                    f"- {pdf_text(positive)}",
                    body_style
                )
            )

            story.append(
                Spacer(1, 4)
            )

    else:

        story.append(
            Paragraph(
                "No significant positive signals were identified.",
                body_style
            )
        )

    story.append(
        Spacer(1, 12)
    )

    # ----------------------------------------------
    # RECOMMENDATION
    # ----------------------------------------------

    story.append(
        Paragraph(
            "Recommendation",
            heading_style
        )
    )

    story.append(
        Paragraph(
            pdf_text(ai_data["recommendation"]),
            body_style
        )
    )

    story.append(
        Spacer(1, 15)
    )

    # ----------------------------------------------
    # EVIDENCE
    # ----------------------------------------------

    story.append(
        Paragraph(
            "Page Content Evidence",
            heading_style
        )
    )

    page_content = data.page_content[:2000]

    story.append(
        Paragraph(
            pdf_text(page_content),
            body_style
        )
    )

    story.append(
        Spacer(1, 15)
    )

    # ----------------------------------------------
    # REPORT NOTE
    # ----------------------------------------------

    story.append(
        Paragraph(
            "Assessment Note",
            heading_style
        )
    )

    story.append(
        Paragraph(
            "This report summarizes the security evidence supplied "
            "to TrustVeil. The deterministic TrustVeil assessment "
            "determines the score and risk level, while the AI "
            "provides an explanation of the supplied evidence. "
            "The AI does not independently perform security checks "
            "or override the deterministic assessment.",
            body_style
        )
    )

    # ----------------------------------------------
    # BUILD PDF
    # ----------------------------------------------

    try:
        document.build(story)
    except Exception as error:
        logger.exception("PDF build failed for domain %s", data.domain)
        raise HTTPException(
            status_code=500,
            detail=f"PDF generation failed: {error}"
        ) from error

    # ----------------------------------------------
    # RETURN DOWNLOAD
    # ----------------------------------------------

    return FileResponse(

        filepath,

        media_type="application/pdf",

        filename="TrustVeil_Security_Report.pdf"
    )
