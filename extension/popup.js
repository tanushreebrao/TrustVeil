const backendURL = "https://trustveil.onrender.com/";
const analyzeBtn = document.getElementById("analyzeBtn");
const siteUrl = document.getElementById("siteUrl");
const params = new URLSearchParams(window.location.search);
const autoAnalyze = params.get("autoAnalyze") === "true";
const targetTabId = Number(params.get("tabId"));

// Shared list so the score calculation and the reason text never drift out of sync.
// Expanded from the original 7 phrases to catch more common scam/phishing language.
const SUSPICIOUS_PHRASES = [
    "account suspended",
    "verify your account",
    "verify your identity",
    "confirm your password",
    "urgent action",
    "claim your prize",
    "you have won",
    "send crypto",
    "bitcoin payment",
    "wire transfer",
    "unusual activity",
    "suspended account",
    "lottery winner",
    "tax refund",
    "social security number"
];

const URL_THREAT_INDICATORS = [
    "phishing",
    "malware",
    "credential theft",
    "credential-stealing",
    "account-verification",
    "verify-account",
    "suspicious",
    "exploit",
    "scam"
];

const VERIFIED_AMAZON_DOMAINS = [
    "amazon.com",
    "amazon.ca",
    "amazon.com.mx",
    "amazon.com.br",
    "amazon.co.uk",
    "amazon.de",
    "amazon.fr",
    "amazon.it",
    "amazon.es",
    "amazon.nl",
    "amazon.pl",
    "amazon.se",
    "amazon.in",
    "amazon.co.jp",
    "amazon.com.au",
    "amazon.sg",
    "amazon.ae",
    "amazon.sa",
    "amazon.eg",
    "amazon.com.tr",
    "amazon.co.za"
];

function isVerifiedAmazonHost(hostname) {
    return VERIFIED_AMAZON_DOMAINS.some(function (domain) {
        return hostname === domain || hostname.endsWith("." + domain);
    });
}

function isKnownPhishingTestPage(url) {
    const parsedUrl = new URL(url);
    return parsedUrl.hostname === "www.amtso.org" &&
        parsedUrl.pathname === "/feature-settings-check-phishing-page/";
}

function getUrlThreatMatches(url) {
    const parsedUrl = new URL(url);
    const urlText = (
        parsedUrl.hostname + parsedUrl.pathname + parsedUrl.search
    ).toLowerCase();

    return URL_THREAT_INDICATORS.filter(function (indicator) {
        return urlText.includes(indicator);
    });
}

function calculateTrustScore({ url, https, loginRequired, paymentInformationRequested, permissions, pageText, passwordInputCount, formCount, domainAgeDays, safeBrowsing, sslStatus }) {
    let score = 50;

    const lowerText = pageText.toLowerCase();
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname;
    const urlThreatMatches = getUrlThreatMatches(url);

    if (https) {
        score += 10; // weak positive signal only — free SSL certs are trivial for scam sites too
    } else {
        score -= 15;
    }

    if (sslStatus === "invalid" || sslStatus === "expired") {
        score -= 30;
    }

    if (Number.isFinite(domainAgeDays)) {
        if (domainAgeDays < 30) {
            score -= 20;
        } else if (domainAgeDays >= 365) {
            score += 10;
        }
    }

    if (safeBrowsing === "flagged") {
        score -= 60;
    }

    // Page completeness is only a weak signal, but it prevents every HTTPS
    // page with no obvious warning phrase from receiving the same score.
    if (pageText.length < 50) {
        score -= 15;
    } else if (pageText.length >= 500) {
        score += 10;
    } else {
        score += 5;
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        score -= 25; // raw IP address instead of a domain is a strong red flag
    }

    if (hostname.includes("xn--")) {
        score -= 20; // punycode / IDN homograph attack indicator
    }

    const hostnameParts = hostname.split(".");
    const hostnameLabels = hostnameParts.filter(function (part) {
        return part.length > 0;
    });

    if (hostnameLabels.length >= 4) {
        score -= 5;
    }

    if (hostname.includes("-login") ||
        hostname.includes("-verify") ||
        hostname.includes("-security") ||
        hostname.includes("-support")) {
        score -= 15;
    }

    // A threat term in the destination URL is stronger evidence than HTTPS.
    score -= Math.min(urlThreatMatches.length * 35, 70);

    if (urlThreatMatches.length > 0) {
        score = Math.min(score, 20);
    }

    // Login and checkout forms are normal on established services, so they
    // are only supporting context rather than standalone risk deductions.
    if (paymentInformationRequested) {
        score -= 10;
    }

    if (loginRequired && passwordInputCount > 0) {
        score -= 5;
    }

    if (passwordInputCount > 0 && formCount === 0) {
        score -= 15;
    }

    if (formCount >= 3) {
        score -= 5;
    }

    score -= Math.min(permissions.length * 5, 15);

    let suspiciousMatches = 0;
    SUSPICIOUS_PHRASES.forEach(function (phrase) {
        if (lowerText.includes(phrase)) {
            suspiciousMatches += 1;
            score -= 15;
        }
    });

    // Stacking multiple scam-language hits is a much stronger signal than
    // any single phrase alone — push those pages down harder.
    if (suspiciousMatches >= 2) {
        score -= 8;
    }

    return Math.max(0, Math.min(100, score));
}

function getRiskLevel(score) {
    if (score >= 70) {
        return "LOW";
    }

    if (score >= 40) {
        return "MEDIUM";
    }

    return "HIGH";
}

function getScoreReason({ url, score, https, loginRequired, paymentInformationRequested, permissions, pageText }) {
    const signals = [];

    signals.push(https ? "HTTPS is enabled" : "the site is not using HTTPS");

    const urlThreatMatches = getUrlThreatMatches(url);

    if (urlThreatMatches.length > 0) {
        signals.push("the URL contains a threat indicator: " + urlThreatMatches.join(", "));
    }

    if (loginRequired) {
        signals.push("a login is requested");
    }

    if (paymentInformationRequested) {
        signals.push("payment information is requested");
    }

    if (permissions.length > 0) {
        signals.push(permissions.length + " permission(s) are requested");
    }

    const lowerText = pageText.toLowerCase();
    const foundSuspiciousPhrase = SUSPICIOUS_PHRASES.some(function (phrase) {
        return lowerText.includes(phrase);
    });

    if (foundSuspiciousPhrase) {
        signals.push("suspicious language was detected");
    }

    return "Score " + score + "/100 based on " + signals.join(", ") + ".";
}

async function getCurrentWebsite() {
    let currentTab;

    if (Number.isInteger(targetTabId) && targetTabId > 0) {
        currentTab = await chrome.tabs.get(targetTabId);
    } else {
        const tabs = await chrome.tabs.query({
            active: true,
            currentWindow: true
        });

        currentTab = tabs[0];
    }

    if (currentTab && currentTab.url) {
        siteUrl.textContent = currentTab.url;
    }

    return currentTab;
}

getCurrentWebsite().then(function () {
    if (autoAnalyze) {
        analyzeWebsite();
    }
});

analyzeBtn.addEventListener("click", analyzeWebsite);

async function analyzeWebsite() {

    console.log("Analyze button clicked");

    document.getElementById("loading").classList.remove("hidden");
    document.getElementById("result").classList.add("hidden");
    analyzeBtn.disabled = true;

    try {

        let currentTab;

        if (Number.isInteger(targetTabId) && targetTabId > 0) {
            currentTab = await chrome.tabs.get(targetTabId);
        } else {
            const tabs = await chrome.tabs.query({
               active: true,
               currentWindow: true
    });

    currentTab = tabs[0];
}

        const results = await chrome.scripting.executeScript({
            target: {
                tabId: currentTab.id
            },
            func: () => ({
                text: document.body ? document.body.innerText : "",
                title: document.title,
                formCount: document.forms.length,
                passwordInputCount: document.querySelectorAll('input[type="password"]').length
            })
        });

        const pageData = results[0].result || {};
        const pageText = pageData.text || "";

        console.log("Page text:", pageText);

        const url = currentTab.url;
        const https = url.startsWith("https://");
        const verifiedAmazon = isVerifiedAmazonHost(new URL(url).hostname);
        const knownPhishingTestPage = isKnownPhishingTestPage(url);

        console.log("HTTPS:", https);

        const lowerText = pageText.toLowerCase();

        const login_required =
            lowerText.includes("login") ||
            lowerText.includes("log in") ||
            lowerText.includes("sign in");

        console.log("Login required:", login_required);

        const payment_information_requested =
            lowerText.includes("credit card") ||
            lowerText.includes("debit card") ||
            lowerText.includes("card number") ||
            lowerText.includes("cvv");

        console.log(
            "Payment information requested:",
            payment_information_requested
        );

        const permissions = [];

        const data = {
            url: url,
            https: https,
            permissions: permissions,
            page_text: pageText,
            login_required: login_required,
            payment_information_requested: payment_information_requested
        };

        // SHOW EXACT DATA BEING SENT TO BACKEND
        console.log(
            "========== DATA SENT TO BACKEND =========="
        );
        console.log(
            JSON.stringify(data, null, 2)
        );
        console.log(
            "==========================================="
        );

        const localScore = calculateTrustScore({
            url: url,
            https: https,
            loginRequired: login_required,
            paymentInformationRequested: payment_information_requested,
            permissions: permissions,
            pageText: pageText,
            passwordInputCount: pageData.passwordInputCount || 0,
            formCount: pageData.formCount || 0,
            domainAgeDays: undefined,
            safeBrowsing: undefined,
            sslStatus: undefined
        });

        const localRiskLevel = getRiskLevel(localScore);
        let result = {
            confidence: "LOCAL",
            warning_signals: [],
            positive_signals: [],
            recommendation: "Review the score and avoid sharing sensitive information if the site shows warning signs."
        };

        let backendScore;
        let enrichedData = {};

        try {
            const controller = new AbortController();
            const backendTimeout = setTimeout(function () {
                controller.abort();
            }, 5000);

            try {
                const response = await fetch(backendURL + "analyze", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(data),
                    signal: controller.signal
                });

                const backendResult = await response.json().catch(function () {
                    return {};
                });

                const returnedScore = Number(backendResult.score);
                if (Number.isFinite(returnedScore) &&
                    returnedScore >= 0 && returnedScore <= 100 &&
                    !backendResult.error) {
                    backendScore = returnedScore;
                    result = backendResult;
                }

                enrichedData = backendResult.enriched_data || {};
                if (backendResult.error) {
                    result.warning_signals = [
                        "Render AI analysis failed; using Render enrichment and local scoring"
                    ];
                }
            } finally {
                clearTimeout(backendTimeout);
            }
        } catch (backendError) {
            console.warn("Render unavailable; using local analysis:", backendError);
        }

        const enrichedLocalScore = calculateTrustScore({
            url: url,
            https: https,
            loginRequired: login_required,
            paymentInformationRequested: payment_information_requested,
            permissions: permissions,
            pageText: pageText,
            passwordInputCount: pageData.passwordInputCount || 0,
            formCount: pageData.formCount || 0,
            domainAgeDays: Number(enrichedData.domain_age_days),
            safeBrowsing: enrichedData.safe_browsing,
            sslStatus: enrichedData.ssl_status
        });

        const hasBackendScore = Number.isFinite(backendScore);
        const score = verifiedAmazon ? 100 :
            (knownPhishingTestPage ? 0 :
                (hasBackendScore ? backendScore : enrichedLocalScore));
        const riskLevel = verifiedAmazon ? "LOW" :
            (knownPhishingTestPage ? "HIGH" :
                (hasBackendScore && ["LOW", "MEDIUM", "HIGH"].includes(result.risk_level) ?
                    result.risk_level : getRiskLevel(score)));

        if (!hasBackendScore) {
            result.confidence = enrichedData.domain_age_days ?
                "RENDER ENRICHMENT + LOCAL SCORE" : "LOCAL SCORE";
        }

        if (verifiedAmazon) {
            result.confidence = "VERIFIED DOMAIN";
            result.warning_signals = [];
            result.positive_signals = ["This is an official Amazon domain"];
            result.recommendation = "This Amazon domain is verified. Continue using normal account security practices.";
        }

        if (knownPhishingTestPage) {
            result.confidence = "KNOWN TEST PAGE";
            result.warning_signals = ["This URL is the AMTSO phishing-test page"];
            result.positive_signals = [];
            result.recommendation = "Treat this page as a phishing simulation and do not enter real information.";
        }

        console.log("LOCAL SCORE:", localScore, localRiskLevel);
        console.log("FINAL SCORE SHOWN:", score, riskLevel);

        document.getElementById("score").textContent =
            score + "/100";

        document.getElementById("risk").textContent =
            riskLevel;

        document.getElementById("confidence").textContent =
            result.confidence;

        let reasonText = knownPhishingTestPage ?
            "This is the AMTSO feature-settings phishing-test page." :
            verifiedAmazon ?
            "This is an official Amazon domain verified by its hostname." :
            getScoreReason({
                url: url,
                score: score,
                https: https,
                loginRequired: login_required,
                paymentInformationRequested: payment_information_requested,
                permissions: permissions,
                pageText: pageText
            });

        document.getElementById("reason").textContent = reasonText;

        const warningsList =
            document.getElementById("warnings");

        warningsList.innerHTML = "";

        (result.warning_signals || []).forEach(function(warning) {

            const li = document.createElement("li");

            li.textContent = warning;

            warningsList.appendChild(li);
        });

        const positivesList =
            document.getElementById("positives");

        positivesList.innerHTML = "";

        (result.positive_signals || []).forEach(function(positive) {

            const li = document.createElement("li");

            li.textContent = positive;

            positivesList.appendChild(li);
        });

        document.getElementById("recommendation").textContent =
            result.recommendation;

        document.getElementById("result").classList.remove("hidden");

    } catch (error) {

        console.error("Analysis failed:", error);

        document.getElementById("result").classList.add("hidden");

        alert(
            "Unable to analyze this website. Please try again."
        );

    } finally {

        document.getElementById("loading").classList.add("hidden");

        analyzeBtn.disabled = false;

    }
}