import re

PHISHING_KEYWORDS = [
    "verify your account", "urgent", "click here", "login now",
    "suspended", "bank", "password", "update payment", "confirm identity",
    "limited time", "act immediately"
]

def analyze_text(text):
    t = text.lower()
    score = 0
    reasons = []

    for kw in PHISHING_KEYWORDS:
        if kw in t:
            score += 15
            reasons.append(f"Suspicious keyword detected: {kw}")

    urls = re.findall(r'https?://\S+|www\.\S+', text)
    if urls:
        score += min(20, len(urls) * 5)
        reasons.append(f"{len(urls)} URL(s) detected")

    if re.search(r'\b(bit\.ly|tinyurl\.com|t\.co)\b', t):
        score += 20
        reasons.append("URL shortener detected")

    if score >= 50:
        label = "PHISHING"
    elif score >= 25:
        label = "SUSPICIOUS"
    else:
        label = "SAFE"

    confidence = min(99, max(50, score + 40 if label != "SAFE" else 95 - score))
    return {
        "label": label,
        "confidence": confidence,
        "score": score,
        "reasons": reasons or ["No strong phishing indicators found."]
    }
