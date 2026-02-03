import google.generativeai as genai
import re
import random

client = None

def init_client(api_key):
    """Initialize Gemini client"""
    global client
    genai.configure(api_key=api_key)
    client = genai.GenerativeModel("gemini-1.5-flash")

def score_threat(indicator, pulse_title=""):
    """Generate a numeric risk score for the given indicator using Gemini"""
    if not client:
        raise ValueError("Gemini client not initialized. Call init_client(api_key) first.")

    try:
        # 🔹 Make Gemini output ONLY a number
        prompt = (
            "You are a cybersecurity risk scorer.\n"
            "Return ONLY a single integer from 0 to 100 with no explanation or extra text.\n\n"
            f"Indicator: {indicator}\n"
            f"Pulse: {pulse_title}"
        )

        response = client.generate_content(prompt)
        score_text = response.text.strip()

        # Extract the first valid integer between 0-100
        match = re.search(r"\b([0-9]{1,3})\b", score_text)
        if match:
            score = int(match.group(1))
            if 0 <= score <= 100:
                return score

        # If Gemini gives unexpected text → fallback
        return heuristic_score(indicator, pulse_title)

    except Exception:
        # If Gemini API fails → fallback
        return heuristic_score(indicator, pulse_title)

def heuristic_score(indicator, pulse_title=""):
    """
    Fallback scoring method if Gemini fails.
    Uses simple rules + randomness for variability.
    """
    score = 50

    # Indicator-based scoring
    if indicator.startswith(("http://", "https://")):
        score += 10
    elif indicator.count(".") == 3:  # IPv4
        score += 5
    elif len(indicator) > 30:  # likely file hash
        score += 15
    elif ".gov" in indicator or ".mil" in indicator:
        score += 20

    # Pulse title-based scoring
    title = (pulse_title or "").lower()
    if any(word in title for word in ["apt", "ransomware", "exploit", "malware"]):
        score += 20
    elif any(word in title for word in ["phishing", "spam", "suspicious"]):
        score += 10

    # Random variance
    score += random.randint(-5, 5)

    return max(0, min(100, score))