import google.generativeai as genai

import google.generativeai as genai

client = None


def init_client(api_key):
    """Initialize Gemini client (safe to call with None)."""
    global client
    if not api_key:
        client = None
        return
    try:
        genai.configure(api_key=api_key)
        client = genai.GenerativeModel("gemini-1.5-flash")
    except Exception:
        client = None


def _action_hint(indicator_type: str) -> str:
    t = (indicator_type or "").lower()
    if "cve" in t:
        return "Check vendor advisories and apply patches."
    if t in ("ipv4", "ip", "ip address"):
        return "Block or monitor connections from this IP and check logs."
    if t in ("url", "domain"):
        return "Block the domain/URL and investigate referrals."
    if "filehash" in t or "sha" in t or "md5" in t:
        return "Quarantine the file and scan endpoints for related activity."
    return "Investigate and apply standard detection/containment steps."


def get_prevention_hint(indicator_type: str) -> str:
    """Return a dict with a short prevention text and optional steps for the indicator type.

    Returns: { 'prevention': str, 'steps': str }
    """
    t = (indicator_type or "").lower()
    try:
        if "cve" in t:
            return {
                "prevention": "Check vendor advisories and apply patches.",
                "steps": "1) Identify affected software 2) Apply vendor patches 3) Verify via scanning"
            }
        if t in ("ipv4", "ip", "ip address"):
            return {
                "prevention": "Block or monitor connections from this IP and check logs.",
                "steps": "1) Add firewall rule to block IP 2) Check access logs 3) Create IDS rule to monitor traffic"
            }
        if t in ("url", "domain"):
            return {
                "prevention": "Block the domain/URL and investigate referrals.",
                "steps": "1) Add URL/domain to blocklist 2) Remove malicious content 3) Scan inbound emails and referrals"
            }
        if "filehash" in t or "sha" in t or "md5" in t:
            return {
                "prevention": "Quarantine the file and scan endpoints for related activity.",
                "steps": "1) Isolate affected host 2) Remove/quarantine file 3) Run full endpoint scans and update AV signatures"
            }
        return {
            "prevention": _action_hint(indicator_type),
            "steps": "Investigate and apply standard detection/containment steps."
        }
    except Exception:
        return {"prevention": "Investigate and apply containment steps.", "steps": "Investigate and contain."}


def summarize_threat(indicator, pulse_title="Unknown Threat"):
    """Return a short, useful one-line summary for an indicator.

    Behavior:
    - If Gemini client is available, ask for a concise (<=20 words) factual sentence
      describing the indicator, its likely risk, and a recommended action.
    - If the model is unavailable or returns nothing, return a deterministic
      one-line fallback that includes an action hint.
    """
    indicator_value = None
    indicator_type = None
    try:
        if isinstance(indicator, dict):
            indicator_value = indicator.get("indicator") or indicator.get("value") or "Unknown"
            indicator_type = indicator.get("type") or "Unknown"
        else:
            indicator_value = str(indicator)
            indicator_type = "Unknown"
    except Exception:
        indicator_value = str(indicator)
        indicator_type = "Unknown"

    # Deterministic fallback
    action = _action_hint(indicator_type)
    fallback = f"{indicator_value} ({indicator_type}) — {action}"

    if client is None:
        return fallback

    prompt = (
        "In ONE short sentence (max 20 words), describe: what this indicator is, the likely risk, and a recommended action. "
        "Be factual and concise; do not speculate. Output only the sentence.\n\n"
        f"Pulse: {pulse_title}\n"
        f"Indicator: {indicator_value}\n"
        f"Type: {indicator_type}"
    )

    try:
        resp = client.generate_content(prompt)
        text = None
        if resp is not None and getattr(resp, "text", None):
            text = resp.text.strip()
        if not text:
            return fallback
        # Use first line and ensure brevity
        first = text.splitlines()[0].strip()
        words = first.split()
        if len(words) > 25:
            first = " ".join(words[:25]) + "..."
        return first
    except Exception:
        return fallback