"""
Lightweight wrapper that delegates to the unified `summarizer` when available.
Kept for backwards compatibility with scripts that import `summarize_threats`.
"""

try:
    from summarizer import summarize_threat as unified_summarize
except Exception:
    unified_summarize = None


def _simple_fallback(indicator):
    if not indicator:
        return "No indicator data"
    val = indicator.get("indicator") if isinstance(indicator, dict) else str(indicator)
    typ = indicator.get("type") if isinstance(indicator, dict) else "Unknown"
    # Provide a helpful action hint based on type
    hint = "Investigate and apply containment steps."
    t = (typ or "").lower()
    if "cve" in t:
        hint = "Check vendor advisories and apply patches."
    elif t in ("ipv4", "ip"):
        hint = "Block/monitor this IP and check logs."
    elif t in ("url", "domain"):
        hint = "Block the domain/URL and investigate referrals."
    elif "filehash" in t or "sha" in t or "md5" in t:
        hint = "Quarantine the file and scan endpoints."
    return f"{val} ({typ}) — {hint}"


def summarize_threat(indicator, pulse_title=""):
    # Prefer the unified summarizer if present
    if unified_summarize:
        try:
            return unified_summarize(indicator, pulse_title)
        except Exception:
            return _simple_fallback(indicator)
    # Fallback local summary
    return _simple_fallback(indicator)
