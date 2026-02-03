import os
import json
import argparse
import requests
from dotenv import load_dotenv

# Optional summarizer
try:
    from summarize_threats import summarize_threat
    HAS_SUMMARIZER = True
except Exception:
    HAS_SUMMARIZER = False

# Load env
load_dotenv()

API_KEY = os.getenv("API_KEY")
API_EXPORT_URL = os.getenv("API_EXPORT_URL") or os.getenv("API_EXPORT_URL")
OUTPUT_FILE = os.getenv("THREATS_OUTPUT", "recent_threats.json")
DEFAULT_LIMIT = int(os.getenv("THREATS_LIMIT", "15"))
DEFAULT_MODIFIED_SINCE = os.getenv("MODIFIED_SINCE", "1h")

HEADERS = {"X-OTX-API-KEY": API_KEY} if API_KEY else {}


def fetch_export(limit=DEFAULT_LIMIT, modified_since=DEFAULT_MODIFIED_SINCE):
    url = API_EXPORT_URL
    if not url:
        raise RuntimeError("API_EXPORT_URL not set in environment")

    params = {"limit": limit, "modified_since": modified_since}
    resp = requests.get(url, headers=HEADERS, params=params, timeout=30)
    resp.raise_for_status()

    # Try JSON first
    try:
        data = resp.json()
        return data
    except Exception:
        # Fall back to raw text (OTX may also return line-delimited format)
        return resp.text


def save_output(obj, path=OUTPUT_FILE):
    with open(path, "w", encoding="utf-8") as f:
        if isinstance(obj, (dict, list)):
            json.dump(obj, f, indent=2, ensure_ascii=False)
        else:
            f.write(str(obj))


def main():
    parser = argparse.ArgumentParser(description="Fetch OTX indicators via export endpoint")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--modified_since", default=DEFAULT_MODIFIED_SINCE)
    parser.add_argument("--out", default=OUTPUT_FILE)

    args = parser.parse_args()
    data = fetch_export(limit=args.limit, modified_since=args.modified_since)
    save_output(data, args.out)
    print(f"Saved export to {args.out}")


if __name__ == "__main__":
    main()
