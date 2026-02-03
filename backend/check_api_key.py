from dotenv import load_dotenv
import os

load_dotenv()

API_KEY = os.getenv("API_KEY")
print(f"API_KEY loaded: {API_KEY is not None}")
if API_KEY:
    print(f"Length: {len(API_KEY)}")
    print(f"First 10 chars: {API_KEY[:10]}")
    print(f"Full key: {API_KEY}")
