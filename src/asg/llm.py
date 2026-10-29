import os
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI

# Load .env from the project root, no matter where the script is run from
ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env", override=True)

def client() -> OpenAI:
    key = os.environ.get("MODEL_API_KEY", "").strip().strip('"').strip("'")
    base = os.environ.get("MODEL_BASE_URL", "").strip()
    if not key or "..." in key or len(key) < 20:
        raise SystemExit(f"MODEL_API_KEY missing or invalid. Looked in: {ROOT / '.env'}")
    if not base:
        raise SystemExit(f"MODEL_BASE_URL missing. Looked in: {ROOT / '.env'}")
    return OpenAI(api_key=key, base_url=base)

MODEL = os.environ.get("MODEL_NAME", "muse-spark-1.1")

if __name__ == "__main__":
    r = client().chat.completions.create(
        model=MODEL,
        messages=[{"role": "user",
                   "content": "Write a DuckDB SQL query: total order amount per customer, top 5."}],
    )
    print(r.choices[0].message.content)
