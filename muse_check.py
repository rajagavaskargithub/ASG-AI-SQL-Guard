import json, os, urllib.request, urllib.error
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env", override=True)
key = os.environ.get("MODEL_API_KEY", "")
base = os.environ.get("MODEL_BASE_URL", "https://api.meta.ai/v1")
print(f"key length={len(key)}  first4={key[:4]!r}  has '|'={'|' in key}  has whitespace={any(c.isspace() for c in key)}")
print("base:", base)

def call(method, path, body=None):
    req = urllib.request.Request(
        base + path, method=method,
        data=json.dumps(body).encode() if body else None,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=60)
        status, text = r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode(errors="replace")
    except Exception as e:
        status, text = "ERR", type(e).__name__
    return status, text.replace(key, "***")[:350] if key else text[:350]

print("\nGET /models      ->", *call("GET", "/models"))
for m in ["muse-spark-1.3", "muse-spark-1.1"]:
    print(f"\nPOST chat {m} ->", *call("POST", "/chat/completions",
          {"model": m, "messages": [{"role": "user", "content": "Reply with the word ok."}]}))
