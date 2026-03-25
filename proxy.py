import httpx
import json
import re
from fastapi import FastAPI, Request, Response
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

import os

app = FastAPI()
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Load configurations from environment
DEFAULT_EXCLUSIONS = os.getenv("DEFAULT_EXCLUSIONS", "").split(",")
DEFAULT_EXCLUSIONS = [ex.strip() for ex in DEFAULT_EXCLUSIONS if ex.strip()]
SCRUBBING_MODE = os.getenv("SCRUBBING_MODE", "generic").lower()

# The target LLM provider endpoint
TARGET_URL = os.getenv("TARGET_URL", "https://cloudcode-pa.googleapis.com")

async def scrub_text(text: str):
    """
    Uses Presidio and custom regex/exclusion logic to redact PII.
    Supports 'semantic' and 'generic' modes.
    """
    mapping = {}
    scrubbed_text = text
    
    # 1. Collect all potential matches with their labels
    # We use a list of tuples (text, label) to preserve the source of the match
    potential_matches = []

    # Presidio PII Detection
    results = analyzer.analyze(text=text, language='en')
    for res in results:
        potential_matches.append((text[res.start:res.end], res.entity_type))

    # IP Pattern Detection
    ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)
    for ip in ips:
        potential_matches.append((ip, "IP_ADDRESS"))

    # "Gibberish" Alphanumeric (6+ chars, mix of letters and numbers)
    potential_gibberish = re.findall(r'\b(?=[a-zA-Z]*\d)(?=\d*[a-zA-Z])[a-zA-Z0-9]{6,}\b', text)
    for g in potential_gibberish:
        potential_matches.append((g, "GIBBERISH"))

    # Custom Exclusions
    for excluded in DEFAULT_EXCLUSIONS:
        if excluded in text:
            potential_matches.append((excluded, "EXCLUSION"))

    # 2. Sort matches by length descending to avoid partial replacements
    # (e.g., "secret123" before "secret")
    potential_matches.sort(key=lambda x: len(x[0]), reverse=True)

    # 3. Apply replacements based on mode
    counts = {}
    seen_texts = {} # text -> placeholder mapping to avoid redundant processing

    for secret, label in potential_matches:
        if not secret or secret in seen_texts:
            continue
            
        if SCRUBBING_MODE == "semantic":
            counts[label] = counts.get(label, 0) + 1
            placeholder = f"<{label}_{counts[label]}>"
        else:
            # Generic mode: all PII uses the same PRIVATE_DATA prefix
            counts["PRIVATE_DATA"] = counts.get("PRIVATE_DATA", 0) + 1
            placeholder = f"<PRIVATE_DATA_{counts['PRIVATE_DATA']}>"
            
        mapping[placeholder] = secret
        seen_texts[secret] = placeholder
        scrubbed_text = scrubbed_text.replace(secret, placeholder)
        
    return scrubbed_text, mapping

def de_scrub_text(text: str, mapping: dict) -> str:
    """Replaces placeholders in the response with original PII values."""
    for placeholder, original_value in mapping.items():
        text = text.replace(placeholder, original_value)
    return text

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_engine(request: Request, path: str):
    # 1. Capture the original request
    body = await request.body()
    headers = dict(request.headers)
    
    pii_mapping = {}
    
    # 2. Intercept and Modify if it's a Gemini Content request
    if request.method == "POST" and "v1internal" in path:
        try:
            data = json.loads(body)
            # The v1internal structure: data['request']['contents'][0]['parts'][0]['text']
            if "request" in data and "contents" in data["request"]:
                for content in data["request"]["contents"]:
                    for part in content.get("parts", []):
                        if "text" in part:
                            # SCRUBBING STEP
                            original_text = part["text"]
                            scrubbed_text, mapping = await scrub_text(original_text)
                            part["text"] = scrubbed_text
                            pii_mapping.update(mapping)
                            print(f"[Privacy] Redacted prompt: {part['text'][:50]}...")
            
            body = json.dumps(data).encode("utf-8")
            headers["Content-Length"] = str(len(body))
        except Exception as e:
            print(f"[Error] Failed to parse/scrub body: {e}")

    # 3. Forward to Google
    async with httpx.AsyncClient() as client:
        # Remove host header to avoid SSL/Routing mismatches
        headers.pop("host", None)
        
        url = f"{TARGET_URL}/{path}"
        response = await client.request(
            method=request.method,
            url=url,
            content=body,
            headers=headers,
            params=request.query_params,
            timeout=60.0
        )

    # 4. Intercept Response and De-Scrub
    response_content = response.content
    
    if pii_mapping and response.status_code == 200:
        try:
            # Check if response is JSON (common for API responses)
            if "application/json" in response.headers.get("Content-Type", ""):
                resp_json = response.json()
                
                # Recursively de-scrub JSON values
                def process_json(obj):
                    if isinstance(obj, str):
                        return de_scrub_text(obj, pii_mapping)
                    elif isinstance(obj, list):
                        return [process_json(item) for item in obj]
                    elif isinstance(obj, dict):
                        return {k: process_json(v) for k, v in obj.items()}
                    return obj
                
                resp_json = process_json(resp_json)
                response_content = json.dumps(resp_json).encode("utf-8")
                
                # Update headers for the new content length
                new_headers = dict(response.headers)
                new_headers["Content-Length"] = str(len(response_content))
                return Response(
                    content=response_content,
                    status_code=response.status_code,
                    headers=new_headers
                )
        except Exception as e:
            print(f"[Error] Failed to de-scrub response: {e}")

    return Response(
        content=response_content,
        status_code=response.status_code,
        headers=dict(response.headers)
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
