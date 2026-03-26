import httpx
import json
import re
from fastapi import FastAPI, Request, Response
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

import os

app = FastAPI()

# Load configurations from environment
DEFAULT_EXCLUSIONS = os.getenv("DEFAULT_EXCLUSIONS", "").split(",")
DEFAULT_EXCLUSIONS = [ex.strip() for ex in DEFAULT_EXCLUSIONS if ex.strip()]
SCRUBBING_MODE = os.getenv("SCRUBBING_MODE", "generic").lower()
ANALYZER_TYPE = os.getenv("ANALYZER_TYPE", "both").lower()

# The target LLM provider endpoint
TARGET_URL = os.getenv("TARGET_URL", "https://cloudcode-pa.googleapis.com")

analyzer = None

def get_analyzer():
    global analyzer
    if analyzer is None:
        try:
            from presidio_analyzer import AnalyzerEngine
            analyzer = AnalyzerEngine()
        except Exception as e:
            print(f"[Error] Failed to initialize Presidio: {e}")
    return analyzer

async def scrub_text(text: str):
    """
    Uses Presidio and custom regex/exclusion logic to redact PII.
    Supports 'semantic' and 'generic' modes.
    Supports 'presidio', 'pattern', and 'both' analyzer types.
    """
    mapping = {}
    scrubbed_text = text
    
    # 1. Collect all potential matches with their labels
    # We use a list of tuples (text, label) to preserve the source of the match
    potential_matches = []

    # Presidio PII Detection (Names, Emails, etc.)
    if ANALYZER_TYPE in ["presidio", "both"]:
        az = get_analyzer()
        if az:
            results = az.analyze(text=text, language='en')
            for res in results:
                potential_matches.append((text[res.start:res.end], res.entity_type))

    # Pattern Detection (IPs, Gibberish, Exclusions)
    if ANALYZER_TYPE in ["pattern", "both"]:
        # IP Pattern Detection
        ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)
        for ip in ips:
            potential_matches.append((ip, "IP_ADDRESS"))

        # "Gibberish" Alphanumeric (6+ chars, mix of letters and numbers)
        potential_gibberish = re.findall(r'\b(?=[a-zA-Z]*\d)(?=\d*[a-zA-Z])[a-zA-Z0-9]{6,}\b', text)
        for g in potential_gibberish:
            potential_matches.append((g, "PRIVATE_KEY"))

    # Custom Exclusions
    for excluded in DEFAULT_EXCLUSIONS:
        if excluded in text:
            potential_matches.append((excluded, "PRIVATE_DATA"))

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

from fastapi.responses import StreamingResponse

async def de_scrub_stream(response_iterator, mapping: dict):
    """
    Generator that de-scrubs a stream of chunks.
    Maintains a buffer for potentially split placeholders (e.g., "<PRIVATE").
    """
    buffer = ""
    async for chunk in response_iterator:
        # 1. Combine buffer with new chunk (it comes as bytes, decode to string)
        text = buffer + chunk.decode("utf-8", errors="replace")
        buffer = ""

        # 2. Check for a trailing partial placeholder (starts with '<' but no '>')
        # We find the last '<' and see if it has a closing '>' after it.
        last_open_bracket = text.rfind("<")
        last_close_bracket = text.rfind(">")

        if last_open_bracket > last_close_bracket:
            # There is an unmatched '<' at the end
            # We buffer from that point onwards
            buffer = text[last_open_bracket:]
            text = text[:last_open_bracket]

        # 3. De-scrub the solid part of the text
        if text:
            yield de_scrub_text(text, mapping).encode("utf-8")

    # 4. Flush remaining buffer if any
    if buffer:
        yield de_scrub_text(buffer, mapping).encode("utf-8")

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

    # 3. Forward to Target
    client = httpx.AsyncClient()
    # Remove host header to avoid SSL/Routing mismatches
    headers.pop("host", None)
    
    url = f"{TARGET_URL}/{path}"
    
    # We use a stream request to support both normal and streaming responses
    req = client.build_request(
        method=request.method,
        url=url,
        content=body,
        headers=headers,
        params=request.query_params,
        timeout=60.0
    )
    
    response = await client.send(req, stream=True)

    # 4. Handle Response
    if pii_mapping and response.status_code == 200:
        # Wrap the response stream with our de-scrubber
        return StreamingResponse(
            de_scrub_stream(response.aiter_bytes(), pii_mapping),
            status_code=response.status_code,
            headers=dict(response.headers),
            background=None # Don't close client automatically if streaming
        )

    # If no mapping or error, just proxy the stream as-is
    return StreamingResponse(
        response.aiter_bytes(),
        status_code=response.status_code,
        headers=dict(response.headers)
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
