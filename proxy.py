import httpx
import json
import re
from fastapi import FastAPI, Request, Response
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

app = FastAPI()
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# The target Google internal endpoint
TARGET_URL = "https://cloudcode-pa.googleapis.com"

async def scrub_text(text: str):
    """
    Uses Presidio to redact PII from the prompt.
    Returns the scrubbed text and a mapping of placeholders to original values.
    """
    results = analyzer.analyze(text=text, language='en')
    
    # Sort results by start index descending to avoid index shifts during replacement
    sorted_results = sorted(results, key=lambda x: x.start, reverse=True)
    
    mapping = {}
    scrubbed_text = text
    
    for i, res in enumerate(sorted_results):
        placeholder = f"<{res.entity_type}_{i}>"
        original_value = text[res.start:res.end]
        mapping[placeholder] = original_value
        scrubbed_text = scrubbed_text[:res.start] + placeholder + scrubbed_text[res.end:]
        
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
