import httpx
import json
import re
import os
import uuid
from datetime import datetime
from collections import deque
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse, HTMLResponse
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

app = FastAPI()

# In-memory log storage (last 50 requests)
REQUEST_LOGS = deque(maxlen=50)

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
        ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)
        for ip in ips:
            potential_matches.append((ip, "IP_ADDRESS"))

        potential_gibberish = re.findall(r'\b(?=[a-zA-Z]*\d)(?=\d*[a-zA-Z])[a-zA-Z0-9]{6,}\b', text)
        for g in potential_gibberish:
            potential_matches.append((g, "PRIVATE_KEY"))

        for excluded in DEFAULT_EXCLUSIONS:
            if excluded in text:
                potential_matches.append((excluded, "PRIVATE_DATA"))

    potential_matches.sort(key=lambda x: len(x[0]), reverse=True)

    counts = {}
    seen_texts = {} 

    for secret, label in potential_matches:
        if not secret or secret in seen_texts:
            continue
            
        if SCRUBBING_MODE == "semantic":
            counts[label] = counts.get(label, 0) + 1
            placeholder = f"<{label}_{counts[label]}>"
        else:
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

async def de_scrub_stream(response_iterator, mapping: dict, log_entry: dict = None):
    """
    Generator that de-scrubs a stream of chunks and captures logs.
    """
    buffer = ""
    full_resp_before = []
    full_resp_after = []
    
    async for chunk in response_iterator:
        chunk_text = chunk.decode("utf-8", errors="replace")
        full_resp_before.append(chunk_text)
        
        text = buffer + chunk_text
        buffer = ""

        last_open_bracket = text.rfind("<")
        last_close_bracket = text.rfind(">")

        if last_open_bracket > last_close_bracket:
            buffer = text[last_open_bracket:]
            text = text[:last_open_bracket]

        if text:
            de_scrubbed = de_scrub_text(text, mapping)
            full_resp_after.append(de_scrubbed)
            yield de_scrubbed.encode("utf-8")

    if buffer:
        de_scrubbed = de_scrub_text(buffer, mapping)
        full_resp_after.append(de_scrubbed)
        yield de_scrubbed.encode("utf-8")
        
    if log_entry is not None:
        log_entry["resp_before"] = "".join(full_resp_before)
        log_entry["resp_after"] = "".join(full_resp_after)

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>LLM Privacy Proxy Logs</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-50 font-sans">
        <div class="max-w-7xl mx-auto px-4 py-8">
            <header class="mb-8 flex justify-between items-center">
                <h1 class="text-3xl font-bold text-gray-900">Privacy Proxy Logs</h1>
                <button onclick="fetchLogs()" class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 transition">Refresh</button>
            </header>
            <div id="logs-container" class="space-y-6"></div>
        </div>
        <script>
            async function fetchLogs() {
                const response = await fetch('/api/logs');
                const logs = await response.json();
                const container = document.getElementById('logs-container');
                if (logs.length === 0) {
                    container.innerHTML = '<div class="text-center py-12 text-gray-500">No logs yet. Send some requests!</div>';
                    return;
                }
                container.innerHTML = logs.map(log => `
                    <div class="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
                        <div class="bg-gray-50 px-6 py-3 border-b border-gray-200 flex justify-between items-center">
                            <span class="font-mono text-sm text-gray-500">${log.timestamp}</span>
                            <span class="px-2 py-1 rounded text-xs font-semibold bg-blue-100 text-blue-800 uppercase">${log.method} ${log.path.split('/').pop()}</span>
                        </div>
                        <div class="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <h3 class="text-sm font-semibold text-gray-700 mb-2 uppercase tracking-wider text-green-600">Request Scrubbing</h3>
                                <div class="space-y-3 mt-2">
                                    <div class="bg-gray-50 p-3 rounded border border-gray-100">
                                        <div class="text-[10px] text-gray-400 mb-1 uppercase">Original</div>
                                        <pre class="text-xs whitespace-pre-wrap break-all">${log.req_before || '(None/Static)'}</pre>
                                    </div>
                                    <div class="bg-green-50 p-3 rounded border border-green-100">
                                        <div class="text-[10px] text-green-400 mb-1 uppercase">Scrubbed</div>
                                        <pre class="text-xs whitespace-pre-wrap break-all font-semibold">${log.req_after || '(None/Static)'}</pre>
                                    </div>
                                </div>
                            </div>
                            <div>
                                <h3 class="text-sm font-semibold text-gray-700 mb-2 uppercase tracking-wider text-blue-600">Response De-Scrubbing</h3>
                                <div class="space-y-3 mt-2">
                                    <div class="bg-gray-50 p-3 rounded border border-gray-100">
                                        <div class="text-[10px] text-gray-400 mb-1 uppercase">Received</div>
                                        <pre class="text-xs whitespace-pre-wrap break-all">${log.resp_before || '(Streaming...)'}</pre>
                                    </div>
                                    <div class="bg-blue-50 p-3 rounded border border-blue-100">
                                        <div class="text-[10px] text-blue-400 mb-1 uppercase">Restored</div>
                                        <pre class="text-xs whitespace-pre-wrap break-all font-semibold">${log.resp_after || '(Streaming...)'}</pre>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `).join('');
            }
            fetchLogs();
            setInterval(fetchLogs, 5000);
        </script>
    </body>
    </html>
    """

@app.get("/api/logs")
async def get_logs():
    return list(REQUEST_LOGS)

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_engine(request: Request, path: str):
    body = await request.body()
    headers = dict(request.headers)
    
    pii_mapping = {}
    log_entry = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "method": request.method,
        "path": path,
        "req_before": "",
        "req_after": "",
        "resp_before": "",
        "resp_after": ""
    }
    
    if request.method == "POST" and "v1internal" in path:
        try:
            data = json.loads(body)
            if "request" in data and "contents" in data["request"]:
                for content in data["request"]["contents"]:
                    for part in content.get("parts", []):
                        if "text" in part:
                            original_text = part["text"]
                            log_entry["req_before"] = original_text
                            scrubbed_text, mapping = await scrub_text(original_text)
                            part["text"] = scrubbed_text
                            log_entry["req_after"] = scrubbed_text
                            pii_mapping.update(mapping)
            
            body = json.dumps(data).encode("utf-8")
            headers["Content-Length"] = str(len(body))
        except Exception as e:
            print(f"[Error] Failed to parse/scrub body: {e}")

    REQUEST_LOGS.appendleft(log_entry)

    client = httpx.AsyncClient()
    headers.pop("host", None)
    url = f"{TARGET_URL}/{path}"
    
    req = client.build_request(
        method=request.method, url=url, content=body,
        headers=headers, params=request.query_params, timeout=60.0
    )
    
    try:
        response = await client.send(req, stream=True)
    except Exception as e:
        log_entry["resp_before"] = f"Error: {str(e)}"
        return Response(content=f"Proxy error: {str(e)}", status_code=502)

    if pii_mapping and response.status_code == 200:
        return StreamingResponse(
            de_scrub_stream(response.aiter_bytes(), pii_mapping, log_entry),
            status_code=response.status_code, headers=dict(response.headers)
        )

    async def log_as_is_stream(res_iter):
        full_resp = []
        async for chunk in res_iter:
            full_resp.append(chunk.decode("utf-8", errors="replace"))
            yield chunk
        log_entry["resp_before"] = "".join(full_resp)
        log_entry["resp_after"] = log_entry["resp_before"]

    return StreamingResponse(
        log_as_is_stream(response.aiter_bytes()),
        status_code=response.status_code, headers=dict(response.headers)
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
