import httpx
import json
import re
import os
import uuid
import threading
import time
from datetime import datetime
from collections import deque
from typing import List, Optional, Union, Dict, Any
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel, RootModel

app = FastAPI()

# In-memory log storage (last 50 requests)
REQUEST_LOGS = deque(maxlen=50)

# Load configurations from environment
DEFAULT_EXCLUSIONS = os.getenv("DEFAULT_EXCLUSIONS", "").split(",")
DEFAULT_EXCLUSIONS = [ex.strip() for ex in DEFAULT_EXCLUSIONS if ex.strip()]
SCRUBBING_MODE = os.getenv("SCRUBBING_MODE", "generic").lower()
ANALYZER_TYPE = os.getenv("ANALYZER_TYPE", "pattern").lower()
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

# Header Whitelist Configuration
BASE_ALLOWED_HEADERS = {"content-type", "authorization", "user-agent", "accept", "accept-encoding"}
EXTRA_HEADERS = os.getenv("ALLOWED_HEADERS", "").split(",")
ALLOWED_HEADERS = BASE_ALLOWED_HEADERS.union({h.strip().lower() for h in EXTRA_HEADERS if h.strip()})

# The target LLM provider endpoint
TARGET_URL = os.getenv("TARGET_URL", "https://cloudcode-pa.googleapis.com").rstrip("/")

def log_debug(msg):
    if DEBUG:
        print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] [DEBUG] {msg}")

# Pydantic Models for Input Validation
class Part(BaseModel):
    text: Optional[str] = None
    inline_data: Optional[Dict[str, Any]] = None

class Content(BaseModel):
    role: Optional[str] = None
    parts: Optional[List[Part]] = None

class GeminiRequest(BaseModel):
    contents: Optional[List[Content]] = None
    generationConfig: Optional[Dict[str, Any]] = None
    safetySettings: Optional[List[Dict[str, Any]]] = None

class WrappedGeminiRequest(BaseModel):
    request: GeminiRequest

class GenericLLMPayload(BaseModel):
    # Flexible model to capture various common LLM request formats
    contents: Optional[List[Content]] = None
    messages: Optional[List[Dict[str, Any]]] = None
    request: Optional[Union[GeminiRequest, Dict[str, Any]]] = None

# Initialize global client for reuse
async_client = httpx.AsyncClient(timeout=60.0)

analyzer = None
analyzer_lock = threading.Lock()

def get_analyzer():
    global analyzer
    if analyzer is None:
        with analyzer_lock:
            if analyzer is None:
                try:
                    from presidio_analyzer import AnalyzerEngine
                    analyzer = AnalyzerEngine()
                except ImportError:
                    print("[Error] Presidio is not installed. Use a non-default build or install 'presidio-analyzer' and 'spacy' manually.")
                except Exception as e:
                    print(f"[Error] Failed to initialize Presidio: {e}")
    return analyzer

async def scrub_text(text: str):
    """
    Uses Presidio and custom regex/exclusion logic to redact PII.
    Collects all potential matches, merges overlaps, and then redacts.
    """
    matches = []

    # 1. Custom Exclusions
    for excluded in DEFAULT_EXCLUSIONS:
        start = 0
        while True:
            pos = text.find(excluded, start)
            if pos == -1:
                break
            matches.append((pos, pos + len(excluded), "EXCLUSION", excluded))
            start = pos + 1

    # 2. Presidio PII Detection
    if ANALYZER_TYPE in ["presidio", "both"]:
        az = get_analyzer()
        if az:
            results = az.analyze(text=text, language='en')
            for res in results:
                matches.append((res.start, res.end, res.entity_type, text[res.start:res.end]))

    # 3. Pattern Detection
    if ANALYZER_TYPE in ["pattern", "both"]:
        # IP Addresses
        for match in re.finditer(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text):
            matches.append((match.start(), match.end(), "IP_ADDRESS", match.group()))

        # Emails (Fallback for Presidio)
        for match in re.finditer(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text):
            matches.append((match.start(), match.end(), "EMAIL_ADDRESS", match.group()))

        # Credit Cards
        for match in re.finditer(r'\b(?:\d[ -]*?){13,16}\b', text):
            matches.append((match.start(), match.end(), "CREDIT_CARD", match.group()))

        # Potential Keys/Gibberish
        for match in re.finditer(r'\b(?=[a-zA-Z0-9-]*\d)(?=[a-zA-Z0-9-]*[a-zA-Z])[a-zA-Z0-9-]{6,}\b', text):
            matches.append((match.start(), match.end(), "PRIVATE_KEY", match.group()))

    # 4. Environment Variable Detection
    for match in re.finditer(r'\b[A-Z0-9_-]+\s*=\s*([a-zA-Z0-9_-]+)', text):
        # We want to redact the value part, not the whole match
        val_start = match.start(1)
        val_end = match.end(1)
        matches.append((val_start, val_end, "ENV_VALUE", match.group(1)))

    if not matches:
        return text, {}

    # Merge overlapping or adjacent ranges
    matches.sort()
    merged = []
    if matches:
        curr_start, curr_end, curr_label, curr_text = matches[0]
        for next_start, next_end, next_label, next_text in matches[1:]:
            if next_start <= curr_end:
                # Overlap or adjacent
                new_end = max(curr_end, next_end)
                # If they overlap, we might want to combine labels or pick one.
                # For simplicity, we'll keep the first label if it's "high priority" like EXCLUSION
                if curr_label != "EXCLUSION" and next_label == "EXCLUSION":
                    curr_label = "EXCLUSION"
                curr_end = new_end
                curr_text = text[curr_start:curr_end]
            else:
                merged.append((curr_start, curr_end, curr_label, curr_text))
                curr_start, curr_end, curr_label, curr_text = next_start, next_end, next_label, next_text
        merged.append((curr_start, curr_end, curr_label, curr_text))

    # Apply replacements in reverse order
    mapping = {}
    scrubbed_text = text
    counts = {}
    seen_texts = {}

    for start, end, label, secret in reversed(merged):
        if secret in seen_texts:
            placeholder = seen_texts[secret]
        else:
            if SCRUBBING_MODE == "semantic" or label in ["EXCLUSION", "ENV_VALUE"]:
                counts[label] = counts.get(label, 0) + 1
                placeholder = f"<{label}_{counts[label]}>"
            else:
                counts["PRIVATE_DATA"] = counts.get("PRIVATE_DATA", 0) + 1
                placeholder = f"<PRIVATE_DATA_{counts['PRIVATE_DATA']}>"
            
            mapping[placeholder] = secret
            seen_texts[secret] = placeholder
        
        scrubbed_text = scrubbed_text[:start] + placeholder + scrubbed_text[end:]
        
    return scrubbed_text, mapping

def de_scrub_text(text: str, mapping: dict) -> str:
    """Replaces placeholders in the response with original PII values."""
    # Sort by length descending to avoid partial replacements (e.g. <EXCLUSION_10> before <EXCLUSION_1>)
    sorted_placeholders = sorted(mapping.keys(), key=len, reverse=True)
    for placeholder in sorted_placeholders:
        original_value = mapping[placeholder]
        # 1. Literal match: <PRIVATE_DATA_1>
        text = text.replace(placeholder, original_value)
        
        # 2. Unicode escape match (common in JSON): \u003cPRIVATE_DATA_1\u003e
        unicode_placeholder = placeholder.replace("<", "\\u003c").replace(">", "\\u003e")
        text = text.replace(unicode_placeholder, original_value)
        
        # 3. HTML escape match: &lt;PRIVATE_DATA_1&gt;
        html_placeholder = placeholder.replace("<", "&lt;").replace(">", "&gt;")
        text = text.replace(html_placeholder, original_value)
    return text

async def de_scrub_stream(response_iterator, mapping: dict, log_entry: dict = None):
    """
    Generator that de-scrubs a stream of chunks and captures logs.
    Handles chunk boundaries by buffering potential placeholder starts.
    """
    buffer = ""
    full_resp_before = []
    full_resp_after = []
    
    # Potential starts of placeholders or escapes: <, \u003, &, \
    potential_starts = ["<", "\\u", "&", "\\"]
    
    async for chunk in response_iterator:
        chunk_text = chunk.decode("utf-8", errors="replace")
        full_resp_before.append(chunk_text)
        
        text = buffer + chunk_text
        buffer = ""

        # Find the last occurrence of any potential placeholder start
        # that doesn't have a corresponding end in the same chunk.
        # This is a bit complex due to multiple escape types.
        # We'll use a conservative approach: if any potential start is near the end, buffer it.
        
        # Literal: < ... >
        # Unicode: \u003c ... \u003e
        # HTML: &lt; ... &gt;
        
        last_start_pos = -1
        for start_seq in potential_starts:
            pos = text.rfind(start_seq)
            if pos > last_start_pos:
                last_start_pos = pos
        
        if last_start_pos != -1:
            # Check if this start is "closed" in the remaining text
            # This is tricky because different starts have different ends.
            # For simplicity, we buffer up to 50 characters if a start is found and not closed.
            # 50 is enough for any reasonable placeholder + escape overhead.
            tail = text[last_start_pos:]
            is_closed = (">" in tail) or ("\\u003e" in tail) or ("&gt;" in tail)
            
            if not is_closed:
                buffer = text[last_start_pos:]
                text = text[:last_start_pos]

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

@app.get("/health")
async def health():
    return {"status": "healthy", "analyzer": ANALYZER_TYPE, "mode": SCRUBBING_MODE}

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
        <div class="max-w-[1600px] mx-auto px-4 py-8">
            <header class="mb-8 flex justify-between items-center">
                <h1 class="text-3xl font-bold text-gray-900">Privacy Proxy Logs</h1>
                <button onclick="fetchLogs()" class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 transition">Refresh</button>
            </header>
            <div id="logs-container" class="space-y-6"></div>
        </div>
        <script>
            function highlightPlaceholders(text) {
                if (!text) return text;
                // First escape all HTML to prevent the browser from hiding <PLACEHOLDERS>
                const escaped = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                // Then wrap the escaped placeholders in a highlighted span
                return escaped.replace(/(&lt;[A-Z0-9_-]+&gt;)/g, '<span class="bg-yellow-300 px-1.5 py-0.5 rounded border border-yellow-500 text-black font-bold mx-0.5">$1</span>');
            }

            async function fetchLogs() {
                const response = await fetch('/api/logs');
                const allLogs = await response.json();
                
                // Filter logs to only show those where the received response contains actual model content
                const logs = allLogs.filter(log => 
                    log.resp_before && (
                        log.resp_before.toLowerCase().includes('"content"') || 
                        log.resp_before.toLowerCase().includes('"parts"') ||
                        log.resp_before.toLowerCase().includes('"text"')
                    )
                );

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
                                        <pre class="text-xs whitespace-pre-wrap break-all font-semibold">${highlightPlaceholders(log.req_after) || '(None/Static)'}</pre>
                                    </div>
                                </div>
                            </div>
                            <div>
                                <h3 class="text-sm font-semibold text-gray-700 mb-2 uppercase tracking-wider text-blue-600">Response De-Scrubbing</h3>
                                <div class="space-y-3 mt-2">
                                    <div class="bg-gray-50 p-3 rounded border border-gray-100">
                                        <div class="text-[10px] text-gray-400 mb-1 uppercase">Received</div>
                                        <pre class="text-xs whitespace-pre-wrap break-all">${highlightPlaceholders(log.resp_before) || '(Streaming...)'}</pre>
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
    start_time = time.perf_counter()
    log_debug(f"New Request: {request.method} /{path}")
    
    body = await request.body()
    log_debug(f"Captured Body (Size: {len(body)} bytes)")
    
    # Header Whitelist Implementation
    headers = {k.lower(): v for k, v in request.headers.items() if k.lower() in ALLOWED_HEADERS}
    
    # Force identity encoding to prevent compression issues
    headers["accept-encoding"] = "identity"
    
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
    
    is_gemini_path = "v1internal" in path or "v1/models" in path or "v1beta/models" in path
    
    if request.method == "POST" and body:
        try:
            # Schema-Driven Validation (Inbound Request Only)
            data_dict = json.loads(body)
            try:
                # We use model_validate to ensure the structure is roughly what we expect
                # but we use a flexible model to support various providers.
                payload = GenericLLMPayload.model_validate(data_dict)
            except Exception as ve:
                log_debug(f"Validation warning: {ve}")
                # We don't necessarily reject if it doesn't match GenericLLMPayload perfectly,
                # but we want to know. If the user wants strict rejection, they can uncomment:
                # raise HTTPException(status_code=400, detail=f"Invalid payload structure: {ve}")

            contents = None
            # Extract contents from various possible locations
            if data_dict.get("contents"):
                contents = data_dict["contents"]
            elif data_dict.get("request") and isinstance(data_dict["request"], dict) and data_dict["request"].get("contents"):
                contents = data_dict["request"]["contents"]
            elif data_dict.get("messages"):
                contents = data_dict["messages"]
                
            if contents:
                log_debug("Starting PII Scrubbing...")
                scrub_start = time.perf_counter()
                for content in contents:
                    if not isinstance(content, dict):
                        continue
                    # Handle both 'parts' (Gemini) and 'content' (OpenAI/Anthropic)
                    parts = content.get("parts", [])
                    if not parts and "content" in content:
                        # Normalize OpenAI-style content to a list of parts for internal processing
                        parts = [{"text": content["content"]}]
                        
                    for part in parts:
                        if isinstance(part, dict) and "text" in part:
                            original_text = part["text"]
                            log_entry["req_before"] = original_text
                            scrubbed_text, mapping = await scrub_text(original_text)
                            part["text"] = scrubbed_text
                            log_entry["req_after"] = scrubbed_text
                            pii_mapping.update(mapping)
                        elif isinstance(part, str):
                            # Simple string parts
                            scrubbed_text, mapping = await scrub_text(part)
                            # This is tricky because we can't easily replace a string in a list by value
                            # if it appears multiple times, but for LLM payloads it's usually one part per message.
                            # For now, we'll assume it's a dict-based payload as per Gemini/OpenAI specs.
                            pass

                log_debug(f"Scrubbing finished in {time.perf_counter() - scrub_start:.4f}s")
            
            body = json.dumps(data_dict).encode("utf-8")
        except json.JSONDecodeError:
            # If it's not JSON, we pass it through as is (might be binary or something else)
            pass
        except Exception as e:
            print(f"[Error] Failed to parse/scrub body: {e}")

    REQUEST_LOGS.appendleft(log_entry)

    # Clean path joining
    target_path = path if path.startswith("/") else f"/{path}"
    url = f"{TARGET_URL}{target_path}"
    log_debug(f"Forwarding request to: {url}")
    
    req = async_client.build_request(
        method=request.method, url=url, content=body,
        headers=headers, params=request.query_params
    )
    
    try:
        fwd_start = time.perf_counter()
        response = await async_client.send(req, stream=True)
        log_debug(f"Target responded with status {response.status_code} in {time.perf_counter() - fwd_start:.4f}s")
    except Exception as e:
        log_debug(f"Forwarding ERROR: {str(e)}")
        log_entry["resp_before"] = f"Error: {str(e)}"
        return Response(content=f"Proxy error: {str(e)}", status_code=502)

    # Sanitize response headers
    resp_headers = {k.lower(): v for k, v in response.headers.items()}
    resp_headers.pop("content-length", None)
    resp_headers.pop("transfer-encoding", None)
    resp_headers.pop("content-encoding", None) # Remove gzip/deflate if present
    resp_headers.pop("connection", None)

    log_debug(f"Total processing time before response stream: {time.perf_counter() - start_time:.4f}s")

    if pii_mapping and response.status_code == 200:
        log_debug("Beginning Streaming De-Scrub...")
        return StreamingResponse(
            de_scrub_stream(response.aiter_bytes(), pii_mapping, log_entry),
            status_code=response.status_code, headers=resp_headers
        )

    async def log_as_is_stream(res_iter):
        full_resp = []
        async for chunk in res_iter:
            full_resp.append(chunk.decode("utf-8", errors="replace"))
            yield chunk
        log_entry["resp_before"] = "".join(full_resp)
        log_entry["resp_after"] = log_entry["resp_before"]
        log_debug("Finished non-scrubbed response stream")

    return StreamingResponse(
        log_as_is_stream(response.aiter_bytes()),
        status_code=response.status_code, headers=resp_headers
    )

def start_fastapi():
    import uvicorn
    # Runs your FastAPI server in the background
    # Use 0.0.0.0 to allow access from outside the container
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")

def run_application():
    import webview
    # 1. Start FastAPI
    if os.getenv("HEADLESS", "false").lower() == "true":
        print("Running in HEADLESS mode (FastAPI only)...")
        start_fastapi()
    else:
        t = threading.Thread(target=start_fastapi)
        t.daemon = True
        t.start()

        # 2. Open a beautiful native GUI window for the user
        try:
            webview.create_window('Gemini Privacy Shield', 'http://127.0.0.1:8080/dashboard')
            webview.start()
        except Exception as e:
            print(f"GUI failed to start: {e}. Falling back to server only.")
            # If GUI fails (common in Docker), keep the thread alive or restart in main
            start_fastapi()

if __name__ == "__main__":
    run_application()
