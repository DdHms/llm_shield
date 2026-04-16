import time

import httpx
import json
import re
import os
import uuid
import threading
from datetime import datetime
from collections import deque
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse, HTMLResponse

app = FastAPI()

# In-memory log storage (last 50 requests)
REQUEST_LOGS = deque(maxlen=50)

# Load configurations from environment
DEFAULT_EXCLUSIONS = os.getenv("DEFAULT_EXCLUSIONS", "").split(",")
DEFAULT_EXCLUSIONS = [ex.strip() for ex in DEFAULT_EXCLUSIONS if ex.strip()]
SCRUBBING_MODE = os.getenv("SCRUBBING_MODE", "generic").lower()
ANALYZER_TYPE = os.getenv("ANALYZER_TYPE", "pattern").lower()
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

# The target LLM provider endpoint
TARGET_URL = os.getenv("TARGET_URL", "https://cloudcode-pa.googleapis.com").rstrip("/")

def log_debug(msg):
    if DEBUG:
        print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] [DEBUG] {msg}")

# Initialize global client for reuse
async_client = httpx.AsyncClient(timeout=60.0)

analyzer = None

def get_analyzer():
    global analyzer
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
    Processes DEFAULT_EXCLUSIONS first, then other analyzers sequentially.
    """
    mapping = {}
    scrubbed_text = text
    counts = {}
    seen_texts = {} 

    def apply_replacement(secret, label):
        nonlocal scrubbed_text
        if not secret or secret in seen_texts:
            return
            
        if SCRUBBING_MODE == "semantic" or label in ["EXCLUSION", "ENV_VALUE"]:
            counts[label] = counts.get(label, 0) + 1
            placeholder = f"<{label}_{counts[label]}>"
        else:
            counts["PRIVATE_DATA"] = counts.get("PRIVATE_DATA", 0) + 1
            placeholder = f"<PRIVATE_DATA_{counts['PRIVATE_DATA']}>"
            
        mapping[placeholder] = secret
        seen_texts[secret] = placeholder
        
        # We need to replace exactly this instance of the secret if it was found via Presidio or Patterns
        # For DEFAULT_EXCLUSIONS, we've already done the replacement using re.sub
        if secret in scrubbed_text:
            scrubbed_text = scrubbed_text.replace(secret, placeholder)

    # 1. process Custom Exclusions FIRST (Case-Insensitive)
    sorted_exclusions = sorted(DEFAULT_EXCLUSIONS, key=len, reverse=True)
    for excluded in sorted_exclusions:
        # Use regex to find all case-insensitive matches
        matches = re.finditer(re.escape(excluded), scrubbed_text, re.IGNORECASE)
        # Sort matches by start position in reverse to avoid index shifts during replacement
        # But wait, it's easier to just use re.sub with a callback to capture original text
        
        def replacement_callback(match):
            original_val = match.group(0)
            label = "EXCLUSION"
            
            if original_val in seen_texts:
                return seen_texts[original_val]
                
            counts[label] = counts.get(label, 0) + 1
            placeholder = f"<{label}_{counts[label]}>"
            
            mapping[placeholder] = original_val
            seen_texts[original_val] = placeholder
            return placeholder

        scrubbed_text = re.sub(re.escape(excluded), replacement_callback, scrubbed_text, flags=re.IGNORECASE)

    # 2. Collect potential matches from subsequent analyzers
    potential_matches = []

    # Presidio PII Detection
    if ANALYZER_TYPE in ["presidio", "both"]:
        az = get_analyzer()
        if az:
            results = az.analyze(text=scrubbed_text, language='en')
            for res in results:
                potential_matches.append((scrubbed_text[res.start:res.end], res.entity_type))

    # Pattern Detection
    if ANALYZER_TYPE in ["pattern", "both"]:
        ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', scrubbed_text)
        for ip in ips:
            potential_matches.append((ip, "IP_ADDRESS"))

        potential_gibberish = re.findall(r'\b(?=[a-zA-Z0-9-]*\d)(?=[a-zA-Z0-9-]*[a-zA-Z])[a-zA-Z0-9-]{6,}\b', scrubbed_text)
        for g in potential_gibberish:
            potential_matches.append((g, "PRIVATE_KEY"))

    # Environment Variable Detection (e.g. MY_ENV_VAR = secret)
    env_vars = re.findall(r'\b[A-Z0-9_-]+\s*=\s*([a-zA-Z0-9_-]+)', scrubbed_text)

    for val in env_vars:
        potential_matches.append((val, "ENV_VALUE"))

    potential_matches.sort(key=lambda x: len(x[0]), reverse=True)

    for secret, label in potential_matches:
        apply_replacement(secret, label)
        
    return scrubbed_text, mapping

def de_scrub_text(text: str, mapping: dict) -> str:
    """Replaces placeholders in the response with original PII values."""
    for placeholder, original_value in mapping.items():
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

            function extractAndFormatContent(text) {
                if (!text) return '(Streaming...)';
                
                const results = [];
                function findContent(obj) {
                    if (!obj || typeof obj !== 'object') return;
                    if (Array.isArray(obj)) {
                        obj.forEach(findContent);
                        return;
                    }
                    for (const key in obj) {
                        if (key === 'content') {
                            results.push(obj[key]);
                        } else {
                            findContent(obj[key]);
                        }
                    }
                }

                // Try parsing as a single JSON or SSE stream
                // Remove SSE prefixes like "data: "
                const chunks = text.split(/\\n?data: /);
                chunks.forEach(chunk => {
                    const trimmed = chunk.trim();
                    if (!trimmed || trimmed === '[DONE]') return;
                    try {
                        const parsed = JSON.parse(trimmed);
                        findContent(parsed);
                    } catch (e) {
                        // Attempt to extract JSON from mixed text if direct parse fails
                        const jsonMatch = trimmed.match(/\\{.*\\}/s);
                        if (jsonMatch) {
                            try {
                                findContent(JSON.parse(jsonMatch[0]));
                            } catch (innerE) {}
                        }
                    }
                });

                if (results.length === 0) return text;
                // If there's only one content object, show it. If multiple (streaming), show as array.
                const finalObj = results.length === 1 ? results[0] : results;
                // Remove bloat like thoughtSignature from the display
                return JSON.stringify(finalObj, (key, value) => key === 'thoughtSignature' ? undefined : value, 2);
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
                container.innerHTML = logs.map(log => {
                    const prettyReceived = highlightPlaceholders(extractAndFormatContent(log.resp_before));
                    const prettyRestored = extractAndFormatContent(log.resp_after);
                    
                    return `
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
                                        <div class="text-[10px] text-gray-400 mb-1 uppercase">Received (Prettified Content)</div>
                                        <pre class="text-xs whitespace-pre-wrap break-all">${prettyReceived || '(Streaming...)'}</pre>
                                    </div>
                                    <div class="bg-blue-50 p-3 rounded border border-blue-100">
                                        <div class="text-[10px] text-blue-400 mb-1 uppercase">Restored (Prettified Content)</div>
                                        <pre class="text-xs whitespace-pre-wrap break-all font-semibold">${prettyRestored || '(Streaming...)'}</pre>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `}).join('');
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
    
    # Clone and sanitize headers
    headers = {k.lower(): v for k, v in request.headers.items()}
    
    # Force identity encoding to prevent compression issues (e.g., "incorrect header check")
    headers["accept-encoding"] = "identity"
    
    # Remove hop-by-hop and length headers
    headers.pop("content-length", None)
    headers.pop("transfer-encoding", None)
    headers.pop("host", None)
    headers.pop("connection", None)
    
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
    
    if request.method == "POST" and is_gemini_path:
        try:
            data = json.loads(body)
            log_entry["req_before"] = json.dumps(data, indent=2)
            
            log_debug("Starting Recursive PII Scrubbing...")
            scrub_start = time.perf_counter()
            
            async def scrub_recursive(obj, in_tool=False):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        # Track if we are inside a tool result object
                        current_in_tool = in_tool or k in ("functionResponse", "toolResult", "function_response", "tool_response")
                        
                        if k == "text" and isinstance(v, str):
                            scrubbed, mapping = await scrub_text(v)
                            obj[k] = scrubbed
                            pii_mapping.update(mapping)
                        elif current_in_tool and isinstance(v, str) and k not in ("name", "id", "type"):
                            scrubbed, mapping = await scrub_text(v)
                            obj[k] = scrubbed
                            pii_mapping.update(mapping)
                        else:
                            await scrub_recursive(v, current_in_tool)
                elif isinstance(obj, list):
                    for item in obj:
                        await scrub_recursive(item, in_tool)

            await scrub_recursive(data)
            log_debug(f"Scrubbing finished in {time.perf_counter() - scrub_start:.4f}s")
            
            log_entry["req_after"] = json.dumps(data, indent=2)
            body = json.dumps(data).encode("utf-8")
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
