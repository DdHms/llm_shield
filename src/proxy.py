import os
import threading
import time
import json
import uuid
from datetime import datetime
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse, HTMLResponse
import httpx

from src import constants
from src.constants import REQUEST_LOGS, DEFAULT_EXCLUSIONS, EXCLUSIONS_LOCK, SCRUBBING_MODE, ANALYZER_TYPE, log_debug
from src.shielding import scrub_text, de_scrub_stream
from src.ui import get_dashboard_html, run_application

app = FastAPI()

@app.get("/health")
async def health():
    return {"status": "healthy", "analyzer": constants.ANALYZER_TYPE, "mode": constants.SCRUBBING_MODE}


@app.get("/api/logs")
async def get_logs():
    return list(REQUEST_LOGS)


@app.get("/api/config")
async def get_config():
    with EXCLUSIONS_LOCK:
        return {
            "exclusions": list(DEFAULT_EXCLUSIONS),
            "scrubbing_mode": SCRUBBING_MODE,
            "analyzer_type": ANALYZER_TYPE,
            "target_url": constants.TARGET_URL,
            "predefined_endpoints": constants.PREDEFINED_ENDPOINTS,
            "scrub_path_patterns": constants.SCRUB_PATH_PATTERNS
        }

@app.post("/api/target_url")
async def update_target_url(request: Request):
    data = await request.json()
    new_url = data.get("url", "").strip().rstrip("/")
    if new_url:
        constants.TARGET_URL = new_url
        log_debug(f"Target URL updated to: {new_url}")
        return {"status": "success", "url": new_url}
    return {"status": "error", "message": "URL cannot be empty"}, 400

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard():
    return get_dashboard_html()



@app.post("/api/exclusions")
async def add_exclusion(request: Request):
    data = await request.json()
    phrase = data.get("phrase", "").strip()
    if phrase:
        with EXCLUSIONS_LOCK:
            if phrase not in DEFAULT_EXCLUSIONS:
                DEFAULT_EXCLUSIONS.append(phrase)
        return {"status": "success", "phrase": phrase}
    return {"status": "error", "message": "Phrase cannot be empty"}, 400


@app.delete("/api/exclusions/{phrase}")
async def remove_exclusion(phrase: str):
    with EXCLUSIONS_LOCK:
        if phrase in DEFAULT_EXCLUSIONS:
            DEFAULT_EXCLUSIONS.remove(phrase)
            return {"status": "success", "phrase": phrase}
    return {"status": "error", "message": "Phrase not found"}, 404


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

    # Determine if this is an LLM interaction that should be scrubbed
    should_scrub = any(pattern in path for pattern in constants.SCRUB_PATH_PATTERNS)

    if request.method == "POST" and should_scrub:
        try:
            data = json.loads(body)
            log_entry["req_before"] = json.dumps(data, indent=2)

            log_debug("Starting Recursive PII Scrubbing...")
            scrub_start = time.perf_counter()
            replacement_state = {"counts": {}, "seen_texts": {}}

            async def scrub_recursive(obj, in_tool=False):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        # Track if we are inside a tool result object
                        current_in_tool = in_tool or k in ("functionResponse", "toolResult", "function_response",
                                                           "tool_response")

                        if k == "text" and isinstance(v, str):
                            scrubbed, mapping = await scrub_text(v, replacement_state)
                            obj[k] = scrubbed
                            pii_mapping.update(mapping)
                        elif current_in_tool and isinstance(v, str) and k not in ("name", "id", "type"):
                            scrubbed, mapping = await scrub_text(v, replacement_state)
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
    url = f"{constants.TARGET_URL}{target_path}"
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
    resp_headers.pop("content-encoding", None)  # Remove gzip/deflate if present
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

async_client = httpx.AsyncClient(timeout=60.0)

if __name__ == "__main__":
    run_application()
