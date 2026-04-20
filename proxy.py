import time
import json
import uuid
from datetime import datetime
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse, HTMLResponse

import constants
from shielding import scrub_text, de_scrub_stream
from ui import get_dashboard_html, run_application

app = FastAPI()

@app.get("/health")
async def health():
    return {"status": "healthy", "analyzer": constants.ANALYZER_TYPE, "mode": constants.SCRUBBING_MODE}

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard():
    return get_dashboard_html()

@app.get("/api/logs")
async def get_logs():
    return list(constants.REQUEST_LOGS)

@app.get("/api/config")
async def get_config():
    with constants.EXCLUSIONS_LOCK:
        return {
            "exclusions": list(constants.DEFAULT_EXCLUSIONS),
            "scrubbing_mode": constants.SCRUBBING_MODE,
            "analyzer_type": constants.ANALYZER_TYPE
        }

@app.post("/api/exclusions")
async def add_exclusion(request: Request):
    data = await request.json()
    phrase = data.get("phrase", "").strip()
    if phrase:
        with constants.EXCLUSIONS_LOCK:
            if phrase not in constants.DEFAULT_EXCLUSIONS:
                constants.DEFAULT_EXCLUSIONS.append(phrase)
        return {"status": "success", "phrase": phrase}
    return {"status": "error", "message": "Phrase cannot be empty"}, 400

@app.delete("/api/exclusions/{phrase}")
async def remove_exclusion(phrase: str):
    with constants.EXCLUSIONS_LOCK:
        if phrase in constants.DEFAULT_EXCLUSIONS:
            constants.DEFAULT_EXCLUSIONS.remove(phrase)
            return {"status": "success", "phrase": phrase}
    return {"status": "error", "message": "Phrase not found"}, 404

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_engine(request: Request, path: str):
    start_time = time.perf_counter()
    constants.log_debug(f"New Request: {request.method} /{path}")
    
    body = await request.body()
    constants.log_debug(f"Captured Body (Size: {len(body)} bytes)")
    
    headers = {k.lower(): v for k, v in request.headers.items()}
    headers["accept-encoding"] = "identity"
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
    
    is_gemini_path = "google.ai.generativelanguage" in path or "v1/models" in path or "v1beta/models" in path
    
    if request.method == "POST" and is_gemini_path:
        try:
            data = json.loads(body)
            log_entry["req_before"] = json.dumps(data, indent=2)
            
            constants.log_debug("Starting Recursive PII Scrubbing...")
            scrub_start = time.perf_counter()
            
            async def scrub_recursive(obj, in_tool=False):
                if isinstance(obj, dict):
                    for k, v in obj.items():
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
            constants.log_debug(f"Scrubbing finished in {time.perf_counter() - scrub_start:.4f}s")
            
            log_entry["req_after"] = json.dumps(data, indent=2)
            body = json.dumps(data).encode("utf-8")
        except Exception as e:
            print(f"[Error] Failed to parse/scrub body: {e}")

    constants.REQUEST_LOGS.appendleft(log_entry)

    target_path = path if path.startswith("/") else f"/{path}"
    url = f"{constants.TARGET_URL}{target_path}"
    constants.log_debug(f"Forwarding request to: {url}")
    
    req = constants.async_client.build_request(
        method=request.method, url=url, content=body,
        headers=headers, params=request.query_params
    )
    
    try:
        fwd_start = time.perf_counter()
        response = await constants.async_client.send(req, stream=True)
        constants.log_debug(f"Target responded with status {response.status_code} in {time.perf_counter() - fwd_start:.4f}s")
    except Exception as e:
        constants.log_debug(f"Forwarding ERROR: {str(e)}")
        log_entry["resp_before"] = f"Error: {str(e)}"
        return Response(content=f"Proxy error: {str(e)}", status_code=502)

    resp_headers = {k.lower(): v for k, v in response.headers.items()}
    resp_headers.pop("content-length", None)
    resp_headers.pop("transfer-encoding", None)
    resp_headers.pop("content-encoding", None)
    resp_headers.pop("connection", None)

    constants.log_debug(f"Total processing time before response stream: {time.perf_counter() - start_time:.4f}s")

    if pii_mapping and response.status_code == 200:
        constants.log_debug("Beginning Streaming De-Scrub...")
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
        constants.log_debug("Finished non-scrubbed response stream")

    return StreamingResponse(
        log_as_is_stream(response.aiter_bytes()),
        status_code=response.status_code, headers=resp_headers
    )

if __name__ == "__main__":
    run_application(app)
