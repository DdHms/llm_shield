# TODO

## Medium Priority

- Return real HTTP error statuses from exclusion endpoints.
  - `return {"status": "error", ...}, 400` is serialized by FastAPI as a JSON array with HTTP 200.
  - Use `HTTPException`, `JSONResponse(status_code=...)`, or set the response status explicitly.
  - Affected file: `src/proxy.py`.

- Close streamed upstream HTTP responses.
  - `async_client.send(..., stream=True)` responses should be closed after downstream streaming finishes.
  - Without explicit close handling, connections can leak under load.
  - Affected file: `src/proxy.py`.

- Make runtime config reads consistent.
  - `shielding.py` imports `ANALYZER_TYPE`, `SCRUBBING_MODE`, and `DEFAULT_EXCLUSIONS` by value.
  - Tests and live config mutations update `src.constants`, but `scrub_text()` may continue using stale imported values.
  - Prefer reading values through `src.constants` at call time.
  - Affected file: `src/shielding.py`.

## Current Verification

- `pytest -q`: 7 failed, 6 passed, 1 skipped.
