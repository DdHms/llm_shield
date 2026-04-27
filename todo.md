# TODO

## High Priority

- Protect dashboard and internal API endpoints.
  - `/api/logs` exposes original prompts, original responses, and restored sensitive data.
  - The server binds to `0.0.0.0`, making these endpoints reachable by anyone with network access to the port.
  - Consider localhost-only defaults, authentication, or disabling logs in shared deployments.
  - Affected file: `src/proxy.py`.

- Repair the documented NPM/native start path.
  - `node src/index.js` fails when no compatible `.node` binding exists.
  - `npm run build` currently fails because `napi` is unavailable from the script environment.
  - The Rust binding imports Python module `"proxy"`, but the module lives at `src/proxy.py`; this likely needs `src.proxy` or a packaging/path fix.
  - Affected files: `src/index.js`, `src/lib.rs`, `package.json`.

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
- `node src/index.js`: fails because no compatible native binding was found.
- `npm run build`: fails because `napi` is not found.
