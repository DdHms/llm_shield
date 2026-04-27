# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LLM Privacy Shield is a proxy server that intercepts requests to LLM providers (primarily Google Cloud Code/Gemini), scrubs PII (Personally Identifiable Information) from requests, and restores it in responses. This prevents sensitive data from being sent to external LLM APIs.

## Architecture

The project has three main components:

1. **FastAPI Proxy** (`src/proxy.py`) - Intercepts HTTP requests, scrubs PII from request bodies, forwards to target LLM provider, and de-scrubs streaming responses
2. **PII Shielding** (`src/shielding.py`) - Core PII detection and redaction logic using Presidio (semantic) and regex patterns (generic)
3. **Dashboard UI** (`src/ui.py`, `src/dashboard.html`) - Web interface for viewing request logs and managing exclusions

The proxy runs on port 8080 and can be used in two modes:
- **GUI mode** (default): Opens a native window using pywebview
- **HEADLESS mode**: Runs as a FastAPI server only (set `HEADLESS=true`)

## Common Commands

### Running the Proxy
```bash
# Run with GUI (default)
python src/proxy.py

# Run in headless mode
HEADLESS=true python src/proxy.py

# Run with Docker
docker build -t llm-shield .
docker run -p 8080:8080 -e TARGET_URL=https://your-llm-endpoint.com llm-shield
```

### Testing
```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_scrubbing.py

# Run with verbose output
pytest tests/ -v
```

### Building Standalone Binaries
```bash
# Build with PyInstaller (requires pyinstaller)
pyinstaller --onefile --windowed --name "LLMShield" --add-data "src/dashboard.html:src" src/proxy.py
```

## Configuration

Environment variables control behavior:

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_URL` | `https://cloudcode-pa.googleapis.com` | LLM provider endpoint |
| `SCRUBBING_MODE` | `generic` | `generic` (regex) or `semantic` (Presidio) |
| `ANALYZER_TYPE` | `pattern` | `pattern`, `presidio`, or `both` |
| `DEFAULT_EXCLUSIONS` | (empty) | Comma-separated phrases to always scrub |
| `HEADLESS` | `false` | Run without GUI |
| `DEBUG` | `false` | Enable debug logging |

## Key Implementation Details

### PII Scrubbing Flow

1. **Custom Exclusions** (case-insensitive) - Processed first via regex
2. **Presidio Analysis** (if enabled) - Detects emails, phone numbers, names, etc.
3. **Pattern Detection** - IP addresses, API keys, gibberish strings, env var values
4. **Replacement** - Creates placeholders like `<EXCLUSION_1>`, `<PRIVATE_DATA_2>`

### Streaming De-scrubbing

The proxy handles streaming responses from LLM providers. The `de_scrub_stream` function buffers chunks to handle split placeholders across chunk boundaries, then replaces placeholders with original PII values.

### Request Logging

All requests are logged in-memory (last 50) with before/after snapshots for debugging. Access via `/api/logs` endpoint.

### Tool Result Handling

When scrubbing requests, the proxy detects tool/function result objects (via keys like `functionResponse`, `toolResult`) and scrubs their string content while preserving structure.

## Testing Patterns

Tests use `pytest` with `pytest-asyncio`. Key patterns:
- Tests are async functions decorated with `@pytest.mark.asyncio`
- Import modules with `sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))`
- Test both scrubbing and de-scrubbing to ensure round-trip correctness
- Use string concatenation to avoid false positives in PII detection tests

## Docker Build

The Dockerfile supports build arguments for different configurations:
```bash
docker build --build-arg ANALYZER_TYPE=pattern --build-arg SCRUBBING_MODE=generic -t llm-shield .
```

Heavy dependencies (Presidio, spaCy) are only installed when `ANALYZER_TYPE != "pattern"`.

## Node.js Bridge

The project includes a Node.js bridge (`src/index.js`) using napi-rs for cross-platform native binaries. This is built via GitHub Actions for Windows, macOS (Intel/ARM), and Linux.
