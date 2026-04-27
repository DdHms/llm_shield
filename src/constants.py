import os
import threading
from collections import deque
from datetime import datetime
import httpx

# In-memory log storage (last 50 requests)
REQUEST_LOGS = deque(maxlen=50)

# Load configurations from environment
DEFAULT_EXCLUSIONS = os.getenv("DEFAULT_EXCLUSIONS", "").split(",")
DEFAULT_EXCLUSIONS = [ex.strip() for ex in DEFAULT_EXCLUSIONS if ex.strip()]
EXCLUSIONS_LOCK = threading.Lock()
SCRUBBING_MODE = os.getenv("SCRUBBING_MODE", "generic").lower()
ANALYZER_TYPE = os.getenv("ANALYZER_TYPE", "pattern").lower()
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8080"))
DASHBOARD_TOKEN = os.getenv("DASHBOARD_TOKEN", "")

# The target LLM provider endpoint
TARGET_URL = os.getenv("TARGET_URL", "https://cloudcode-pa.googleapis.com").rstrip("/")

PREDEFINED_ENDPOINTS = {
    "Gemini CLI": "https://cloudcode-pa.googleapis.com",
    "Claude Code": "https://api.anthropic.com",
    "Codex": "https://api.openai.com",
    "Gemini Vertex AI": "https://us-central1-aiplatform.googleapis.com",
    "Custom": ""
}

SCRUB_PATH_PATTERNS = [
    "v1internal", "v1/models", "v1beta/models",  # Gemini
    "v1/messages", "v1/complete",                # Anthropic/Claude
    "v1/chat/completions", "v1/completions", "v1/responses",  # OpenAI/Codex
    "publishers/google/models"                    # Vertex AI
]

# Initialize global client for reuse
async_client = httpx.AsyncClient(timeout=60.0)


def public_dashboard_url():
    display_host = "localhost" if HOST in ("0.0.0.0", "::", "127.0.0.1") else HOST
    return f"http://{display_host}:{PORT}/dashboard"


def print_startup_urls():
    print(f"Proxy endpoint: http://localhost:{PORT}", flush=True)
    print(f"Dashboard: {public_dashboard_url()}", flush=True)
    if DASHBOARD_TOKEN:
        print(
            "Dashboard auth is enabled. Open /dashboard?token=<DASHBOARD_TOKEN> once or use "
            "Authorization: Bearer <token>.",
            flush=True,
        )


def log_debug(msg):
    if DEBUG:
        print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] [DEBUG] {msg}")
