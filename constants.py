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

# The target LLM provider endpoint
TARGET_URL = os.getenv("TARGET_URL", "https://cloudcode-pa.googleapis.com").rstrip("/")

# Initialize global client for reuse
async_client = httpx.AsyncClient(timeout=60.0)

def log_debug(msg):
    if DEBUG:
        print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] [DEBUG] {msg}")
