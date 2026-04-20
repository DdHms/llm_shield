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
EXCLUSIONS_LOCK = threading.Lock()
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
    with EXCLUSIONS_LOCK:
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
    <html lang="en" class="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>LLM Privacy Proxy</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            body {
                font-family: 'Inter', sans-serif;
                background-color: #121212;
                color: #ffffff;
            }
            .sidebar { background-color: #1a1a1a; }
            .input-bar { background-color: #212121; }
            
            /* Custom scrollbar for dark theme */
            ::-webkit-scrollbar {
                width: 8px;
            }
            ::-webkit-scrollbar-track {
                background: #121212; 
            }
            ::-webkit-scrollbar-thumb {
                background: #333; 
                border-radius: 4px;
            }
            ::-webkit-scrollbar-thumb:hover {
                background: #555; 
            }
        </style>
    </head>
    <body class="h-screen w-full flex overflow-hidden">
        <!-- Sidebar -->
        <aside class="w-64 sidebar flex flex-col h-full border-r border-white/5 transition-all duration-300">
            <div class="p-4 flex items-center mb-2">
                <div class="w-8 h-8 bg-white text-black rounded-lg flex items-center justify-center font-bold text-xl mr-3 shadow-md">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                </div>
            </div>
            
            <nav class="flex-1 px-3 space-y-1 mt-2">
                <button onclick="switchTab('chat', this)" class="nav-btn w-full flex items-center gap-3 px-3 py-2 text-sm text-gray-300 hover:bg-white/10 rounded-lg transition-colors bg-white/10 font-medium">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"></path></svg>
                    New Chat
                </button>
                <button onclick="switchTab('logs', this)" class="nav-btn w-full flex items-center gap-3 px-3 py-2 text-sm text-gray-300 hover:bg-white/10 rounded-lg transition-colors">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"></path></svg>
                    Logs
                </button>
                <div class="pt-4 pb-2">
                    <p class="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">Settings</p>
                </div>
                <button onclick="switchTab('settings', this)" class="nav-btn w-full flex items-center gap-3 px-3 py-2 text-sm text-gray-300 hover:bg-white/10 rounded-lg transition-colors">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                    Settings & Exclusions
                </button>
            </nav>
        </aside>

        <!-- Main Content -->
        <main class="flex-1 flex flex-col relative bg-[#121212]">
            <!-- Top bar -->
            <header class="absolute top-0 left-0 w-full p-4 flex items-center justify-start pointer-events-none z-10 pl-6 pt-5">
                <div class="flex items-center gap-3 bg-[#1e1e1e] border border-white/10 rounded-xl px-4 py-2 pointer-events-auto shadow-md backdrop-blur-sm bg-opacity-80 hover:bg-opacity-100 transition duration-200 cursor-pointer">
                    <svg class="w-4 h-4 text-[#ff8c00]" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 14.5v-9l6 4.5-6 4.5z"/></svg>
                    <span class="text-sm font-medium text-gray-200" id="model-name-display">Privacy Proxy Active</span>
                    <svg class="w-3.5 h-3.5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
                    <div class="h-4 w-px bg-white/20 mx-1"></div>
                    <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                    <div class="w-2 h-2 bg-green-500 rounded-full shadow-[0_0_8px_rgba(34,197,94,0.8)] ml-1"></div>
                </div>
            </header>

            <!-- Chat View section -->
            <section id="view-chat" class="flex-1 flex flex-col justify-center items-center p-4">
                <h1 class="text-[32px] font-semibold mb-8 text-white tracking-tight">How can I help you today?</h1>
                <div class="w-full max-w-3xl input-bar rounded-2xl flex items-center p-2 border border-white/10 shadow-2xl transition-all focus-within:border-white/30 focus-within:ring-1 focus-within:ring-white/20">
                    <div class="flex items-center gap-1 pl-2">
                        <button class="p-2 text-gray-400 hover:text-white transition rounded-full hover:bg-white/5 disabled:opacity-50">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
                        </button>
                        <button class="p-2 text-gray-400 hover:text-white transition rounded-full hover:bg-white/5 disabled:opacity-50">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
                        </button>
                    </div>
                    <input type="text" class="flex-1 bg-transparent border-none text-white focus:outline-none px-4 py-3 placeholder-gray-500 text-[15px]" placeholder="Message...">
                    <button class="p-2 bg-white text-black rounded-full hover:bg-gray-200 transition shadow-md w-9 h-9 flex items-center justify-center mr-1 disabled:opacity-50">
                        <svg class="w-4 h-4 ml-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M14 5l7 7m0 0l-7 7m7-7H3"></path></svg>
                    </button>
                </div>
                <p class="text-xs text-gray-500 mt-4 h-4">Currently operating as a privacy proxy. Chat UI is illustrative only.</p>
            </section>

            <!-- Logs View section -->
            <section id="view-logs" class="flex-1 overflow-y-auto p-8 pt-24 hidden">
                <div class="max-w-5xl mx-auto">
                    <div class="flex items-center justify-between mb-8">
                        <h2 class="text-2xl font-bold text-white flex items-center gap-3">
                            <svg class="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"></path></svg>
                            Request Logs
                        </h2>
                        <div class="flex items-center gap-5">
                            <label class="flex items-center gap-2 text-sm text-gray-400 cursor-pointer hover:text-white transition group">
                                <div class="relative flex items-center justify-center">
                                    <input type="checkbox" id="shielded-filter" onchange="lastLogsHash = ''; fetchLogs()" class="peer appearance-none w-5 h-5 border border-white/20 rounded bg-[#1a1a1a] checked:bg-blue-500 checked:border-blue-500 transition-colors cursor-pointer">
                                    <svg class="absolute w-3.5 h-3.5 text-white opacity-0 peer-checked:opacity-100 pointer-events-none transition-opacity" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"></path></svg>
                                </div>
                                <span class="select-none font-medium">Only Shielded</span>
                            </label>
                            <button onclick="fetchLogs()" class="text-sm bg-white/10 hover:bg-white/20 text-white px-4 py-2 rounded-lg transition border border-white/5 flex items-center gap-2">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                                Refresh
                            </button>
                        </div>
                    </div>
                    <div id="logs-container" class="space-y-5"></div>
                </div>
            </section>

            <!-- Settings View section -->
            <section id="view-settings" class="flex-1 overflow-y-auto p-8 pt-24 hidden">
                <div class="max-w-3xl mx-auto">
                    <h2 class="text-2xl font-bold mb-8 text-white flex items-center gap-3">
                        <svg class="w-6 h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                        Settings & Exclusions
                    </h2>
                    
                    <div class="bg-[#1a1a1a] p-7 rounded-2xl border border-white/5 shadow-lg">
                        <h3 class="text-lg font-medium text-gray-200 mb-2">Custom Exclusions</h3>
                        <p class="text-sm text-gray-500 mb-6">Add specific phrases, secrets, or project names that should be automatically redacted from requests before being sent to the LLM.</p>
                        
                        <div class="flex gap-4 mb-8">
                            <input type="text" id="new-exclusion" placeholder="Add a phrase to exclude..." 
                                   class="flex-1 bg-[#242424] border border-white/10 text-white px-4 py-3 rounded-xl focus:outline-none focus:border-white/30 focus:shadow-[0_0_0_1px_rgba(255,255,255,0.1)] transition-all">
                            <button onclick="addExclusion()" class="bg-white text-black font-semibold px-6 py-3 rounded-xl hover:bg-gray-200 transition-colors shadow-md">Add Rule</button>
                        </div>
                        
                        <div class="space-y-3">
                            <h4 class="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Active Rules</h4>
                            <div id="exclusions-list" class="flex flex-wrap gap-2 min-h-[50px] p-4 bg-[#121212] rounded-xl border border-white/5">
                                <!-- Dynamic exclusions go here -->
                            </div>
                        </div>
                    </div>
                </div>
            </section>
        </main>

        <script>
            // UI Tab Switching logic
            function switchTab(tabId, btnElement) {
                document.querySelectorAll('section[id^="view-"]').forEach(el => el.classList.add('hidden'));
                document.getElementById('view-' + tabId).classList.remove('hidden');
                
                // Update active state in nav
                if(btnElement) {
                    document.querySelectorAll('.nav-btn').forEach(btn => {
                        btn.classList.remove('bg-white/10', 'font-medium');
                    });
                    btnElement.classList.add('bg-white/10', 'font-medium');
                }
            }

            async function fetchExclusions() {
                const response = await fetch('/api/config');
                const config = await response.json();
                const container = document.getElementById('exclusions-list');
                
                if (config.exclusions.length === 0) {
                    container.innerHTML = '<span class="text-sm text-gray-500 italic">No custom exclusions defined.</span>';
                    return;
                }
                
                container.innerHTML = config.exclusions.map(ex => `
                    <span class="inline-flex items-center bg-[#2a2a2a] text-gray-300 text-sm px-3 py-1.5 rounded-lg border border-white/10 shadow-sm group hover:border-white/20 transition-all">
                        <span class="mr-2 font-mono text-xs text-purple-400">#</span>
                        ${ex}
                        <button onclick="removeExclusion('${ex}')" class="ml-3 text-gray-500 hover:text-red-400 hover:bg-red-400/10 p-0.5 rounded-md transition-colors">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                        </button>
                    </span>
                `).join('');
            }

            async function addExclusion() {
                const input = document.getElementById('new-exclusion');
                const phrase = input.value.trim();
                if (!phrase) return;

                const response = await fetch('/api/exclusions', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ phrase })
                });

                if (response.ok) {
                    input.value = '';
                    fetchExclusions();
                }
            }

            async function removeExclusion(phrase) {
                const response = await fetch(`/api/exclusions/${encodeURIComponent(phrase)}`, {
                    method: 'DELETE'
                });

                if (response.ok) {
                    fetchExclusions();
                }
            }

            function highlightPlaceholders(text) {
                if (!text) return text;
                const escaped = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                return escaped.replace(/(&lt;[A-Z0-9_-]+&gt;)/g, '<span class="bg-[#3d3119] text-[#ffd666] px-1.5 py-0.5 rounded border border-[#ffd666]/30 font-mono text-[11px] mx-0.5 shadow-sm">$1</span>');
            }

            function extractTextContent(text) {
                if (!text) return '(Empty)';
                const results = [];
                function findContent(obj) {
                    if (!obj || typeof obj !== 'object') return;
                    if (Array.isArray(obj)) {
                        obj.forEach(findContent);
                        return;
                    }
                    if (obj.hasOwnProperty('text') && typeof obj.text === 'string') {
                        results.push(obj.text);
                    } else if (obj.hasOwnProperty('content') && typeof obj.content === 'string') {
                        results.push(obj.content);
                    } else {
                        for (const key in obj) {
                            findContent(obj[key]);
                        }
                    }
                }
                const chunks = text.split(/\\n?data: /);
                chunks.forEach(chunk => {
                    const trimmed = chunk.trim();
                    if (!trimmed || trimmed === '[DONE]') return;
                    try {
                        findContent(JSON.parse(trimmed));
                    } catch (e) {
                        try {
                            const jsonMatch = trimmed.match(/\\{.*\\}/s);
                            if (jsonMatch) {
                                findContent(JSON.parse(jsonMatch[0]));
                            }
                        } catch (err) {}
                    }
                });

                if (results.length > 0) {
                    return results.join('\\n\\n').trim();
                }
                return text;
            }

            let lastLogsHash = '';

            async function fetchLogs() {
                const response = await fetch('/api/logs');
                const allLogs = await response.json();
                
                let logs = allLogs.filter(log => 
                    log.resp_before && (
                        log.resp_before.toLowerCase().includes('"content"') || 
                        log.resp_before.toLowerCase().includes('"parts"') ||
                        log.resp_before.toLowerCase().includes('"text"')
                    )
                );

                const filterShielded = document.getElementById('shielded-filter').checked;
                if (filterShielded) {
                    const shieldRegex = /<(PRIVATE|GIBBERISH|IP_ADDRESS|PERSON|EMAIL|ENV_VALUE|EXCLUSION)_/i;
                    logs = logs.filter(log => {
                        return (log.req_after && shieldRegex.test(log.req_after)) || 
                               (log.resp_before && shieldRegex.test(log.resp_before));
                    });
                }

                const logsStr = JSON.stringify(logs);
                if (logsStr === lastLogsHash) return;
                lastLogsHash = logsStr;

                const scrollStates = new Map();
                document.querySelectorAll('[data-scroll-id]').forEach(el => {
                    scrollStates.set(el.getAttribute('data-scroll-id'), { top: el.scrollTop, left: el.scrollLeft });
                });

                const container = document.getElementById('logs-container');
                if (logs.length === 0) {
                    container.innerHTML = `
                    <div class="text-center py-16 bg-[#1a1a1a] rounded-2xl border border-white/5 border-dashed">
                        <svg class="w-12 h-12 text-gray-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                        <p class="text-gray-400 font-medium">No intercepted requests yet</p>
                        <p class="text-sm text-gray-500 mt-1">Make a request through the proxy to see logs here.</p>
                    </div>`;
                    return;
                }
                
                container.innerHTML = logs.map(log => {
                    const prettyReqBefore = extractTextContent(log.req_before) || '(None/Static)';
                    const prettyReqAfter = highlightPlaceholders(extractTextContent(log.req_after)) || '(None/Static)';
                    const prettyReceived = highlightPlaceholders(extractTextContent(log.resp_before)) || '(Streaming...)';
                    const prettyRestored = highlightPlaceholders(extractTextContent(log.resp_after)) || '(Streaming...)';
                    
                    return `
                    <div class="bg-[#1a1a1a] rounded-2xl border border-white/5 overflow-hidden shadow-lg transition-transform hover:border-white/10">
                        <div class="bg-[#242424] px-5 py-3 border-b border-white/5 flex justify-between items-center">
                            <div class="flex items-center gap-3">
                                <span class="px-2.5 py-1 rounded-md text-[10px] font-bold bg-white/10 text-gray-200 uppercase tracking-wider">${log.method} ${log.path.split('/').pop()}</span>
                                <span class="font-mono text-[11px] text-gray-500">${log.timestamp}</span>
                            </div>
                        </div>
                        <div class="p-5 grid grid-cols-1 xl:grid-cols-2 gap-5">
                            <div>
                                <h3 class="text-[11px] font-bold text-gray-500 mb-3 uppercase tracking-wider flex items-center gap-2">
                                    <svg class="w-3.5 h-3.5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                                    Request Scrubbing
                                </h3>
                                <div class="space-y-3">
                                    <div class="bg-[#0f0f0f] p-3.5 rounded-xl border border-white/5">
                                        <div class="text-[10px] text-gray-500 mb-2 uppercase tracking-wide font-semibold">Original Prompt</div>
                                        <pre data-scroll-id="${log.id}-req-before" class="text-[13px] text-gray-300 whitespace-pre-wrap break-all font-mono leading-relaxed max-h-48 overflow-y-auto">${prettyReqBefore}</pre>
                                    </div>
                                    <div class="bg-[#0f1711] p-3.5 rounded-xl border border-green-500/20">
                                        <div class="text-[10px] text-green-500 mb-2 uppercase tracking-wide font-semibold">Scrubbed (Sent to LLM)</div>
                                        <pre data-scroll-id="${log.id}-req-after" class="text-[13px] text-green-100 whitespace-pre-wrap break-all font-mono leading-relaxed max-h-48 overflow-y-auto">${prettyReqAfter}</pre>
                                    </div>
                                </div>
                            </div>
                            <div>
                                <h3 class="text-[11px] font-bold text-gray-500 mb-3 uppercase tracking-wider flex items-center gap-2">
                                    <svg class="w-3.5 h-3.5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z"></path></svg>
                                    Response Processing
                                </h3>
                                <div class="space-y-3">
                                    <div class="bg-[#0f0f0f] p-3.5 rounded-xl border border-white/5">
                                        <div class="text-[10px] text-gray-500 mb-2 uppercase tracking-wide font-semibold">Received from LLM</div>
                                        <pre data-scroll-id="${log.id}-resp-before" class="text-[13px] text-gray-300 whitespace-pre-wrap break-all font-mono leading-relaxed max-h-48 overflow-y-auto">${prettyReceived}</pre>
                                    </div>
                                    <div class="bg-[#0f141f] p-3.5 rounded-xl border border-blue-500/20">
                                        <div class="text-[10px] text-blue-400 mb-2 uppercase tracking-wide font-semibold">Restored (Sent to Client)</div>
                                        <pre data-scroll-id="${log.id}-resp-after" class="text-[13px] text-blue-100 whitespace-pre-wrap break-all font-mono leading-relaxed max-h-48 overflow-y-auto">${prettyRestored}</pre>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `}).join('');

                document.querySelectorAll('[data-scroll-id]').forEach(el => {
                    const state = scrollStates.get(el.getAttribute('data-scroll-id'));
                    if (state) {
                        el.scrollTop = state.top;
                        el.scrollLeft = state.left;
                    }
                });
            }
            fetchLogs();
            fetchExclusions();
            setInterval(fetchLogs, 5000);
            
            // Listen for enter on input
            document.getElementById('new-exclusion').addEventListener('keypress', function (e) {
                if (e.key === 'Enter') addExclusion();
            });
        </script>
    </body>
    </html>
    """


@app.get("/api/logs")
async def get_logs():
    return list(REQUEST_LOGS)

@app.get("/api/config")
async def get_config():
    with EXCLUSIONS_LOCK:
        return {
            "exclusions": list(DEFAULT_EXCLUSIONS),
            "scrubbing_mode": SCRUBBING_MODE,
            "analyzer_type": ANALYZER_TYPE
        }

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
