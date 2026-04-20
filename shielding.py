import re
import time
import constants

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

    def apply_replacement(val, label):
        nonlocal scrubbed_text
        if not val or val in seen_texts:
            return
            
        if constants.SCRUBBING_MODE == "semantic" or label in ["EXCLUSION", "ENV_VALUE"]:
            counts[label] = counts.get(label, 0) + 1
            placeholder = f"<{label}_{counts[label]}>"
        else:
            counts["PRIVATE_DATA"] = counts.get("PRIVATE_DATA", 0) + 1
            placeholder = f"<PRIVATE_DATA_{counts['PRIVATE_DATA']}>"
            
        mapping[placeholder] = val
        seen_texts[val] = placeholder
        
        if val in scrubbed_text:
            scrubbed_text = scrubbed_text.replace(val, placeholder)

    # 1. process Custom Exclusions FIRST (Case-Insensitive)
    with constants.EXCLUSIONS_LOCK:
        sorted_exclusions = sorted(constants.DEFAULT_EXCLUSIONS, key=len, reverse=True)
    
    for excluded in sorted_exclusions:
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

        # Using \b word boundaries for exclusions to prevent over-scrubbing (like 'it' in 'iterator')
        # However, we only apply \b if the exclusion starts/ends with alphanumeric characters
        pattern = re.escape(excluded)
        if re.match(r'^\w', excluded):
            pattern = r'\b' + pattern
        if re.search(r'\w$', excluded):
            pattern = pattern + r'\b'
            
        scrubbed_text = re.sub(pattern, replacement_callback, scrubbed_text, flags=re.IGNORECASE)

    # 2. Collect potential matches from subsequent analyzers
    potential_matches = []

    # Presidio PII Detection
    if constants.ANALYZER_TYPE in ["presidio", "both"]:
        az = get_analyzer()
        if az:
            results = az.analyze(text=scrubbed_text, language='en')
            for res in results:
                potential_matches.append((scrubbed_text[res.start:res.end], res.entity_type))

    # Pattern Detection
    if constants.ANALYZER_TYPE in ["pattern", "both"]:
        ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', scrubbed_text)
        for ip in ips:
            potential_matches.append((ip, "IP_ADDRESS"))

        potential_gibberish = re.findall(r'\b(?=[A-Z0-9-]*\d)(?=[A-Z0-9-]*[a-zA-Z])[A-Z0-9-]{6,}\b', scrubbed_text)
        for g in potential_gibberish:
            potential_matches.append((g, "PRIVATE_KEY"))

    # Environment Variable Detection (e.g. MY_ENV_VAR = some_value)
    env_vars = re.findall(r'\b[A-Z0-9_-]+\s*=\s*([A-Za-z0-9_-]+)', scrubbed_text)

    for val in env_vars:
        potential_matches.append((val, "ENV_VALUE"))

    potential_matches.sort(key=lambda x: len(x[0]), reverse=True)

    for val, label in potential_matches:
        apply_replacement(val, label)
        
    return scrubbed_text, mapping


def de_scrub_text(text: str, mapping: dict) -> str:
    """Replaces placeholders in the response with original PII values."""
    for placeholder, original_value in mapping.items():
        text = text.replace(placeholder, original_value)
        
        unicode_placeholder = placeholder.replace("<", "\\u003c").replace(">", "\\u003e")
        text = text.replace(unicode_placeholder, original_value)
        
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
