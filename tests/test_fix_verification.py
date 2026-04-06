import pytest
import os
import sys
import json
from fastapi.testclient import TestClient

# Add the root directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from proxy import app, scrub_text, de_scrub_text, ALLOWED_HEADERS

@pytest.mark.asyncio
async def test_overlapping_exclusions_merging():
    # Test that "abc" and "bcd" in "abcd" are merged and redacted together
    import proxy
    proxy.DEFAULT_EXCLUSIONS = ["abc", "bcd"]
    proxy.SCRUBBING_MODE = "generic"
    
    text = "Find abcd in this text."
    scrubbed, mapping = await scrub_text(text)
    
    # "abcd" should be one placeholder
    assert "<EXCLUSION_1>" in scrubbed
    assert "d" not in scrubbed[scrubbed.find("<EXCLUSION_1>"):] # Ensure 'd' is not left over
    
    # Verify restoration
    restored = de_scrub_text(scrubbed, mapping)
    assert restored == text

def test_header_whitelist():
    client = TestClient(app)
    # Host header should be stripped/ignored by our logic (handled by httpx but let's check our ALLOWED_HEADERS)
    assert "host" not in ALLOWED_HEADERS
    assert "cookie" not in ALLOWED_HEADERS
    assert "authorization" in ALLOWED_HEADERS

@pytest.mark.asyncio
async def test_placeholder_length_collision():
    # Test that <EXCLUSION_10> is replaced before <EXCLUSION_1>
    mapping = {
        "<EXCLUSION_1>": "short",
        "<EXCLUSION_10>": "long-secret"
    }
    text = "Here is <EXCLUSION_1> and <EXCLUSION_10>."
    restored = de_scrub_text(text, mapping)
    
    assert restored == "Here is short and long-secret."
    # If it was bugged, <EXCLUSION_1>0 might become "short0"
    assert "short0" not in restored

@pytest.mark.asyncio
async def test_request_validation_warning():
    # This just checks that the code runs without crashing on various formats
    import proxy
    
    # Gemini format
    payload = {"contents": [{"parts": [{"text": "hello"}]}]}
    # Should not raise
    proxy.GenericLLMPayload.model_validate(payload)
    
    # OpenAI format
    payload = {"messages": [{"role": "user", "content": "hello"}]}
    # Should not raise
    proxy.GenericLLMPayload.model_validate(payload)

    # Wrapped format
    payload = {"request": {"contents": [{"parts": [{"text": "hello"}]}]}}
    # Should not raise
    proxy.GenericLLMPayload.model_validate(payload)
