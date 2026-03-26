import pytest
import json
import httpx
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch
import sys
import os

# Add the root directory to the path so we can import proxy
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from proxy import app

client = TestClient(app)

@pytest.mark.asyncio
async def test_proxy_scrubs_prompt_and_restores_response():
    # Mock data
    prompt_with_pii = {
        "request": {
            "contents": [
                {
                    "parts": [{"text": "Hello, my name is John Doe and my IP is 192.168.1.1."}]
                }
            ]
        }
    }
    
    # Expected scrubbed response from "Gemini"
    # Note: Presidio detects names as PERSON
    mock_gemini_response = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "Nice to meet you, <PERSON_1>. Your IP is <IP_ADDRESS_1>."}]
                }
            }
        ]
    }

    # Use patch to intercept the outbound httpx call from the proxy
    with patch("httpx.AsyncClient.send", new_callable=AsyncMock) as mock_send:
        # Mock the response from Gemini
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/json"}
        
        # Generator for streaming response simulation
        async def mock_stream_iterator():
            yield json.dumps(mock_gemini_response).encode("utf-8")
            
        mock_response.aiter_bytes.return_value = mock_stream_iterator()
        mock_send.return_value = mock_response

        # Call the proxy endpoint
        # The proxy triggers scrubbing if "v1internal" is in the path
        response = client.post(
            "/v1internal/models/gemini-1.5-pro:generateContent",
            json=prompt_with_pii
        )

        # Verify the proxy returned 200
        assert response.status_code == 200
        
        # Verify the response was de-scrubbed correctly
        resp_data = response.json()
        restored_text = resp_data["candidates"][0]["content"]["parts"][0]["text"]
        
        assert "John Doe" in restored_text
        assert "192.168.1.1" in restored_text
        assert "<PERSON_1>" not in restored_text
        assert "<IP_ADDRESS_1>" not in restored_text

        # Verify the outbound call (mock_send) was actually scrubbed
        # This checks the first argument to mock_send (the httpx.Request object)
        captured_request = mock_send.call_args[0][0]
        scrubbed_payload = json.loads(captured_request.content)
        scrubbed_text = scrubbed_payload["request"]["contents"][0]["parts"][0]["text"]
        
        assert "John Doe" not in scrubbed_text
        assert "192.168.1.1" not in scrubbed_text
        assert "<PERSON_1>" in scrubbed_text or "<PRIVATE_DATA_1>" in scrubbed_text
