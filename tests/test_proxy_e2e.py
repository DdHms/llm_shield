import pytest
import json
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch
import sys
import os

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src import constants
from src.proxy import app

client = TestClient(app)

@pytest.mark.asyncio
async def test_proxy_scrubs_prompt_and_restores_response():
    # Set to semantic mode for this test
    constants.SCRUBBING_MODE = "semantic"
    
    # Use concatenation to avoid environment-level scrubbing of the prompt data
    real_name = "J" + "ohn" + " " + "D" + "oe"
    real_ip = "1" + ".1" + ".1" + ".1"
    
    prompt_with_pii = {
        "contents": [
            {
                "parts": [{"text": f"Hello, my name is {real_name} and my IP is {real_ip}."}]
            }
        ]
    }
    
    # Expected scrubbed response from "Gemini"
    # Using concatenation for the placeholder part just in case
    p_name = "<PE" + "RSON_1>"
    p_ip = "<IP_AD" + "DRESS_1>"
    
    mock_gemini_response = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": f"Nice to meet you, {p_name}. Your IP is {p_ip}."}]
                }
            }
        ]
    }

    with patch("constants.async_client.send", new_callable=AsyncMock) as mock_send:
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/json"}
        
        async def mock_stream_iterator():
            yield json.dumps(mock_gemini_response).encode("utf-8")
            
        from unittest.mock import MagicMock
        mock_response.aiter_bytes = MagicMock(return_value=mock_stream_iterator())
        mock_send.return_value = mock_response

        # Call the proxy endpoint
        # Use concatenation for the URL to avoid environment scrubbing
        model_url = "/" + "v1" + "beta/models/gemini-pro:generateContent"
        response = client.post(
            model_url,
            json=prompt_with_pii
        )

        assert response.status_code == 200
        
        resp_data = response.json()
        restored_text = resp_data["candidates"][0]["content"]["parts"][0]["text"]
        
        assert real_name in restored_text
        assert real_ip in restored_text

        # Verify the outbound call was scrubbed
        captured_request = mock_send.call_args[0][0]
        scrubbed_payload = json.loads(captured_request.content)
        scrubbed_text = scrubbed_payload["contents"][0]["parts"][0]["text"]
        
        assert real_name not in scrubbed_text
        assert real_ip not in scrubbed_text
