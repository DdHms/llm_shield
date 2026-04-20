from fastapi.testclient import TestClient
import sys
import os
import asyncio

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.proxy import app
from src import shielding

client = TestClient(app)

def test_add_and_remove_exclusion():
    # 1. Add exclusion
    phrase = "LiveEx" + "clusionTest"
    response = client.post("/api/exclusions", json={"phrase": phrase})
    assert response.status_code == 200
    assert response.json()["phrase"] == phrase

    # Verify it's in config
    response = client.get("/api/config")
    assert phrase in response.json()["exclusions"]

    # 2. Test scrubbing with the new exclusion
    async def check_scrub():
        scrubbed, mapping = await shielding.scrub_text(f"Hello {phrase}")
        return scrubbed, mapping

    loop = asyncio.get_event_loop()
    scrubbed, mapping = loop.run_until_complete(check_scrub())
    
    assert phrase not in scrubbed
    # Instead of checking for literal yedidya, check mapping
    assert any("EXCLUSION" in k for k in mapping.keys())

    # 3. Remove exclusion
    response = client.delete(f"/api/exclusions/{phrase}")
    assert response.status_code == 200

    # Verify it's gone from config
    response = client.get("/api/config")
    assert phrase not in response.json()["exclusions"]
