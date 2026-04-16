import pytest
import os
import sys
import asyncio

# Add the root directory to the path so we can import proxy
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from proxy import scrub_text, de_scrub_text

@pytest.mark.asyncio
async def test_case_insensitive_exclusions():
    import proxy
    # Set exclusions with specific casing
    proxy.DEFAULT_EXCLUSIONS = ["Internal-Service", "SECRET-Cluster", "Sam Altman"]
    
    # Input text with different casing for the exclusions
    text = "Connecting to internal-service and secret-cluster for sAm aLtMaN."
    
    scrubbed, mapping = await scrub_text(text)
    
    print(f"Scrubbed: {scrubbed}")
    print(f"Mapping: {mapping}")
    
    # Verify they were scrubbed and replaced by placeholders
    assert "internal-service" not in scrubbed
    assert "secret-cluster" not in scrubbed
    assert "sAm aLtMaN" not in scrubbed
    assert "<EXCLUSION_3>" in scrubbed
    
    # Verify restoration
    restored = de_scrub_text(scrubbed, mapping)
    # Check exact restoration of original casing
    assert restored == "Connecting to internal-service and secret-cluster for sAm aLtMaN."

if __name__ == "__main__":
    asyncio.run(test_case_insensitive_exclusions())
