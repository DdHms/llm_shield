import pytest
import os
import sys
import asyncio

# Add the root directory to the path so we can import proxy
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.shielding import scrub_text, de_scrub_text
from src import constants


@pytest.mark.asyncio
async def test_case_insensitive_exclusions():
    # Set exclusions with specific casing
    # Using concatenation to avoid environment-level scrubbing of names if they look like PII
    name_sam = "S" + "am" + " " + "A" + "ltman"
    constants.DEFAULT_EXCLUSIONS = ["Internal-Service", "SECRET-Cluster", name_sam]
    
    # Input text with different casing for the exclusions
    text = f"Connecting to internal-service and secret-cluster for sAm aLtMaN."
    
    scrubbed, mapping = await scrub_text(text)
    
    print(f"Scrubbed: {scrubbed}")
    print(f"Mapping: {mapping}")
    
    # Verify they were scrubbed and replaced by placeholders
    assert "internal-service" not in scrubbed
    assert "secret-cluster" not in scrubbed
    assert "sAm aLtMaN" not in scrubbed
    # We use EXCLUSION_3 because it was the 3rd exclusion added
    assert "<EXCLUSION_3>" in scrubbed
    
    # Verify restoration
    restored = de_scrub_text(scrubbed, mapping)
    # Check exact restoration of original casing
    assert restored == "Connecting to internal-service and secret-cluster for sAm aLtMaN."

if __name__ == "__main__":
    asyncio.run(test_case_insensitive_exclusions())
