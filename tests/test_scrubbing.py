import pytest
import os
import sys

# Add the root directory to the path so we can import proxy
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from proxy import scrub_text, de_scrub_text

@pytest.mark.asyncio
async def test_scrub_and_descrub_ips():
    text = "The server is at 192.168.1.1 and the DB at 10.0.0.5."
    scrubbed, mapping = await scrub_text(text)
    
    # Verify IPs are replaced
    assert "192.168.1.1" not in scrubbed
    assert "10.0.0.5" not in scrubbed
    assert "<PRIVATE_DATA_1>" in scrubbed or "<IP_ADDRESS_1>" in scrubbed
    
    # Verify de-scrubbing restores the IPs
    restored = de_scrub_text(scrubbed, mapping)
    assert restored == text

@pytest.mark.asyncio
async def test_scrub_gibberish():
    text = "Access the secret key: abc123def456."
    scrubbed, mapping = await scrub_text(text)
    
    # Verify gibberish is replaced
    assert "abc123def456" not in scrubbed
    assert "<PRIVATE_DATA_1>" in scrubbed or "<GIBBERISH_1>" in scrubbed
    
    # Verify de-scrubbing restores the gibberish
    restored = de_scrub_text(scrubbed, mapping)
    assert restored == text

@pytest.mark.asyncio
async def test_scrub_custom_exclusions():
    # Set a custom exclusion for this test
    os.environ["DEFAULT_EXCLUSIONS"] = "my-secret-cluster,internal-service"
    import proxy
    # Re-trigger the environment loading for the test
    proxy.DEFAULT_EXCLUSIONS = ["my-secret-cluster", "internal-service"]
    
    text = "Connect to my-secret-cluster through internal-service."
    scrubbed, mapping = await scrub_text(text)
    
    # Verify custom exclusions are replaced
    assert "my-secret-cluster" not in scrubbed
    assert "internal-service" not in scrubbed
    
    # Verify de-scrubbing restores them
    restored = de_scrub_text(scrubbed, mapping)
    assert restored == text

@pytest.mark.asyncio
async def test_semantic_mode():
    os.environ["SCRUBBING_MODE"] = "semantic"
    import proxy
    proxy.SCRUBBING_MODE = "semantic"
    
    text = "My email is test@example.com."
    scrubbed, mapping = await scrub_text(text)
    
    # Verify semantic label is used (Presidio should detect EMAIL_ADDRESS)
    assert "<EMAIL_ADDRESS_1>" in scrubbed
    
    # Verify de-scrubbing restores it
    restored = de_scrub_text(scrubbed, mapping)
    assert restored == text

@pytest.mark.asyncio
async def test_sequential_scrubbing_priority():
    # Set an exclusion that overlaps with what Presidio might find
    # 'John Doe' is a name, but we want it scrubbed as an EXCLUSION first.
    import proxy
    proxy.DEFAULT_EXCLUSIONS = ["John Doe"]
    proxy.SCRUBBING_MODE = "semantic"
    proxy.ANALYZER_TYPE = "both"
    
    text = "Hello, my name is John Doe."
    scrubbed, mapping = await scrub_text(text)
    
    # 1. Verify it was caught by the EXCLUSION logic first
    # If it was caught by Presidio, it would be <PERSON_1>
    # If it was caught by Exclusion, it will be <EXCLUSION_1>
    assert "<EXCLUSION_1>" in scrubbed
    assert "<PERSON_1>" not in scrubbed
    
    # 2. Verify mapping is correct
    assert mapping["<EXCLUSION_1>"] == "John Doe"
    
    # 3. Verify restoration
    restored = de_scrub_text(scrubbed, mapping)
    assert restored == text

@pytest.mark.asyncio
async def test_overlap_exclusion_handling():
    # Test that longer exclusions are handled before shorter ones
    import proxy
    proxy.DEFAULT_EXCLUSIONS = ["super-secret-service", "super-secret"]
    proxy.SCRUBBING_MODE = "generic"
    
    text = "Deploying to super-secret-service now."
    scrubbed, mapping = await scrub_text(text)
    
    # It should replace the long one entirely, not partially
    assert "<PRIVATE_DATA_1>" in scrubbed
    assert "-service" not in scrubbed 
    assert mapping["<PRIVATE_DATA_1>"] == "super-secret-service"
