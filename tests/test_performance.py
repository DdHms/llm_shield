import pytest
import time
import os
import sys

# Add root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import proxy
from proxy import scrub_text

# A complex prompt to give the analyzers some work
TEST_PROMPT = """
Hello, my name is John Doe and I work for ACME Corp. 
You can reach me at john.doe@acme.com or call my mobile at 555-0199.
I am currently working on a server at 192.168.1.100 and the database is at 10.0.0.5.
The secret API key for the dev environment is abc123xyz789def456.
Please ensure the dev-db-cluster-01 is protected.
"""

@pytest.mark.asyncio
async def test_performance_comparison():
    # 1. Test Pattern Analyzer
    proxy.ANALYZER_TYPE = "pattern"
    proxy.DEFAULT_EXCLUSIONS = ["dev-db-cluster-01"]
    
    start_time = time.perf_counter()
    for _ in range(10): # Run 10 times for a better average
        await scrub_text(TEST_PROMPT)
    pattern_duration = (time.perf_counter() - start_time) / 10
    
    # 2. Test Presidio Analyzer
    proxy.ANALYZER_TYPE = "presidio"
    # Ensure analyzer is initialized
    proxy.get_analyzer()
    
    start_time = time.perf_counter()
    for _ in range(10):
        await scrub_text(TEST_PROMPT)
    presidio_duration = (time.perf_counter() - start_time) / 10
    
    # 3. Test Both
    proxy.ANALYZER_TYPE = "both"
    
    start_time = time.perf_counter()
    for _ in range(10):
        await scrub_text(TEST_PROMPT)
    both_duration = (time.perf_counter() - start_time) / 10

    print(f"\n--- Analyzer Performance (Average of 10 runs) ---")
    print(f"Pattern Analyzer:  {pattern_duration:.6f}s")
    print(f"Presidio Analyzer: {presidio_duration:.6f}s")
    print(f"Both Analyzers:    {both_duration:.6f}s")
    print(f"-----------------------------------------------")
    
    # Assertions to ensure they actually did something
    proxy.ANALYZER_TYPE = "pattern"
    scrubbed_pattern, _ = await scrub_text(TEST_PROMPT)
    assert "192.168.1.100" not in scrubbed_pattern
    assert "abc123xyz789def456" not in scrubbed_pattern
    
    proxy.ANALYZER_TYPE = "presidio"
    scrubbed_presidio, _ = await scrub_text(TEST_PROMPT)
    assert "John Doe" not in scrubbed_presidio
    assert "john.doe@acme.com" not in scrubbed_presidio
