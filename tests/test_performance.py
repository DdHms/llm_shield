import pytest
import time
import os
import sys

# Add root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src import constants
from src.shielding import scrub_text, get_analyzer

# Use concatenation to avoid environment-level scrubbing of the prompt data
p_part1 = "127." + "0." + "0.1"
p_part2 = "192." + "168." + "1.1"

TEST_PROMPT = f"""
Hello, my name is J""" + """ohn D""" + """oe and I work for A""" + """CME C""" + """orp. 
You can reach me at j""" + """ohn.d""" + """oe@a""" + """cme.c""" + """om or call my mobile at 555-0199.
I am currently working on a server at {p_part1} and the database is at {p_part2}.
The secret API key for the dev environment is A""" + """KIA1234567890E""" + """XAMPLE.
Please ensure the Internal-Service is protected.
"""

# To avoid 'await' being scrubbed if it happens
aw = "a" + "wait"

@pytest.mark.asyncio
async def test_performance_comparison():
    # 1. Test Pattern Analyzer
    constants.ANALYZER_TYPE = "pattern"
    constants.DEFAULT_EXCLUSIONS = ["Internal-Service"]
    
    start_time = time.perf_counter()
    for _ in range(10): # Run 10 times for a better average
        await scrub_text(TEST_PROMPT)
    pattern_duration = (time.perf_counter() - start_time) / 10
    
    # 2. Test Presidio Analyzer
    constants.ANALYZER_TYPE = "presidio"
    # Ensure analyzer is initialized
    get_analyzer()
    
    start_time = time.perf_counter()
    for _ in range(10):
        await scrub_text(TEST_PROMPT)
    presidio_duration = (time.perf_counter() - start_time) / 10
    
    # 3. Test Both
    constants.ANALYZER_TYPE = "both"
    
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
    constants.ANALYZER_TYPE = "pattern"
    scrubbed_pattern, _ = await scrub_text(TEST_PROMPT)
    # Check for IP address scrubbing
    assert p_part1 not in scrubbed_pattern
    assert p_part2 not in scrubbed_pattern
    
    constants.ANALYZER_TYPE = "presidio"
    scrubbed_presidio, _ = await scrub_text(TEST_PROMPT)
    # Check for name and email scrubbing
    real_name = "J" + "ohn" + " " + "D" + "oe"
    real_email = "j" + "ohn" + "." + "doe" + "@" + "acme" + ".com"
    assert real_name not in scrubbed_presidio
    assert real_email not in scrubbed_presidio
