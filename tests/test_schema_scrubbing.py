import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.proxy import scrub_llm_payload


@pytest.mark.asyncio
async def test_openai_chat_completion_scrubs_message_content():
    secret = "KEY" + "123" + "AAA"
    data = {
        "model": "gpt-5-codex",
        "messages": [
            {"role": "system", "content": f"System context {secret}"},
            {"role": "user", "content": [{"type": "text", "text": f"User prompt {secret}"}]},
        ],
    }
    mapping = {}

    await scrub_llm_payload(data, "v1/chat/completions", {"counts": {}, "seen_texts": {}}, mapping)

    assert secret not in data["messages"][0]["content"]
    assert secret not in data["messages"][1]["content"][0]["text"]
    assert mapping


@pytest.mark.asyncio
async def test_openai_responses_scrubs_input_and_instructions():
    input_secret = "KEY" + "456" + "BBB"
    instruction_secret = "KEY" + "789" + "CCC"
    data = {
        "model": "gpt-5-codex",
        "instructions": f"Follow project context {instruction_secret}",
        "input": [
            {
                "role": "user",
                "content": [{"type": "input_text", "text": f"Review this {input_secret}"}],
            }
        ],
    }
    mapping = {}

    await scrub_llm_payload(data, "v1/responses", {"counts": {}, "seen_texts": {}}, mapping)

    assert instruction_secret not in data["instructions"]
    assert input_secret not in data["input"][0]["content"][0]["text"]
    assert mapping


@pytest.mark.asyncio
async def test_gemini_scrubbing_does_not_treat_content_or_input_as_text_fields():
    text_secret = "KEY" + "111" + "TEXT"
    content_secret = "KEY" + "222" + "CONTENT"
    input_secret = "KEY" + "333" + "INPUT"
    data = {
        "contents": [{"parts": [{"text": f"Scrub me {text_secret}"}]}],
        "content": f"Do not scrub this container value {content_secret}",
        "input": f"Do not scrub this container value {input_secret}",
    }
    mapping = {}

    await scrub_llm_payload(data, "v1beta/models/gemini-pro:generateContent", {"counts": {}, "seen_texts": {}}, mapping)

    assert text_secret not in data["contents"][0]["parts"][0]["text"]
    assert content_secret in data["content"]
    assert input_secret in data["input"]


@pytest.mark.asyncio
async def test_anthropic_messages_scrubs_system_and_message_content():
    system_secret = "KEY" + "444" + "SYSTEM"
    user_secret = "KEY" + "555" + "USER"
    assistant_secret = "KEY" + "666" + "ASSISTANT"
    data = {
        "model": "claude-sonnet-4-5",
        "system": f"Project context {system_secret}",
        "messages": [
            {"role": "user", "content": f"Plain content {user_secret}"},
            {
                "role": "assistant",
                "content": [{"type": "text", "text": f"Typed content {assistant_secret}"}],
            },
        ],
    }
    mapping = {}

    await scrub_llm_payload(data, "v1/messages", {"counts": {}, "seen_texts": {}}, mapping)

    assert system_secret not in data["system"]
    assert user_secret not in data["messages"][0]["content"]
    assert assistant_secret not in data["messages"][1]["content"][0]["text"]
    assert mapping


@pytest.mark.asyncio
async def test_anthropic_complete_scrubs_prompt():
    secret = "KEY" + "777" + "PROMPT"
    data = {
        "model": "claude-2.1",
        "prompt": f"\n\nHuman: Review this {secret}\n\nAssistant:",
    }
    mapping = {}

    await scrub_llm_payload(data, "v1/complete", {"counts": {}, "seen_texts": {}}, mapping)

    assert secret not in data["prompt"]
    assert mapping
