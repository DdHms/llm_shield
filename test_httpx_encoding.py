
import httpx
import asyncio

async def test_httpx_encoding():
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent"
    async with httpx.AsyncClient() as client:
        req = client.build_request("POST", url)
        print(f"Original URL: {url}")
        print(f"httpx URL:    {req.url}")
        print(f"Encoded URL:  {str(req.url)}")

if __name__ == "__main__":
    asyncio.run(test_httpx_encoding())
