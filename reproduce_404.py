
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

app = FastAPI()

@app.api_route("/{path:path}", methods=["GET", "POST"])
async def catch_all(request: Request, path: str):
    return {"path": path}

client = TestClient(app)

def test_encoded_colon():
    # Test with encoded colon
    response = client.post("/v1beta/models/gemini-1.5-pro%3AgenerateContent")
    print(f"Encoded colon response: {response.status_code} - {response.json() if response.status_code == 200 else response.text}")

    # Test with literal colon
    response = client.post("/v1beta/models/gemini-1.5-pro:generateContent")
    print(f"Literal colon response: {response.status_code} - {response.json() if response.status_code == 200 else response.text}")

if __name__ == "__main__":
    test_encoded_colon()
