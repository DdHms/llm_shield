import os
import threading
from fastapi.responses import HTMLResponse

def get_dashboard_html():
    with open("dashboard.html", "r") as f:
        return f.read()

def start_fastapi(app):
    import uvicorn
    # Runs your FastAPI server in the background
    # Use 0.0.0.0 to allow access from outside the container
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")

def run_application(app):
    import webview
    # 1. Start FastAPI
    if os.getenv("HEADLESS", "false").lower() == "true":
        print("Running in HEADLESS mode (FastAPI only)...")
        start_fastapi(app)
    else:
        t = threading.Thread(target=start_fastapi, args=(app,))
        t.daemon = True
        t.start()

        # 2. Open a beautiful native GUI window for the user
        try:
            webview.create_window('Gemini Privacy Shield', 'http://localhost:8080/dashboard')
            webview.start()
        except Exception as e:
            print(f"GUI failed to start: {e}. Falling back to server only.")
            # If GUI fails (common in Docker), keep the thread alive or restart in main
            start_fastapi(app)
