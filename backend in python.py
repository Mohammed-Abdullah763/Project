from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from typing import Optional
import secrets
import datetime

app = FastAPI(title="KeyForge API")

# Add CORS (lets HTML file call Python)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store API keys
API_KEYS = {}

@app.get("/")
def homepage():
    """Serve the HTML file"""
    with open("index.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.get("/generate-api-key")
def generate_api_key():
    """Generate a REAL working API key"""
    new_key = "api_key_" + secrets.token_hex(40)
    
    API_KEYS[new_key] = {
        "created_at": datetime.datetime.now().isoformat(),
        "status": "active",
        "type": "full"
    }
    
    return {
        "success": True,
        "api_key": new_key,
        "message": "API key generated successfully!"
    }

@app.get("/validate")
def validate_key(key: Optional[str] = None):
    """Validate if an API key is real"""
    if not key:
        return {"valid": False, "message": "No key provided"}
    
    if key not in API_KEYS:
        return {"valid": False, "message": "Invalid API key"}
    
    return {
        "valid": True,
        "api_key": key,
        "message": "This is a REAL working API key!"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
