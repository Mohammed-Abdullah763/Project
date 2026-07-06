"""
StudyMind — Complete Core API Gateway
Provides structured endpoints matching all client user interface scripts.
"""
import os
import re
import json
import webbrowser
import asyncio
from typing import Optional, Any
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
import httpx
import uvicorn

# ══════════════════════════════════════════════════════════════════════════════
# 1. ENVIRONMENT CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
class AppConfig:
    APP_NAME = "StudyMind"
    VERSION = "3.1.0"
    
    # Reads from system environment. Set this variable before booting!
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    MAX_TOKENS = 3000

# ══════════════════════════════════════════════════════════════════════════════
# 2. CLIENT UTILITY UTILITIES & DATA PARSERS
# ══════════════════════════════════════════════════════════════════════════════
_async_client: Optional[httpx.AsyncClient] = None

def get_http_client() -> httpx.AsyncClient:
    global _async_client
    if _async_client is None:
        _async_client = httpx.AsyncClient(timeout=60.0, http2=True)
    return _async_client

def extract_structured_json(raw_text: str) -> Any:
    """Removes standard markdown formatting code fences seamlessly."""
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        cleaned = "\n".join(lines[1:]).rsplit("```", 1)[0]
    match = re.search(r'[\[{][\s\S]*[\]}]', cleaned)
    return json.loads(match.group(0) if match else cleaned.strip())

async def hit_gemini_api(system_prompt: str, user_text: str) -> str:
    if not AppConfig.GEMINI_API_KEY:
        raise HTTPException(
            status_code=500, 
            detail="Missing GEMINI_API_KEY. Please ensure your key environment variable is configured."
        )
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={AppConfig.GEMINI_API_KEY}"
    payload = {
        "contents": [{"parts": [{"text": f"{system_prompt}\n\nUser Input Data Context:\n{user_text}"}]}],
        "generationConfig": {
            "maxOutputTokens": AppConfig.MAX_TOKENS,
            "temperature": 0.15
        }
    }
    client = get_http_client()
    resp = await client.post(url, headers={"Content-Type": "application/json"}, json=payload)
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Google Core Upstream Failure: {resp.text}")
    return resp.json()["candidates"][0]["content"]["parts"][0]["text"]

# ══════════════════════════════════════════════════════════════════════════════
# 3. FASTAPI ROUTING ROUTER DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════
app = FastAPI(title=AppConfig.APP_NAME, version=AppConfig.VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class FeatureRequest(BaseModel):
    feature: str
    text: str

class ChatRequest(BaseModel):
    message: str
    context: str
    history: list = []

# Exact JSON structure shapes required by the frontend JavaScript rendering framework
FEATURE_PROMPTS = {
    "summarize": (
        "You are an expert educational summarizing system. Return a valid JSON object ONLY. Structure:\n"
        '{"tldr": "One sentence main takeaway summary", "key_points": ["Point A", "Point B"], '
        '"concepts": ["Tag 1", "Tag 2"], "importance": "Why this matters context layout explanation"}'
    ),
    "flashcards": (
        "Convert the text context into a valid JSON array of flashcards objects ONLY. Structure:\n"
        '[{"q": "Targeted Question?", "a": "Precise brief flashcard answer", "hint": "Small helper hint", "difficulty": "easy"}]'
    ),
    "quiz": (
        "Generate a balanced multi-choice evaluation exam from text. Return a JSON array ONLY. Structure:\n"
        '[{"q": "Question formulation?", "options": ["Choice A", "Choice B", "Choice C"], "answer": 0, "explanation": "Detailed correct logic breakdown."}]'
    ),
    "mindmap": (
        "Convert text into an interconnected visual network map schema tree. Return a valid JSON object ONLY. Structure:\n"
        '{"root": "Overarching Core Topic Name", "branches": [{"name": "Subcategory Component Branch", "leaves": ["Specific structural detail 1", "Fact item 2"]}]}'
    ),
    "terms": (
        "Deconstruct core vocabulary keywords from materials. Return a valid JSON array ONLY. Structure:\n"
        '[{"term": "Target Word Keyword", "definition": "Direct textbook dictionary summary clarity context string."}]'
    ),
    "plan": (
        "Build a multi-day timeline calendar planning agenda layout. Return a valid JSON array ONLY. Structure:\n"
        '[{"day": 1, "title": "Day Core Theme Topic Tracker", "tasks": "Task assignment action milestone A, Task item B"}]'
    )
}

@app.post("/api/process-feature")
async def process_study_feature(payload: FeatureRequest):
    feat = payload.feature.lower().strip()
    if feat not in FEATURE_PROMPTS:
        raise HTTPException(status_code=400, detail=f"Operation target feature '{payload.feature}' is invalid.")
    
    try:
        raw_output = await hit_gemini_api(FEATURE_PROMPTS[feat], payload.text)
        structured_json = extract_structured_json(raw_output)
        return JSONResponse(content=structured_json)
    except Exception as err:
        return JSONResponse(status_code=502, content={"error": f"AI Parsing generation error: {str(err)}"})

@app.post("/api/chat-tutor")
async def chat_tutor_endpoint(payload: ChatRequest):
    try:
        system_instruction = (
            f"You are StudyMind AI, an encouraging and ultra-clear personal school coach tutor.\n"
            f"The notebook content context the student is researching is here:\n"
            f"==================\n{payload.context[:3500]}\n==================\n"
            f"Use this text to answer their prompts accurately with helpful examples. Use Markdown for layout spacing."
        )
        
        # Format chat chain
        conversation_history_block = ""
        for message_turn in payload.history[-6:]:
            role_label = "Student" if message_turn.get("role") == "user" else "Tutor"
            conversation_history_block += f"{role_label}: {message_turn.get('content')}\n"
        conversation_history_block += f"Student: {payload.message}"
        
        raw_chat_response = await hit_gemini_api(system_instruction, conversation_history_block)
        return JSONResponse(content={"text": raw_chat_response})
    except Exception as err:
        return JSONResponse(status_code=502, content={"error": str(err)})

# ══════════════════════════════════════════════════════════════════════════════
# 4. FRONTEND HOOK INJECTION ENGINE
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/", response_class=HTMLResponse)
def serve_and_wire_frontend():
    try:
        with open("frontend.html", "r", encoding="utf-8") as file:
            html_content = file.read()
            
            # Re-links the frontend's main feature buttons to point directly to Python
            html_content = html_content.replace(
                "async function callClaude(feat, text) {",
                """async function callClaude(feat, text) {
    const response = await fetch('/api/process-feature', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ feature: feat, text: text })
    });
    if (!response.ok) throw new Error('API server failed processing request.');
    return await response.json();
}
function _disabled_old_callClaude() {"""
            )
            
            # Re-links the sidebar Chat Tutor container straight to your python chat handler
            html_content = html_content.replace(
                "async function sendChat() {",
                """async function sendChat() {
    const input = document.getElementById('chatInput');
    const msg = input.value.trim();
    if(!msg) return;
    input.value = '';
    addMsg('user', msg);
    
    const sendBtn = document.getElementById('chatSendBtn');
    sendBtn.disabled = true;
    addMsg('ai', 'Thinking…', 'typing');
    
    try {
        const response = await fetch('/api/chat-tutor', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: msg,
                context: state.notes || '',
                history: chatHistory
            })
        });
        document.getElementById('typing')?.remove();
        const data = await response.json();
        
        if (data.error) {
            addMsg('ai', '⚠️ Error: ' + data.error);
        } else {
            addMsg('ai', data.text);
            chatHistory.push({role: 'user', content: msg});
            chatHistory.push({role: 'assistant', content: data.text});
        }
    } catch(e) {
        document.getElementById('typing')?.remove();
        addMsg('ai', '❌ API Gateway timed out or was disconnected.');
    } finally {
        sendBtn.disabled = false;
    }
}
function _disabled_old_sendChat() {"""
            )
            
            return html_content
    except FileNotFoundError:
        return "<h3>System Error: Ensure frontend.html is in the exact same directory alongside app.py</h3>"

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.call_later(1.0, lambda: webbrowser.open("http://127.0.0.1:8000"))
    uvicorn.run(app, host="0.0.0.0", port=8000)
