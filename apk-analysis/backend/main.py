import hashlib
import os
import shutil
import uuid
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from static_analysis import analyze_apk
from dynamic_analysis import run_dynamic_analysis
from genai_provider import get_genai_verdict
from scoring import compute_risk_score
from report import generate_report

app = FastAPI(title="ShieldNetX-APK Analysis API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# in-memory job store — fine for a hackathon demo, swap for Redis/Postgres later
JOBS = {}


def run_pipeline(job_id: str, filepath: str):
    try:
        JOBS[job_id]["stage"] = "static_analysis"
        static_findings = analyze_apk(filepath)
        JOBS[job_id]["static_findings"] = static_findings

        JOBS[job_id]["stage"] = "dynamic_analysis"
        dynamic_findings = run_dynamic_analysis(filepath)
        JOBS[job_id]["dynamic_findings"] = dynamic_findings

        JOBS[job_id]["stage"] = "genai_analysis"
        findings_text = (
            f"Package: {static_findings['package_name']}\n"
            f"Permissions: {', '.join(static_findings['permissions'])}\n"
            f"Dangerous combos: {static_findings['dangerous_combos']}\n"
            f"Banking keywords found: {static_findings['banking_keyword_hits']}\n"
        )
        genai_verdict = get_genai_verdict(findings_text)
        JOBS[job_id]["genai_verdict"] = genai_verdict

        JOBS[job_id]["stage"] = "risk_scoring"
        risk = compute_risk_score(static_findings, genai_verdict, dynamic_findings)
        JOBS[job_id]["risk"] = risk

        JOBS[job_id]["stage"] = "report_generation"
        report = generate_report(static_findings, genai_verdict, risk, JOBS[job_id]["sha256"])
        JOBS[job_id]["report"] = report

        JOBS[job_id]["stage"] = "complete"
        JOBS[job_id]["completed_at"] = datetime.utcnow().isoformat()
    except Exception as e:
        JOBS[job_id]["stage"] = "error"
        JOBS[job_id]["error"] = str(e)


@app.post("/api/analyze")
async def analyze(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if not file.filename.endswith(".apk"):
        raise HTTPException(400, "File must be a .apk")

    job_id = str(uuid.uuid4())
    filepath = os.path.join(UPLOAD_DIR, f"{job_id}.apk")

    with open(filepath, "wb") as f:
        shutil.copyfileobj(file.file, f)

    with open(filepath, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()

    # dedup check
    for jid, job in JOBS.items():
        if job.get("sha256") == sha256 and job.get("stage") == "complete":
            return {"job_id": jid, "deduped": True}

    JOBS[job_id] = {
        "job_id": job_id,
        "filename": file.filename,
        "sha256": sha256,
        "stage": "queued",
        "submitted_at": datetime.utcnow().isoformat(),
    }

    background_tasks.add_task(run_pipeline, job_id, filepath)
    return {"job_id": job_id, "deduped": False}


@app.get("/api/status/{job_id}")
async def status(job_id: str):
    if job_id not in JOBS:
        raise HTTPException(404, "Job not found")
    job = JOBS[job_id]
    return {"job_id": job_id, "stage": job["stage"], "error": job.get("error")}


@app.get("/api/report/{job_id}")
async def report(job_id: str):
    if job_id not in JOBS:
        raise HTTPException(404, "Job not found")
    job = JOBS[job_id]
    if job["stage"] != "complete":
        raise HTTPException(409, f"Analysis not complete, current stage: {job['stage']}")
    return job


@app.get("/api/jobs")
async def list_jobs():
    return list(JOBS.values())


@app.get("/health")
async def health():
    return {"status": "ok"}
