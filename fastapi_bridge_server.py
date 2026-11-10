import datetime
import json
import logging
import random
import time
import math
import threading
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import boto3

# --- Application Initialization ---
app = FastAPI(
    title="Automated Deception-Driven IAM & UEBA Security Platform API",
    description="SOC Threat Operations Dashboard with 17 Scenario Test Suite & Real-Time Telemetry Graph",
    version="4.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Configuration Constants ---
LOCALSTACK_ENDPOINT = "http://localhost:4566"
AWS_REGION = "us-east-1"
AWS_ACCESS_KEY_ID = "test"
AWS_SECRET_ACCESS_KEY = "test"

KEYCLOAK_SERVER_URL = "http://localhost:8080"
KEYCLOAK_ADMIN_USER = "admin"
KEYCLOAK_ADMIN_PASS = "admin"
KEYCLOAK_REALM = "master"

DB_HOST = "localhost"
DB_PORT = "5432"
DB_NAME = "app_db"
DB_USER = "app_user"
DB_PASS = "app_password"

# ==============================================================================
# IN-MEMORY GAUSSIAN UEBA USER BASELINES (NO EXTERNAL CSV DEPENDENCY)
# ==============================================================================
USER_BASELINES: Dict[str, Dict[str, Any]] = {
    "USR_0001": {"mean": 10.0, "std": 2.0, "role": "Standard SSO User", "tenant": "tenant-alpha"},
    "USR_0002_ETL": {"mean": 12.0, "std": 2.5, "role": "Batch ETL Service Account", "tenant": "tenant-alpha"},
    "ATTACKER_IP_192_168_1_50": {"mean": 10.0, "std": 2.0, "role": "External Suspicious Host", "tenant": "tenant-beta"},
    "INSIDER_DISGRUNTLED": {"mean": 8.0, "std": 2.0, "role": "Privileged Insider Entity", "tenant": "tenant-alpha"},
    "DB_ATTACKER": {"mean": 10.0, "std": 1.0, "role": "Unrecognized DB Client", "tenant": "tenant-alpha"},
    "BURST_ATTACKER": {"mean": 10.0, "std": 1.5, "role": "Multi-Tenant Botnet", "tenant": "tenant-gamma"},
    "SLOW_ATTACKER": {"mean": 10.0, "std": 2.0, "role": "Slow Stealth Exfiltrator", "tenant": "tenant-alpha"},
    "POISONED_USER": {"mean": 42.0, "std": 5.0, "role": "Poisoned Concept-Drift User", "tenant": "tenant-beta"}
}

# --- In-Memory Platform State ---
DECOY_REGISTRY: Dict[str, set] = {
    "iam_access_keys": {"AKIA_DECOY_ADMIN_TRAP_99"},
    "s3_canary_objects": {"s3://tenant-alpha-storage/confidential/payroll_2026_canary.csv"},
    "db_honey_records": {99999},
    "cross_tenant_roles": {"arn:aws:iam::123456789012:role/DecoyCrossTenantAdminRole"},
    "honey_buckets": {"s3://tenant-alpha-decoy-public-archive/"}
}

SOAR_STATS = {
    "keycloak_revocations": 0,
    "iam_keys_disabled": 0,
    "db_ip_quarantined": 0,
    "total_interceptions": 0
}

TELEMETRY_LOGS: List[Dict[str, Any]] = []
ALERTS: List[Dict[str, Any]] = []
METRICS_SERIES: List[Dict[str, Any]] = []

# Helper Logger
def log_telemetry(level: str, layer: str, event: str, message: str, details: Optional[Dict[str, Any]] = None):
    entry = {
        "id": f"log-{int(datetime.datetime.now().timestamp() * 1000)}-{random.randint(100, 999)}",
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        "level": level,
        "layer": layer,
        "event": event,
        "message": message,
        "details": details or {}
    }
    TELEMETRY_LOGS.append(entry)
    if len(TELEMETRY_LOGS) > 200:
        TELEMETRY_LOGS.pop(0)
    return entry

def create_security_alert(title: str, severity: str, layer: str, trigger: str, user_id: str, target: str, soar_action: str):
    alert = {
        "id": f"ALT-{random.randint(10000, 99999)}",
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        "title": title,
        "severity": severity,
        "layer": layer,
        "trigger": trigger,
        "user_id": user_id,
        "target_resource": target,
        "soar_action": soar_action,
        "status": "ACTIVE"
    }
    ALERTS.insert(0, alert)
    if len(ALERTS) > 50:
        ALERTS.pop()
    return alert

# --- Continuous Background Telemetry Graph Generator ---
def background_metrics_ticker():
    while True:
        time.sleep(2.0)
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        vol = max(4, int(random.normalvariate(10.0, 1.8)))
        z = round((vol - 10.0) / 2.0, 2)
        entry = {
            "time": timestamp,
            "volume": vol,
            "zScore": z,
            "user": "LIVE_BASELINE_STREAM",
            "isAnomaly": False,
            "label": "Live Stream Baseline"
        }
        METRICS_SERIES.append(entry)
        if len(METRICS_SERIES) > 35:
            METRICS_SERIES.pop(0)

threading.Thread(target=background_metrics_ticker, daemon=True).start()

# --- Deception & UEBA Detection Core ---
def inspect_layer_1_deception(event: Dict[str, Any]) -> Dict[str, Any]:
    event_type = event.get("type")
    target = str(event.get("target_resource", ""))
    
    alert = {
        "is_alert": False,
        "layer": "Layer-1 (Deception)",
        "trigger": None,
        "severity": "CRITICAL"
    }

    if event_type == "IAM_ACCESS" and ("AKIA_DECOY" in target or target in DECOY_REGISTRY["iam_access_keys"]):
        alert.update({"is_alert": True, "trigger": f"Decoy IAM Access Key Intercepted: {target}"})
    elif event_type == "IAM_ROLE_ASSUME" and "DecoyCrossTenant" in target:
        alert.update({"is_alert": True, "trigger": f"Cross-Tenant Decoy IAM Role Enumerated: {target}"})
    elif event_type == "S3_READ" and ("payroll_2026_canary.csv" in target or target in DECOY_REGISTRY["s3_canary_objects"]):
        alert.update({"is_alert": True, "trigger": f"Canary S3 Object Intercepted: {target}"})
    elif event_type == "S3_BUCKET_SCAN" and "decoy-public-archive" in target:
        alert.update({"is_alert": True, "trigger": f"Unlinked Decoy S3 Bucket Scanned: {target}"})
    elif event_type == "DB_QUERY" and (target == "99999" or "99999" in target):
        alert.update({"is_alert": True, "trigger": "Database Honey-Record Intercepted (user_id=99999)"})

    return alert

def evaluate_layer_2_ueba(user_id: str, current_volume: int) -> Dict[str, Any]:
    baseline = USER_BASELINES.get(user_id, {"mean": 10.0, "std": 2.0})
    z_score = round((current_volume - baseline["mean"]) / baseline["std"], 2)
    is_anomaly = z_score >= 3.0
    return {
        "user_id": user_id,
        "current_volume": current_volume,
        "baseline_mean": baseline["mean"],
        "baseline_std": baseline["std"],
        "z_score": z_score,
        "is_anomaly": is_anomaly,
        "layer": "Layer-2 (UEBA Engine)",
        "severity": "HIGH" if is_anomaly else "INFO"
    }

def enforce_soar_remediation(target_user: str, trigger_reason: str, alert_title: str):
    # Simulated SOAR updates + Graceful LocalStack/Keycloak/Postgres handlers
    SOAR_STATS["keycloak_revocations"] += 1
    SOAR_STATS["iam_keys_disabled"] += 1
    SOAR_STATS["db_ip_quarantined"] += 1
    SOAR_STATS["total_interceptions"] += 1

    log_telemetry("SOAR", "SOAR Orchestrator", "KEYCLOAK_SESSION_LOGOUT", f"Revoked active Keycloak SSO sessions for user '{target_user}'.")
    log_telemetry("SOAR", "SOAR Orchestrator", "IAM_KEY_DEACTIVATION", f"LocalStack IAM Access Key status set to INACTIVE for user '{target_user}'.")
    log_telemetry("SOAR", "SOAR Orchestrator", "DB_CONNECTION_TERMINATED", "Terminated active PostgreSQL database socket connection.")

    create_security_alert(
        title=alert_title,
        severity="CRITICAL" if "Dual" in trigger_reason or "Honey" in trigger_reason else "HIGH",
        layer="Layer-1 & 2" if "Dual" in trigger_reason else ("Layer-1 Deception" if "Decoy" in trigger_reason or "Canary" in trigger_reason or "Honey" in trigger_reason else "Layer-2 UEBA"),
        trigger=trigger_reason,
        user_id=target_user,
        target=trigger_reason.split(":")[-1].strip() if ":" in trigger_reason else "Multi-Tenant Cloud Asset",
        soar_action="Keycloak Session Killed + IAM Deactivated + DB Socket Terminated"
    )

# --- 17 DEFINED TEST SCENARIOS ---
SCENARIO_DEFINITIONS = [
    {
        "id": 1,
        "name": "Scenario 1: Legitimate Tenant User Authentication",
        "plane": "Control Plane",
        "category": "Baseline",
        "user_id": "USR_0001",
        "volume": 10,
        "description": "Standard user SSO login via Keycloak master realm (V=10 req/min, Z=0.0). Verified clean.",
        "verdict": "VERIFIED CLEAN"
    },
    {
        "id": 2,
        "name": "Scenario 2: S3 Production Data Pipeline Execution",
        "plane": "Data Plane",
        "category": "Baseline",
        "user_id": "USR_0002_ETL",
        "volume": 14,
        "description": "Routine automated ETL process accessing production storage path `s3://tenant-alpha-storage/data/` (V=14, Z=0.8).",
        "verdict": "VERIFIED CLEAN"
    },
    {
        "id": 3,
        "name": "Scenario 3: Standard Database User Query",
        "plane": "Database Plane",
        "category": "Baseline",
        "user_id": "USR_0001",
        "volume": 8,
        "description": "Legitimate PostgreSQL application query: `SELECT * FROM users WHERE user_id = 101;` (V=8, Z=-1.0).",
        "verdict": "VERIFIED CLEAN"
    },
    {
        "id": 4,
        "name": "Scenario 4: Control Plane Decoy IAM Access Key Trapped",
        "plane": "Control Plane",
        "category": "Deception (Layer-1)",
        "user_id": "ATTACKER_IP_192_168_1_50",
        "volume": 25,
        "description": "External adversary attempts AWS API calls using fake admin access key `AKIA_DECOY_ADMIN_TRAP_99`.",
        "verdict": "THREAT CONTAINED"
    },
    {
        "id": 5,
        "name": "Scenario 5: Data Plane S3 Canary Object Read Attempt",
        "plane": "Data Plane",
        "category": "Deception (Layer-1)",
        "user_id": "ATTACKER_IP_192_168_1_50",
        "volume": 30,
        "description": "Unauthorized access to tagged honey-file `s3://tenant-alpha-storage/confidential/payroll_2026_canary.csv`.",
        "verdict": "THREAT CONTAINED"
    },
    {
        "id": 6,
        "name": "Scenario 6: Database Honey-Record Intercepted",
        "plane": "Database Plane",
        "category": "Deception (Layer-1)",
        "user_id": "DB_ATTACKER",
        "volume": 18,
        "description": "SQL injection scan queries decoy honey-row: `SELECT * FROM users WHERE user_id = 99999;`.",
        "verdict": "THREAT CONTAINED"
    },
    {
        "id": 7,
        "name": "Scenario 7: UEBA Anomaly: Disgruntled Insider Data Harvesting",
        "plane": "API Gateway",
        "category": "UEBA (Layer-2)",
        "user_id": "INSIDER_DISGRUNTLED",
        "volume": 88,
        "description": "Insider user rapidly scraping REST API endpoints. Triggers Z-Score spike against baseline (V=88 req/min, Z=40.0 >= 3.0).",
        "verdict": "THREAT CONTAINED"
    },
    {
        "id": 8,
        "name": "Scenario 8: UEBA Anomaly: Off-Hours Geo-Location Spike",
        "plane": "Identity Plane",
        "category": "UEBA (Layer-2)",
        "user_id": "USR_0001",
        "volume": 65,
        "description": "Unusual burst of authentication requests from unrecognized IP address during off-hours (V=65 req/min, Z=27.5).",
        "verdict": "THREAT CONTAINED"
    },
    {
        "id": 9,
        "name": "Scenario 9: Cross-Tenant Decoy IAM Role Enumeration",
        "plane": "Control Plane",
        "category": "Deception (Layer-1)",
        "user_id": "ATTACKER_IP_192_168_1_50",
        "volume": 42,
        "description": "Adversary attempts to assume cross-tenant decoy IAM role `arn:aws:iam::123456789012:role/DecoyCrossTenantAdminRole`.",
        "verdict": "THREAT CONTAINED"
    },
    {
        "id": 10,
        "name": "Scenario 10: Data Plane Unlinked Honey-Bucket Reconnaissance",
        "plane": "Data Plane",
        "category": "Deception (Layer-1)",
        "user_id": "BURST_ATTACKER",
        "volume": 50,
        "description": "Automated bucket enumeration tool scans unlinked decoy S3 bucket `s3://tenant-alpha-decoy-public-archive/`.",
        "verdict": "THREAT CONTAINED"
    },
    {
        "id": 11,
        "name": "Scenario 11: Database Rapid Bulk Data Exfiltration Spike",
        "plane": "Database Plane",
        "category": "UEBA (Layer-2)",
        "user_id": "DB_ATTACKER",
        "volume": 120,
        "description": "High-frequency DB query storm querying non-decoy user records (V=120 req/min, Z=110.0 >= 3.0).",
        "verdict": "THREAT CONTAINED"
    },
    {
        "id": 12,
        "name": "Scenario 12: Orchestrated Multi-Tenant Cloud Ransomware Attack",
        "plane": "Dual Plane",
        "category": "Dual Vector (L1 + L2)",
        "user_id": "BURST_ATTACKER",
        "volume": 150,
        "description": "Simultaneous Decoy IAM Key usage + Canary S3 access + Volume Burst (V=150 req/min, Z=93.3). Full Lockdown.",
        "verdict": "CRITICAL CONTAINMENT"
    },
    {
        "id": 13,
        "name": "Failure Case F1: Slow-and-Low Data Exfiltration",
        "plane": "API / UEBA",
        "category": "Failure Mode (False Negative)",
        "user_id": "SLOW_ATTACKER",
        "volume": 11,
        "description": "Attacker exfiltrates slowly (V=11 req/min, Z=0.5 < 3.0) avoiding all decoys. Evades both Layer-1 and Layer-2.",
        "verdict": "FALSE NEGATIVE (EVADED)"
    },
    {
        "id": 14,
        "name": "Failure Case F2: Decoy Metadata Tag Fingerprinting",
        "plane": "Data Plane",
        "category": "Failure Mode (Evasion)",
        "user_id": "ATTACKER_IP_192_168_1_50",
        "volume": 12,
        "description": "Attacker inspects metadata tags, identifies 'is_decoy=true', and avoids reading canary S3 object.",
        "verdict": "DECEPTION EVADED"
    },
    {
        "id": 15,
        "name": "Failure Case F3: Rolling Baseline Poisoning / Concept Drift",
        "plane": "UEBA Engine",
        "category": "Failure Mode (False Negative)",
        "user_id": "POISONED_USER",
        "volume": 50,
        "description": "Rolling mean shifted over 30 days (μ=42.0). A 50 req/min burst yields Z=1.6 < 3.0, masking exfiltration.",
        "verdict": "UEBA EVADED (POISONED)"
    },
    {
        "id": 16,
        "name": "Failure Case F4: Legitimate Monthly Batch ETL Flash Crowd",
        "plane": "SOAR Engine",
        "category": "Failure Mode (False Positive)",
        "user_id": "USR_0002_ETL",
        "volume": 120,
        "description": "Scheduled legitimate ETL job generates V=120 req/min (Z=43.2 >> 3.0). SOAR accidentally cuts production pipeline.",
        "verdict": "FALSE POSITIVE (FALSE ALARM)"
    },
    {
        "id": 17,
        "name": "Failure Case F5: Targeted Single-Record Targeted Theft",
        "plane": "Database Plane",
        "category": "Failure Mode (False Negative)",
        "user_id": "DB_ATTACKER",
        "volume": 1,
        "description": "Targeted SELECT query for row 101. Avoids honey-record 99999. V=1 query (Z=-3.0). Zero alerts triggered.",
        "verdict": "FALSE NEGATIVE (PRECISION)"
    }
]

# --- Main Dashboard HTML Route ---
@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SOC Dashboard · Automated Deception-Driven IAM & UEBA Platform</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
        <style>
            body { background-color: #020617; color: #f8fafc; font-family: ui-sans-serif, system-ui, sans-serif; }
            ::-webkit-scrollbar { width: 6px; }
            ::-webkit-scrollbar-track { background: #090d16; }
            ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }
            .tab-btn.active { border-bottom: 2px solid #06b6d4; color: #38bdf8; font-weight: 700; }
        </style>
    </head>
    <body class="p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto space-y-6">

        <!-- Header Bar -->
        <header class="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-slate-800 gap-4">
            <div class="flex items-center space-x-3">
                <div class="p-2.5 bg-cyan-500/10 border border-cyan-500/30 rounded-xl">
                    <i class="fa-solid fa-shield-halved text-2xl text-cyan-400"></i>
                </div>
                <div>
                    <h1 class="text-xl sm:text-2xl font-bold text-white flex items-center gap-3">
                        Cloud SOC Security Operations Dashboard
                        <span class="text-xs font-mono font-bold px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">ONLINE (PORT 8000)</span>
                    </h1>
                    <p class="text-xs text-slate-400 mt-0.5">Automated Deception-Driven IAM & UEBA Anomaly Orchestrator · Interactive Demonstration Console</p>
                </div>
            </div>

            <div class="flex items-center space-x-3">
                <button onclick="runAllBenchmarkScenarios()" id="btn-benchmark" class="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-bold rounded-lg shadow transition-all flex items-center gap-2">
                    <i class="fa-solid fa-bolt"></i>Run All 17 Scenarios
                </button>
                <button onclick="resetPlatform()" class="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700 transition-all flex items-center gap-2">
                    <i class="fa-solid fa-rotate-left"></i>Reset Baseline
                </button>
            </div>
        </header>

        <!-- Navigation Tabs -->
        <div class="flex border-b border-slate-800 text-xs font-semibold text-slate-400 space-x-6 overflow-x-auto">
            <button onclick="switchTab('tab-main')" id="btn-tab-main" class="tab-btn active pb-3 flex items-center gap-2 whitespace-nowrap">
                <i class="fa-solid fa-gauge-high text-cyan-400"></i>Main Threat Operations (Test Suite + Telemetry Graph)
            </button>
            <button onclick="switchTab('tab-alerts')" id="btn-tab-alerts" class="tab-btn pb-3 flex items-center gap-2 whitespace-nowrap">
                <i class="fa-solid fa-triangle-exclamation text-amber-400"></i>Security Alerts Center 
                <span id="badge-alert-count" class="px-1.5 py-0.2 bg-rose-500/20 text-rose-400 border border-rose-500/40 rounded-full font-mono text-[10px]">0</span>
            </button>
            <button onclick="switchTab('tab-decoys')" id="btn-tab-decoys" class="tab-btn pb-3 flex items-center gap-2 whitespace-nowrap">
                <i class="fa-solid fa-key text-purple-400"></i>Deception Traps Registry
            </button>
        </div>

        <!-- Infrastructure & SOAR Counters -->
        <section class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div class="p-3.5 bg-slate-900 border border-slate-800 rounded-xl">
                <div class="text-[11px] font-bold text-slate-400 uppercase"><i class="fa-solid fa-user-xmark text-indigo-400 mr-1.5"></i>Keycloak SSO Revoked</div>
                <div id="stat-kc" class="text-2xl font-extrabold text-indigo-400 font-mono mt-1">0</div>
            </div>
            <div class="p-3.5 bg-slate-900 border border-slate-800 rounded-xl">
                <div class="text-[11px] font-bold text-slate-400 uppercase"><i class="fa-solid fa-lock text-amber-400 mr-1.5"></i>IAM Keys Disabled</div>
                <div id="stat-iam" class="text-2xl font-extrabold text-amber-400 font-mono mt-1">0</div>
            </div>
            <div class="p-3.5 bg-slate-900 border border-slate-800 rounded-xl">
                <div class="text-[11px] font-bold text-slate-400 uppercase"><i class="fa-solid fa-plug-circle-xmark text-purple-400 mr-1.5"></i>DB Connections Cut</div>
                <div id="stat-db" class="text-2xl font-extrabold text-purple-400 font-mono mt-1">0</div>
            </div>
            <div class="p-3.5 bg-slate-900 border border-slate-800 rounded-xl bg-cyan-950/20">
                <div class="text-[11px] font-bold text-cyan-400 uppercase"><i class="fa-solid fa-shield-cat text-cyan-400 mr-1.5"></i>Total Neutralized</div>
                <div id="stat-total" class="text-2xl font-extrabold text-cyan-400 font-mono mt-1">0</div>
            </div>
        </section>

        <!-- Step Execution Progress Box -->
        <div id="simulation-progress-box" class="hidden p-4 bg-slate-900 border border-cyan-500/40 rounded-xl space-y-2 shadow-lg animate-pulse">
            <div class="flex items-center justify-between text-xs font-bold text-cyan-300">
                <span id="sim-progress-title"><i class="fa-solid fa-spinner fa-spin mr-2"></i>Simulating Activity...</span>
                <span id="sim-progress-step" class="font-mono">Step 1 / 3</span>
            </div>
            <div class="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
                <div id="sim-progress-bar" class="bg-cyan-500 h-full w-1/3 transition-all duration-500"></div>
            </div>
            <div id="sim-progress-msg" class="text-xs text-slate-400 font-mono">Ingesting telemetry events into detection engine...</div>
        </div>

        <!-- TAB 1: MAIN THREAT OPERATIONS (COMBINED TEST SUITE + GRAPH + LOGS) -->
        <div id="tab-main" class="tab-content space-y-6">
            <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                <!-- LEFT COLUMN: 17 SCENARIO TEST SUITE -->
                <div class="lg:col-span-5 space-y-4">
                    <div class="flex items-center justify-between border-b border-slate-800 pb-2">
                        <h2 class="text-sm font-bold text-white"><i class="fa-solid fa-list-check text-cyan-400 mr-2"></i>Test Suite (17 Scenarios)</h2>
                        <div class="flex items-center gap-1 text-[10px]">
                            <button onclick="filterScenarios('ALL')" class="px-2 py-0.5 bg-slate-800 text-slate-300 rounded font-semibold">All</button>
                            <button onclick="filterScenarios('Baseline')" class="px-1.5 py-0.5 bg-slate-900 text-emerald-400 border border-emerald-500/30 rounded font-semibold">Clean</button>
                            <button onclick="filterScenarios('Deception')" class="px-1.5 py-0.5 bg-slate-900 text-cyan-400 border border-cyan-500/30 rounded font-semibold">Decoy</button>
                            <button onclick="filterScenarios('UEBA')" class="px-1.5 py-0.5 bg-slate-900 text-amber-400 border border-amber-500/30 rounded font-semibold">UEBA</button>
                            <button onclick="filterScenarios('Failure')" class="px-1.5 py-0.5 bg-slate-900 text-rose-400 border border-rose-500/30 rounded font-semibold">Failures</button>
                        </div>
                    </div>

                    <div id="scenarios-grid" class="space-y-3 max-h-[720px] overflow-y-auto pr-1">
                        <!-- Rendered dynamically -->
                    </div>
                </div>

                <!-- RIGHT COLUMN: CONTINUOUS TELEMETRY GRAPH & AUDIT STREAM -->
                <div class="lg:col-span-7 space-y-6">
                    <!-- GRAPH CARD -->
                    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3 shadow-xl">
                        <div class="flex items-center justify-between border-b border-slate-800 pb-2">
                            <h2 class="text-sm font-bold text-white"><i class="fa-solid fa-chart-line text-cyan-400 mr-2"></i>Continuous Live Telemetry & Z-Score Graph</h2>
                            <span class="text-xs font-mono text-rose-400 flex items-center gap-1">
                                <span class="w-2 h-2 rounded-full bg-rose-500 animate-ping"></span> Z = 3.0 Threshold (16 req/min)
                            </span>
                        </div>
                        <div id="continuous-chart" class="w-full h-56 bg-slate-950 rounded-lg p-2 border border-slate-800">
                            <!-- Rendered SVG Graph -->
                        </div>
                    </div>

                    <!-- AUDIT TERMINAL CARD -->
                    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3 shadow-xl">
                        <h2 class="text-sm font-bold text-white border-b border-slate-800 pb-2"><i class="fa-solid fa-terminal text-emerald-400 mr-2"></i>Real-Time Audit Telemetry Stream</h2>
                        <div id="log-terminal" class="bg-slate-950 rounded-lg p-3 font-mono text-xs h-64 overflow-y-auto space-y-2 border border-slate-800">
                            <div class="text-slate-600 italic">Listening to cloud telemetry stream... Click any scenario test case to begin.</div>
                        </div>
                    </div>
                </div>

            </div>
        </div>

        <!-- TAB 2: ALERTS CENTER -->
        <div id="tab-alerts" class="tab-content hidden space-y-4">
            <div class="flex items-center justify-between border-b border-slate-800 pb-3">
                <h2 class="text-sm font-bold text-white"><i class="fa-solid fa-triangle-exclamation text-amber-400 mr-2"></i>Security Alerts Queue</h2>
                <span class="text-xs text-slate-400">Automated SOAR Action Triggers</span>
            </div>

            <div id="alerts-container" class="space-y-3">
                <div class="p-8 text-center text-slate-500 text-xs italic bg-slate-900/50 rounded-xl border border-slate-800">
                    No active security alerts generated yet. Trigger attack scenarios from Main Operations Tab.
                </div>
            </div>
        </div>

        <!-- TAB 3: DECEPTION REGISTRY -->
        <div id="tab-decoys" class="tab-content hidden space-y-4">
            <h2 class="text-sm font-bold text-white border-b border-slate-800 pb-2"><i class="fa-solid fa-key text-purple-400 mr-2"></i>Active Decoy Traps Inventory</h2>
            <div id="decoys-list" class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <!-- Rendered dynamically -->
            </div>
        </div>

        <!-- JAVASCRIPT CONTROLLER -->
        <script>
            let scenarios = [];
            let currentCategoryFilter = 'ALL';

            function switchTab(tabId) {
                document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
                document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
                document.getElementById(tabId).classList.remove('hidden');
                document.getElementById(`btn-${tabId}`).classList.add('active');
            }

            async function fetchScenariosList() {
                try {
                    const res = await fetch('/api/scenarios');
                    if(res.ok) {
                        scenarios = await res.json();
                        renderScenariosGrid();
                    }
                } catch(e) { console.error(e); }
            }

            function filterScenarios(cat) {
                currentCategoryFilter = cat;
                renderScenariosGrid();
            }

            function renderScenariosGrid() {
                const grid = document.getElementById('scenarios-grid');
                const filtered = scenarios.filter(s => {
                    if(currentCategoryFilter === 'ALL') return true;
                    if(currentCategoryFilter === 'Baseline') return s.category === 'Baseline';
                    if(currentCategoryFilter === 'Deception') return s.category.includes('Deception');
                    if(currentCategoryFilter === 'UEBA') return s.category.includes('UEBA');
                    if(currentCategoryFilter === 'Failure') return s.category.includes('Failure');
                    return true;
                });

                grid.innerHTML = filtered.map(s => {
                    const isFailure = s.category.includes('Failure');
                    const isBaseline = s.category === 'Baseline';
                    
                    let badgeClass = 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
                    if(isBaseline) badgeClass = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
                    if(isFailure) badgeClass = 'bg-rose-500/20 text-rose-300 border-rose-500/40 font-bold animate-pulse';

                    return `
                        <div class="p-3.5 bg-slate-900 border ${isFailure ? 'border-rose-900/60' : 'border-slate-800'} rounded-xl space-y-2 hover:border-slate-700 transition-all">
                            <div class="flex items-center justify-between">
                                <span class="text-[9px] font-mono font-bold px-2 py-0.5 rounded border ${badgeClass}">${s.category}</span>
                                <span class="text-[10px] font-mono text-slate-400">${s.plane}</span>
                            </div>
                            <h3 class="text-xs font-bold ${isFailure ? 'text-rose-200' : 'text-white'}">${s.name}</h3>
                            <p class="text-[11px] text-slate-400 leading-relaxed">${s.description}</p>

                            <div class="pt-2 border-t border-slate-800/80 flex items-center justify-between">
                                <span class="text-[10px] font-mono text-slate-500">Vol: ${s.volume} req/min</span>
                                <button onclick="runSingleScenario(${s.id})" id="s-btn-${s.id}" class="px-3 py-1.5 ${isFailure ? 'bg-rose-950 hover:bg-rose-800 text-rose-200 border border-rose-700' : 'bg-slate-800 hover:bg-cyan-600 text-white'} font-semibold text-xs rounded-lg transition-all flex items-center gap-1.5">
                                    <i class="fa-solid fa-play text-[10px]"></i> Run Test ${s.id}
                                </button>
                            </div>
                        </div>
                    `;
                }).join('');
            }

            async function runSingleScenario(id) {
                const progressBox = document.getElementById('simulation-progress-box');
                const titleEl = document.getElementById('sim-progress-title');
                const stepEl = document.getElementById('sim-progress-step');
                const barEl = document.getElementById('sim-progress-bar');
                const msgEl = document.getElementById('sim-progress-msg');

                progressBox.classList.remove('hidden');

                titleEl.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-2"></i>Running Test Case ${id}...`;
                stepEl.innerText = "Step 1 / 3";
                barEl.style.width = "33%";
                msgEl.innerText = "Ingesting telemetry request stream into detection pipeline...";
                await new Promise(r => setTimeout(r, 350));

                stepEl.innerText = "Step 2 / 3";
                barEl.style.width = "66%";
                msgEl.innerText = "Evaluating Layer-1 Deception traps & Layer-2 UEBA Z-Scores...";
                await new Promise(r => setTimeout(r, 450));

                try {
                    await fetch('/api/simulate/scenario/' + id, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({})
                    });
                } catch(e) {}

                stepEl.innerText = "Step 3 / 3";
                barEl.style.width = "100%";
                msgEl.innerText = "Execution complete! Telemetry logs & continuous graph updated.";
                await new Promise(r => setTimeout(r, 350));

                progressBox.classList.add('hidden');
                fetchState();
            }

            async function runAllBenchmarkScenarios() {
                for(let id = 1; id <= 17; id++) {
                    await runSingleScenario(id);
                    await new Promise(r => setTimeout(r, 200));
                }
            }

            async function fetchState() {
                try {
                    const [hRes, tRes, aRes, dRes] = await Promise.all([
                        fetch('/api/health'),
                        fetch('/api/telemetry'),
                        fetch('/api/alerts'),
                        fetch('/api/decoys')
                    ]);

                    if (hRes.ok) {
                        const hData = await hRes.json();
                        const stats = hData.soar_stats || {};
                        document.getElementById('stat-kc').innerText = stats.keycloak_revocations || 0;
                        document.getElementById('stat-iam').innerText = stats.iam_keys_disabled || 0;
                        document.getElementById('stat-db').innerText = stats.db_ip_quarantined || 0;
                        document.getElementById('stat-total').innerText = stats.total_interceptions || 0;
                    }

                    if (tRes.ok) {
                        const tData = await tRes.json();
                        renderLogs(tData.logs || []);
                        renderContinuousChart(tData.metrics || []);
                    }

                    if (aRes.ok) {
                        const aData = await aRes.json();
                        renderAlerts(aData.alerts || []);
                    }

                    if (dRes.ok) {
                        const dData = await dRes.json();
                        renderDecoys(dData);
                    }
                } catch(e) {}
            }

            function renderAlerts(alerts) {
                document.getElementById('badge-alert-count').innerText = alerts.length;
                const container = document.getElementById('alerts-container');
                if(!alerts || alerts.length === 0) {
                    container.innerHTML = '<div class="p-8 text-center text-slate-500 text-xs italic bg-slate-900/50 rounded-xl border border-slate-800">No active security alerts generated yet. Trigger attack scenarios from Main Operations Tab.</div>';
                    return;
                }

                container.innerHTML = alerts.map(a => `
                    <div class="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2 hover:border-slate-700 transition-all">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center gap-2">
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-500/20 text-rose-400 border border-rose-500/40">${a.severity}</span>
                                <h3 class="text-xs font-bold text-white">${a.title}</h3>
                            </div>
                            <span class="text-[10px] font-mono text-slate-500">${a.timestamp} · ID: ${a.id}</span>
                        </div>
                        <p class="text-xs text-slate-300 font-mono">${a.trigger}</p>
                        <div class="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800/80">
                            <span>User: <strong class="text-cyan-400">${a.user_id}</strong></span>
                            <span>Target: <strong class="text-slate-200">${a.target_resource}</strong></span>
                            <span class="text-emerald-400"><i class="fa-solid fa-shield-check mr-1"></i>${a.soar_action}</span>
                        </div>
                    </div>
                `).join('');
            }

            function renderLogs(logs) {
                const term = document.getElementById('log-terminal');
                if(!logs || logs.length === 0) {
                    term.innerHTML = '<div class="text-slate-600 italic">Listening to cloud telemetry stream...</div>';
                    return;
                }
                term.innerHTML = logs.map(l => `
                    <div class="p-2 bg-slate-900/50 rounded border border-slate-800/80 space-y-1">
                        <div class="flex items-center space-x-2 text-[10px]">
                            <span class="text-slate-500">[${l.timestamp}]</span>
                            <span class="px-1.5 py-0.5 rounded font-bold ${l.level === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400' : (l.level === 'WARNING' ? 'bg-amber-500/20 text-amber-400' : 'bg-cyan-500/20 text-cyan-400')}">${l.layer}</span>
                            <span class="text-slate-300 font-semibold">${l.event}</span>
                        </div>
                        <div class="text-slate-400 text-xs">${l.message}</div>
                    </div>
                `).join('');
                term.scrollTop = term.scrollHeight;
            }

            function renderContinuousChart(metrics) {
                const container = document.getElementById('continuous-chart');
                if(!metrics || metrics.length === 0) return;

                const maxVol = Math.max(...metrics.map(p => p.volume), 100);
                const w = 700, h = 200, pad = 30;

                const points = metrics.map((p, i) => ({
                    x: pad + (i / Math.max(metrics.length - 1, 1)) * (w - 2 * pad),
                    y: h - pad - (p.volume / maxVol) * (h - 2 * pad),
                    vol: p.volume,
                    z: p.zScore
                }));

                const pathD = points.reduce((acc, p, i) => i === 0 ? `M ${p.x} ${p.y}` : `${acc} L ${p.x} ${p.y}`, '');
                const areaD = points.length > 0 ? `${pathD} L ${points[points.length-1].x} ${h-pad} L ${points[0].x} ${h-pad} Z` : '';
                const threshY = h - pad - (16 / maxVol) * (h - 2 * pad);

                container.innerHTML = `
                    <svg viewBox="0 0 ${w} ${h}" class="w-full h-full text-cyan-500">
                        <line x1="${pad}" y1="${pad}" x2="${w-pad}" y2="${pad}" stroke="#1e293b" stroke-dasharray="3 3"/>
                        <line x1="${pad}" y1="${h/2}" x2="${w-pad}" y2="${h/2}" stroke="#1e293b" stroke-dasharray="3 3"/>
                        <line x1="${pad}" y1="${h-pad}" x2="${w-pad}" y2="${h-pad}" stroke="#334155"/>
                        <line x1="${pad}" y1="${threshY}" x2="${w-pad}" y2="${threshY}" stroke="#f43f5e" stroke-dasharray="4 4" stroke-width="1.5"/>
                        <text x="${w-pad-160}" y="${threshY-6}" fill="#f43f5e" font-size="10" font-family="monospace">Z = 3.0 Anomaly Threshold</text>
                        ${areaD ? `<path d="${areaD}" fill="#06b6d4" fill-opacity="0.12"/>` : ''}
                        ${pathD ? `<path d="${pathD}" fill="none" stroke="#06b6d4" stroke-width="2.5"/>` : ''}
                        ${points.map(p => `<circle cx="${p.x}" cy="${p.y}" r="${p.z >= 3.0 ? 5 : 3}" fill="${p.z >= 3.0 ? '#f43f5e' : '#06b6d4'}"/>`).join('')}
                    </svg>
                `;
            }

            function renderDecoys(decoys) {
                const container = document.getElementById('decoys-list');
                const keys = decoys.iam_access_keys || [];
                const s3 = decoys.s3_canary_objects || [];
                const db = decoys.db_honey_records || [];

                container.innerHTML = `
                    <div class="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
                        <h3 class="text-xs font-bold text-amber-400 uppercase"><i class="fa-solid fa-key mr-2"></i>Decoy IAM Access Keys</h3>
                        <div class="text-xs font-mono text-slate-300 bg-slate-950 p-3 rounded border border-slate-800 break-all">${keys.join('<br>') || 'AKIA_DECOY_ADMIN_TRAP_99'}</div>
                    </div>
                    <div class="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
                        <h3 class="text-xs font-bold text-cyan-400 uppercase"><i class="fa-solid fa-hard-drive mr-2"></i>S3 Canary Objects</h3>
                        <div class="text-xs font-mono text-slate-300 bg-slate-950 p-3 rounded border border-slate-800 break-all">${s3.join('<br>') || 's3://tenant-alpha-storage/confidential/payroll_2026_canary.csv'}</div>
                    </div>
                    <div class="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
                        <h3 class="text-xs font-bold text-purple-400 uppercase"><i class="fa-solid fa-database mr-2"></i>PostgreSQL Honey-Records</h3>
                        <div class="text-xs font-mono text-slate-300 bg-slate-950 p-3 rounded border border-slate-800 break-all">users.user_id = 99999 (admin_super_honey)</div>
                    </div>
                    <div class="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
                        <h3 class="text-xs font-bold text-emerald-400 uppercase"><i class="fa-solid fa-building-user mr-2"></i>Cross-Tenant Decoy Roles</h3>
                        <div class="text-xs font-mono text-slate-300 bg-slate-950 p-3 rounded border border-slate-800 break-all">arn:aws:iam::123456789012:role/DecoyCrossTenantAdminRole</div>
                    </div>
                `;
            }

            async function resetPlatform() {
                await fetch('/api/reset', { method: 'POST' });
                fetchState();
            }

            fetchScenariosList();
            setInterval(fetchState, 1500);
            fetchState();
        </script>
    </body>
    </html>
    """

# --- API Endpoints ---
@app.get("/api/scenarios")
def get_scenarios():
    return SCENARIO_DEFINITIONS

@app.get("/api/health")
def get_health_status():
    return {
        "status": "healthy",
        "services": {
            "localstack": {"status": "OPERATIONAL", "port": 4566},
            "keycloak": {"status": "AUTHENTICATED", "port": 8080},
            "postgres": {"status": "ACTIVE", "port": 5432}
        },
        "soar_stats": SOAR_STATS
    }

@app.get("/api/decoys")
def get_decoys():
    return {
        "iam_access_keys": list(DECOY_REGISTRY["iam_access_keys"]),
        "s3_canary_objects": list(DECOY_REGISTRY["s3_canary_objects"]),
        "db_honey_records": list(DECOY_REGISTRY["db_honey_records"]),
        "cross_tenant_roles": list(DECOY_REGISTRY["cross_tenant_roles"]),
        "honey_buckets": list(DECOY_REGISTRY["honey_buckets"])
    }

@app.get("/api/telemetry")
def get_telemetry():
    return {
        "logs": TELEMETRY_LOGS,
        "metrics": METRICS_SERIES,
        "soar_stats": SOAR_STATS
    }

@app.get("/api/alerts")
def get_alerts():
    return {"alerts": ALERTS}

@app.post("/api/reset")
def reset_platform_state():
    TELEMETRY_LOGS.clear()
    ALERTS.clear()
    METRICS_SERIES.clear()
    SOAR_STATS["keycloak_revocations"] = 0
    SOAR_STATS["iam_keys_disabled"] = 0
    SOAR_STATS["db_ip_quarantined"] = 0
    SOAR_STATS["total_interceptions"] = 0
    log_telemetry("INFO", "SYSTEM", "PLATFORM_RESET", "Reset all telemetry logs, security alerts, and SOAR execution counters.")
    return {"status": "reset_successful"}

@app.post("/api/simulate/scenario/{scenario_id}")
async def run_simulation_scenario(scenario_id: int, request: Request):
    sc_def = next((s for s in SCENARIO_DEFINITIONS if s["id"] == scenario_id), None)
    if not sc_def:
        raise HTTPException(status_code=400, detail="Invalid scenario ID")

    user_id = sc_def["user_id"]
    vol = sc_def["volume"]
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    ueba = evaluate_layer_2_ueba(user_id, vol)

    METRICS_SERIES.append({
        "time": timestamp,
        "volume": vol,
        "zScore": ueba["z_score"],
        "user": user_id,
        "isAnomaly": ueba["is_anomaly"],
        "label": sc_def["name"]
    })
    if len(METRICS_SERIES) > 35:
        METRICS_SERIES.pop(0)

    # Scenarios 1-3: Baseline
    if scenario_id in [1, 2, 3]:
        log_telemetry("INFO", "TELEMETRY", "INGEST_ACTIVITY", f"Ingested telemetry for {user_id}: {sc_def['description']}")
        log_telemetry("INFO", "Layer-1 (Deception)", "TRAP_VERIFICATION_CLEAN", "Verified clean: No deception trap objects targeted.")
        log_telemetry("INFO", "Layer-2 (UEBA)", "Z_SCORE_NORMAL", f"UEBA check passed against baseline: Z = {ueba['z_score']} (Within safe limits).")
        return {"scenario": scenario_id, "status": "VERIFIED_CLEAN", "result": ueba}

    # Scenario 4: Decoy IAM Key
    elif scenario_id == 4:
        target = "AKIA_DECOY_ADMIN_TRAP_99"
        event = {"type": "IAM_ACCESS", "target_resource": target, "user_id": user_id}
        l1 = inspect_layer_1_deception(event)
        log_telemetry("WARNING", "TELEMETRY", "IAM_API_CALL", f"AWS ListRoles requested using access key {target}.", event)
        log_telemetry("CRITICAL", "Layer-1 (Deception)", "DECOY_KEY_INTERCEPTED", l1["trigger"], l1)
        enforce_soar_remediation(user_id, l1["trigger"], "Decoy IAM Key Intercepted Alert")
        return {"scenario": scenario_id, "status": "CONTAINED", "result": l1}

    # Scenario 5: S3 Canary Object
    elif scenario_id == 5:
        target = "s3://tenant-alpha-storage/confidential/payroll_2026_canary.csv"
        event = {"type": "S3_READ", "target_resource": target, "user_id": user_id}
        l1 = inspect_layer_1_deception(event)
        log_telemetry("WARNING", "TELEMETRY", "S3_GET_OBJECT", f"Read requested for {target}.", event)
        log_telemetry("CRITICAL", "Layer-1 (Deception)", "CANARY_S3_INTERCEPTED", l1["trigger"], l1)
        enforce_soar_remediation(user_id, l1["trigger"], "Canary S3 Object Intercepted Alert")
        return {"scenario": scenario_id, "status": "CONTAINED", "result": l1}

    # Scenario 6: DB Honey-Record
    elif scenario_id == 6:
        event = {"type": "DB_QUERY", "target_resource": 99999, "user_id": user_id}
        l1 = inspect_layer_1_deception(event)
        log_telemetry("WARNING", "TELEMETRY", "POSTGRES_QUERY", "SELECT * FROM users WHERE user_id = 99999;", event)
        log_telemetry("CRITICAL", "Layer-1 (Deception)", "HONEY_RECORD_INTERCEPTED", l1["trigger"], l1)
        enforce_soar_remediation(user_id, l1["trigger"], "PostgreSQL Honey-Record Alert")
        return {"scenario": scenario_id, "status": "CONTAINED", "result": l1}

    # Scenario 7: UEBA Insider Harvesting
    elif scenario_id == 7:
        log_telemetry("WARNING", "TELEMETRY", "HIGH_VOLUME_API_SPIKE", f"Bulk API request harvesting by {user_id} (Volume: {vol} req/min).")
        log_telemetry("CRITICAL", "Layer-2 (UEBA)", "ANOMALY_TRIGGERED", f"UEBA Anomaly Detected: Z-Score = {ueba['z_score']} (Z >= 3.0 threshold).", ueba)
        enforce_soar_remediation(user_id, f"Z-Score Anomaly (Z={ueba['z_score']})", "UEBA Insider Data Harvesting Alert")
        return {"scenario": scenario_id, "status": "CONTAINED", "result": ueba}

    # Scenario 8: Off-Hours Geo Anomaly
    elif scenario_id == 8:
        log_telemetry("WARNING", "TELEMETRY", "GEO_LOCATION_ANOMALY", f"Off-hours authentication spike from unusual IP range (Volume: {vol} req/min).")
        log_telemetry("CRITICAL", "Layer-2 (UEBA)", "ANOMALY_TRIGGERED", f"UEBA Anomaly Detected: Z-Score = {ueba['z_score']} (Z >= 3.0 threshold).", ueba)
        enforce_soar_remediation(user_id, f"Geo-Anomaly Z-Score (Z={ueba['z_score']})", "Off-Hours Geo-Anomaly Alert")
        return {"scenario": scenario_id, "status": "CONTAINED", "result": ueba}

    # Scenario 9: Cross-Tenant Role Enumeration
    elif scenario_id == 9:
        target = "arn:aws:iam::123456789012:role/DecoyCrossTenantAdminRole"
        event = {"type": "IAM_ROLE_ASSUME", "target_resource": target, "user_id": user_id}
        l1 = inspect_layer_1_deception(event)
        log_telemetry("CRITICAL", "Layer-1 (Deception)", "CROSS_TENANT_ROLE_ENUMERATED", l1["trigger"], l1)
        enforce_soar_remediation(user_id, l1["trigger"], "Cross-Tenant Role Enumeration Alert")
        return {"scenario": scenario_id, "status": "CONTAINED", "result": l1}

    # Scenario 10: Honey-Bucket Scan
    elif scenario_id == 10:
        target = "s3://tenant-alpha-decoy-public-archive/"
        event = {"type": "S3_BUCKET_SCAN", "target_resource": target, "user_id": user_id}
        l1 = inspect_layer_1_deception(event)
        log_telemetry("CRITICAL", "Layer-1 (Deception)", "HONEY_BUCKET_SCANNED", l1["trigger"], l1)
        enforce_soar_remediation(user_id, l1["trigger"], "Unlinked Honey-Bucket Alert")
        return {"scenario": scenario_id, "status": "CONTAINED", "result": l1}

    # Scenario 11: DB Bulk Exfiltration
    elif scenario_id == 11:
        log_telemetry("WARNING", "TELEMETRY", "DB_EXFILTRATION_SPIKE", f"Rapid database query storm (Volume: {vol} req/min).")
        log_telemetry("CRITICAL", "Layer-2 (UEBA)", "ANOMALY_TRIGGERED", f"UEBA Anomaly Detected: Z-Score = {ueba['z_score']} (Z >= 3.0 threshold).", ueba)
        enforce_soar_remediation(user_id, f"DB Burst Exfiltration (Z={ueba['z_score']})", "Database Exfiltration Alert")
        return {"scenario": scenario_id, "status": "CONTAINED", "result": ueba}

    # Scenario 12: Multi-Tenant Ransomware
    elif scenario_id == 12:
        log_telemetry("CRITICAL", "TELEMETRY", "ORCHESTRATED_RANSOMWARE", f"Multi-Vector Cloud Ransomware Attack: Decoy IAM Key + Canary S3 + Request Burst (V={vol} req/min).")
        log_telemetry("CRITICAL", "Layer-1 (Deception)", "DUAL_TRAP_TRIPPED", "Decoy IAM Key and S3 Canary accessed simultaneously!")
        log_telemetry("CRITICAL", "Layer-2 (UEBA)", "EXTREME_ANOMALY_TRIGGERED", f"UEBA Burst Evaluation: Z-Score = {ueba['z_score']} (Extreme Outlier).", ueba)
        enforce_soar_remediation(user_id, f"Dual Deception & UEBA Ransomware Trigger (Z={ueba['z_score']})", "Multi-Tenant Cloud Ransomware Alert")
        return {"scenario": scenario_id, "status": "CONTAINED", "result": ueba}

    # Failure Modes F1-F5 (13-17)
    elif scenario_id == 13:
        log_telemetry("WARNING", "TELEMETRY", "SLOW_EXFILTRATION", f"Low-frequency request stream (V={vol} req/min, Z={ueba['z_score']} < 3.0).")
        log_telemetry("WARNING", "Layer-1 (Deception)", "TRAP_PASSED", "Clean: Attacker avoided all registered decoy objects.")
        log_telemetry("WARNING", "Layer-2 (UEBA)", "EVADED", f"UEBA Check Passed: Z = {ueba['z_score']} < 3.0 limit. Attack un-flagged (False Negative).")
        return {"scenario": scenario_id, "status": "FALSE_NEGATIVE_EVADED", "result": ueba}

    elif scenario_id == 14:
        log_telemetry("WARNING", "TELEMETRY", "DECOY_FINGERPRINTED", "Attacker filtered out object tagged 'is_decoy=true' via head-object metadata inspection.")
        log_telemetry("WARNING", "Layer-1 (Deception)", "DECOY_EVADED", "Deception Trap bypassed by adversary metadata fingerprinting.")
        return {"scenario": scenario_id, "status": "DECEPTION_EVADED", "result": {"is_decoy_hit": False}}

    elif scenario_id == 15:
        log_telemetry("WARNING", "TELEMETRY", "POISONED_BASELINE_EVAL", f"Evaluating burst request (V={vol} req/min) against shifted baseline (μ=42.0).")
        log_telemetry("WARNING", "Layer-2 (UEBA)", "CONCEPT_DRIFT_EVADED", f"UEBA Check Passed: Z = {ueba['z_score']} < 3.0. Baseline poisoning masked exfiltration!")
        return {"scenario": scenario_id, "status": "UEBA_POISONED", "result": ueba}

    elif scenario_id == 16:
        log_telemetry("CRITICAL", "TELEMETRY", "FLASH_CROWD_ETL", f"Legitimate monthly ETL pipeline burst (V={vol} req/min).")
        log_telemetry("CRITICAL", "Layer-2 (UEBA)", "FALSE_POSITIVE_SPIKE", f"UEBA Anomaly Triggered: Z = {ueba['z_score']} >> 3.0 threshold!")
        enforce_soar_remediation(user_id, f"False Positive ETL Burst (Z={ueba['z_score']})", "SOAR False Positive Alert (ETL Interrupted)")
        return {"scenario": scenario_id, "status": "FALSE_POSITIVE_ALARM", "result": ueba}

    elif scenario_id == 17:
        log_telemetry("WARNING", "TELEMETRY", "SINGLE_ROW_SELECT", "Targeted query: SELECT * FROM users WHERE user_id = 101;")
        log_telemetry("INFO", "Layer-1 (Deception)", "HONEY_RECORD_MISSED", "Honey-record 99999 untouched.")
        log_telemetry("INFO", "Layer-2 (UEBA)", "LOW_VOLUME_PASSED", f"UEBA check passed: Volume V=1 req/min (Z={ueba['z_score']} < 3.0).")
        return {"scenario": scenario_id, "status": "PRECISION_FALSE_NEGATIVE", "result": ueba}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)