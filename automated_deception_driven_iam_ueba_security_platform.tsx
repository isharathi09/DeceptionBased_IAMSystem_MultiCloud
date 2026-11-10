import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Shield, ShieldAlert, ShieldCheck, Key, Database, HardDrive, Activity,
  Terminal, Zap, Play, RotateCcw, Cpu, Server, AlertTriangle, CheckCircle2,
  XCircle, Lock, Unlock, UserCheck, UserX, Layers, Radio, Eye, FileText,
  RefreshCw, Sliders, ChevronRight, Copy, Check, Filter, Search, Info, Link2, Wifi
} from 'lucide-react';
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ReferenceLine
} from 'recharts';

const API_BASE = "http://localhost:8000";

const INITIAL_CHART_DATA = [
  { time: '10:00:00', volume: 8, zScore: -1.0, user: 'USR_0001', isAnomaly: false },
  { time: '10:00:15', volume: 10, zScore: 0.0, user: 'USR_0001', isAnomaly: false },
  { time: '10:00:30', volume: 11, zScore: 0.5, user: 'USR_0001', isAnomaly: false },
  { time: '10:00:45', volume: 9, zScore: -0.5, user: 'USR_0001', isAnomaly: false },
  { time: '10:01:00', volume: 12, zScore: 1.0, user: 'USR_0001', isAnomaly: false },
  { time: '10:01:15', volume: 10, zScore: 0.0, user: 'USR_0001', isAnomaly: false },
  { time: '10:01:30', volume: 9, zScore: -0.5, user: 'USR_0001', isAnomaly: false },
  { time: '10:01:45', volume: 11, zScore: 0.5, user: 'USR_0001', isAnomaly: false },
];

const INITIAL_DECOYS = [
  {
    id: 'decoy-iam-1',
    type: 'IAM Access Key',
    plane: 'Control Plane',
    target: 'LocalStack IAM',
    identifier: 'AKIA_DECOY_ADMIN_TRAP_99',
    status: 'ARMED',
    hits: 0,
  },
  {
    id: 'decoy-s3-1',
    type: 'S3 Canary Object',
    plane: 'Data Plane',
    target: 'LocalStack S3',
    identifier: 's3://tenant-alpha-storage/confidential/payroll_2026_canary.csv',
    status: 'ARMED',
    hits: 0,
  },
  {
    id: 'decoy-db-1',
    type: 'Database Honey-Record',
    plane: 'Database Plane',
    target: 'PostgreSQL app_db',
    identifier: 'users.user_id = 99999',
    status: 'ARMED',
    hits: 0,
  }
];

export default function App() {
  const [backendOnline, setBackendOnline] = useState(false);
  const [chartData, setChartData] = useState(INITIAL_CHART_DATA);
  const [decoys, setDecoys] = useState(INITIAL_DECOYS);
  const [logs, setLogs] = useState([]);
  const [soarStats, setSoarStats] = useState({
    keycloakRevocations: 0,
    iamKeysDisabled: 0,
    dbIpQuarantined: 0,
    totalInterceptions: 0
  });
  const [isSimulating, setIsSimulating] = useState(false);
  const [activeScenario, setActiveScenario] = useState(null);
  const [logFilter, setLogFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedLog, setSelectedLog] = useState(null);
  const [copied, setCopied] = useState(false);

  const terminalEndRef = useRef(null);

  // Poll FastAPI backend health and real telemetry
  useEffect(() => {
    const checkBackend = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/health`);
        if (res.ok) {
          const data = await res.json();
          setBackendOnline(true);
          if (data.soar_stats) {
            setSoarStats({
              keycloakRevocations: data.soar_stats.keycloak_revocations,
              iamKeysDisabled: data.soar_stats.iam_keys_disabled,
              dbIpQuarantined: data.soar_stats.db_ip_quarantined,
              totalInterceptions: data.soar_stats.total_interceptions
            });
          }
        } else {
          setBackendOnline(false);
        }
      } catch (e) {
        setBackendOnline(false);
      }
    };

    checkBackend();
    const interval = setInterval(checkBackend, 3000);
    return () => clearInterval(interval);
  }, []);

  // Poll live telemetry logs from FastAPI backend when online
  useEffect(() => {
    if (!backendOnline) return;
    const fetchTelemetry = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/telemetry`);
        if (res.ok) {
          const data = await res.json();
          setLogs(data.logs || []);
        }
      } catch (e) {}
    };
    fetchTelemetry();
    const interval = setInterval(fetchTelemetry, 1500);
    return () => clearInterval(interval);
  }, [backendOnline]);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const addLocalLog = (entry) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [
      ...prev,
      { id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`, timestamp, ...entry }
    ]);
  };

  const calcZScore = (volume, mean = 10.0, std = 2.0) => {
    return parseFloat(((volume - mean) / std).toFixed(2));
  };

  const handleReset = async () => {
    if (backendOnline) {
      try {
        await fetch(`${API_BASE}/api/reset`, { method: 'POST' });
      } catch (e) {}
    }
    setLogs([]);
    setChartData(INITIAL_CHART_DATA);
    setSoarStats({ keycloakRevocations: 0, iamKeysDisabled: 0, dbIpQuarantined: 0, totalInterceptions: 0 });
    setDecoys(INITIAL_DECOYS);
    setActiveScenario(null);
    addLocalLog({
      level: 'INFO',
      layer: 'SYSTEM',
      event: 'SYSTEM_RESET',
      message: 'Telemetry metrics and SOAR orchestration counters reset to baseline state.'
    });
  };

  const executeScenario = async (scenarioId, mockVolume, userLabel) => {
    if (isSimulating) return;
    setIsSimulating(true);
    setActiveScenario(String(scenarioId));
    const time = new Date().toLocaleTimeString();
    const z = calcZScore(mockVolume);

    if (backendOnline) {
      try {
        await fetch(`${API_BASE}/api/simulate/scenario/${scenarioId}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ user_id: userLabel, request_volume: mockVolume })
        });
      } catch (e) {
        console.error("Backend trigger error:", e);
      }
    } else {
      // Mock Client-Side Fallback Logic
      if (scenarioId === 1) {
        addLocalLog({ level: 'INFO', layer: 'TELEMETRY', event: 'USER_ACTIVITY_INGESTED', message: `Ingested user ${userLabel} request batch (Volume: ${mockVolume} req/min).` });
        addLocalLog({ level: 'INFO', layer: 'Layer-1 (Deception)', event: 'TRAP_CHECK_PASSED', message: 'No matching IAM keys, S3 canary objects, or DB honey-records targeted.' });
        addLocalLog({ level: 'INFO', layer: 'Layer-2 (UEBA)', event: 'Z_SCORE_EVALUATION', message: `Calculated Z-Score = ${z} (Z < 3.0 threshold). Baseline normal.` });
      } else if (scenarioId === 2) {
        addLocalLog({ level: 'WARNING', layer: 'TELEMETRY', event: 'HIGH_VOLUME_SPIKE_DETECTED', message: `Spike in API request volume for user ${userLabel} (Volume: ${mockVolume} req/min).` });
        addLocalLog({ level: 'CRITICAL', layer: 'Layer-2 (UEBA)', event: 'ANOMALY_THRESHOLD_EXCEEDED', message: `Z-SCORE ANOMALY TRIGGERED: Z = ${z} (Threshold Z >= 3.0).` });
        addLocalLog({ level: 'SOAR', layer: 'SOAR Orchestrator', event: 'AUTOMATED_CONTAINMENT_EXECUTED', message: 'Executing Keycloak SSO logout & session revocation.' });
        setSoarStats((p) => ({ ...p, keycloakRevocations: p.keycloakRevocations + 1, totalInterceptions: p.totalInterceptions + 1 }));
      } else if (scenarioId === 3) {
        addLocalLog({ level: 'WARNING', layer: 'TELEMETRY', event: 'S3_GET_OBJECT_REQUEST', message: 'Read attempt on S3 object path: s3://tenant-alpha-storage/confidential/payroll_2026_canary.csv' });
        addLocalLog({ level: 'CRITICAL', layer: 'Layer-1 (Deception)', event: 'DECOY_CANARY_INTERCEPTED', message: 'TRAP TRIGGERED! Access attempt on active Data-Plane S3 Canary.' });
        addLocalLog({ level: 'SOAR', layer: 'SOAR Orchestrator', event: 'IAM_KEY_DEACTIVATION', message: 'LocalStack IAM Access Key AKIA_DECOY_ADMIN_TRAP_99 set to INACTIVE.' });
        setSoarStats((p) => ({ ...p, iamKeysDisabled: p.iamKeysDisabled + 1, totalInterceptions: p.totalInterceptions + 1 }));
        setDecoys((prev) => prev.map((d) => (d.id === 'decoy-s3-1' ? { ...d, hits: d.hits + 1 } : d)));
      } else if (scenarioId === 4) {
        addLocalLog({ level: 'WARNING', layer: 'TELEMETRY', event: 'POSTGRES_SQL_QUERY', message: 'SQL execution: SELECT * FROM users WHERE user_id = 99999;' });
        addLocalLog({ level: 'CRITICAL', layer: 'Layer-1 (Deception)', event: 'HONEY_RECORD_INTERCEPTED', message: 'DATABASE TRAP TRIGGERED! Query touched interleaved Honey-Record (ID: 99999).' });
        addLocalLog({ level: 'SOAR', layer: 'SOAR Orchestrator', event: 'DB_CONNECTION_TERMINATED', message: 'Terminated active PostgreSQL database socket connection.' });
        setSoarStats((p) => ({ ...p, dbIpQuarantined: p.dbIpQuarantined + 1, totalInterceptions: p.totalInterceptions + 1 }));
        setDecoys((prev) => prev.map((d) => (d.id === 'decoy-db-1' ? { ...d, hits: d.hits + 1 } : d)));
      } else if (scenarioId === 5) {
        addLocalLog({ level: 'CRITICAL', layer: 'TELEMETRY', event: 'CROSS_TENANT_BURST_ATTACK', message: 'Massive burst scan detected (Volume: 110 req/min). Targeting decoy key & S3 canary!' });
        addLocalLog({ level: 'CRITICAL', layer: 'Layer-1 (Deception)', event: 'IAM_TRAP_TRIGGERED', message: 'Decoy IAM Access Key used for admin actions!' });
        addLocalLog({ level: 'CRITICAL', layer: 'Layer-2 (UEBA)', event: 'EXTREME_ANOMALY_TRIGGERED', message: `UEBA Evaluation: Z-Score = ${z} (Extreme Outlier).` });
        addLocalLog({ level: 'SOAR', layer: 'SOAR Orchestrator', event: 'FULL_TENANT_CONTAINMENT_PROTOCOL', message: 'CONTAINMENT ENFORCED: Keycloak Revoked, LocalStack IAM Disabled, DB IP Blacklisted.' });
        setSoarStats((p) => ({
          keycloakRevocations: p.keycloakRevocations + 2,
          iamKeysDisabled: p.iamKeysDisabled + 1,
          dbIpQuarantined: p.dbIpQuarantined + 1,
          totalInterceptions: p.totalInterceptions + 2
        }));
        setDecoys((prev) => prev.map((d) => ({ ...d, hits: d.hits + 1 })));
      }
    }

    setChartData((prev) => [
      ...prev.slice(-10),
      { time, volume: mockVolume, zScore: z, user: userLabel, isAnomaly: z >= 3.0 }
    ]);
    setIsSimulating(false);
  };

  const runFullBenchmark = () => {
    if (isSimulating) return;
    executeScenario(1, 12, 'USR_0001');
    setTimeout(() => executeScenario(2, 85, 'USR_0001'), 1600);
    setTimeout(() => executeScenario(3, 25, 'ATTACKER_IP'), 3200);
    setTimeout(() => executeScenario(4, 18, 'DB_ATTACKER'), 4800);
    setTimeout(() => executeScenario(5, 110, 'BURST_ATTACKER'), 6400);
  };

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      const matchesFilter =
        logFilter === 'ALL'
          ? true
          : logFilter === 'CRITICAL'
          ? log.level === 'CRITICAL'
          : logFilter === 'SOAR'
          ? log.layer === 'SOAR Orchestrator'
          : logFilter === 'DECEPTION'
          ? log.layer.includes('Layer-1')
          : log.layer.includes('Layer-2');

      const matchesSearch =
        searchQuery === ''
          ? true
          : log.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
            log.event.toLowerCase().includes(searchQuery.toLowerCase()) ||
            log.layer.toLowerCase().includes(searchQuery.toLowerCase());

      return matchesFilter && matchesSearch;
    });
  }, [logs, logFilter, searchQuery]);

  const copyLogJSON = (log) => {
    navigator.clipboard.writeText(JSON.stringify(log, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans p-4 sm:p-6 lg:p-8 space-y-6">
      {/* --- TOP HEADER BAR --- */}
      <header className="flex flex-col lg:flex-row lg:items-center justify-between pb-6 border-b border-slate-800 gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyan-400">
              <ShieldCheck className="w-8 h-8 animate-pulse text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center space-x-3">
                <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white">
                  Automated Deception-Driven IAM & UEBA Platform
                </h1>
                <span
                  className={`inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-bold border ${
                    backendOnline
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                  }`}
                >
                  <Wifi className="w-3 h-3" />
                  <span>{backendOnline ? 'FASTAPI LIVE (PORT 8000)' : 'STANDALONE MOCK MODE'}</span>
                </span>
              </div>
              <p className="text-xs sm:text-sm text-slate-400 font-medium mt-0.5">
                MTech Dissertation Project · Real-time Control/Data-Plane Deception & Anomaly Orchestrator
              </p>
            </div>
          </div>
        </div>

        {/* Global Control Buttons */}
        <div className="flex items-center space-x-3 self-end lg:self-center">
          <button
            onClick={runFullBenchmark}
            disabled={isSimulating}
            className="flex items-center space-x-2 px-4 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-white font-semibold text-xs sm:text-sm rounded-lg shadow-lg shadow-cyan-900/30 transition-all border border-cyan-400/30 active:scale-95"
          >
            <Zap className="w-4 h-4" />
            <span>Run Benchmark Suite</span>
          </button>

          <button
            onClick={handleReset}
            disabled={isSimulating}
            className="flex items-center space-x-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-300 font-semibold text-xs sm:text-sm rounded-lg border border-slate-700 transition-all active:scale-95"
          >
            <RotateCcw className="w-4 h-4" />
            <span>Reset Baseline</span>
          </button>
        </div>
      </header>

      {/* --- INFRASTRUCTURE SERVICES STATUS --- */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/80 border border-slate-800/80 rounded-xl p-4 flex items-center justify-between">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <Server className="w-4 h-4 text-slate-400" />
              <span className="text-xs font-bold uppercase text-slate-300">LocalStack AWS</span>
            </div>
            <p className="text-xs text-slate-400">IAM & S3 Canaries</p>
            <div className="text-[10px] text-slate-500 font-mono">Port: 4566</div>
          </div>
          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            OPERATIONAL
          </span>
        </div>

        <div className="bg-slate-900/80 border border-slate-800/80 rounded-xl p-4 flex items-center justify-between">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <Server className="w-4 h-4 text-slate-400" />
              <span className="text-xs font-bold uppercase text-slate-300">Keycloak OIDC</span>
            </div>
            <p className="text-xs text-slate-400">SSO Session Revocation</p>
            <div className="text-[10px] text-slate-500 font-mono">Port: 8080</div>
          </div>
          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">
            AUTHENTICATED
          </span>
        </div>

        <div className="bg-slate-900/80 border border-slate-800/80 rounded-xl p-4 flex items-center justify-between">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <Server className="w-4 h-4 text-slate-400" />
              <span className="text-xs font-bold uppercase text-slate-300">PostgreSQL DB</span>
            </div>
            <p className="text-xs text-slate-400">Honey-Records Interleaved</p>
            <div className="text-[10px] text-slate-500 font-mono">Port: 5432</div>
          </div>
          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            SEEDING ACTIVE
          </span>
        </div>

        <div className="bg-slate-900/80 border border-slate-800/80 rounded-xl p-4 flex items-center justify-between">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold uppercase text-slate-300">Security Posture</span>
            </div>
            <p className="text-xs text-slate-400">Layer 1 & Layer 2 Active</p>
            <div className="text-[10px] text-cyan-400 font-mono">Z-Threshold: 3.0</div>
          </div>
          <span className="px-2.5 py-1 rounded-full text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            ARMED MESH
          </span>
        </div>
      </section>

      {/* --- MAIN DASHBOARD CONTENT GRID --- */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* LEFT COLUMN: Controls & Deception Registry (5 Cols) */}
        <div className="lg:col-span-5 space-y-6">
          {/* SIMULATION SUITE PANEL */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Play className="w-5 h-5 text-cyan-400" />
                <h2 className="text-base font-bold text-white tracking-wide">Threat Simulation Suite</h2>
              </div>
              <span className="text-xs font-mono text-slate-400">Select Attack Scenario</span>
            </div>

            <div className="space-y-2.5">
              <button
                onClick={() => executeScenario(1, 12, 'USR_0001')}
                disabled={isSimulating}
                className={`w-full text-left p-3.5 rounded-xl border transition-all flex items-start justify-between group ${
                  activeScenario === '1'
                    ? 'bg-emerald-950/40 border-emerald-500/60'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 hover:bg-slate-800/50'
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                      Scenario 1
                    </span>
                    <span className="text-sm font-semibold text-slate-200">Legitimate User Access</span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Normal activity pattern (V=12 req/min, Z=0.38). Passes all health checks.
                  </p>
                </div>
                <ChevronRight className="w-5 h-5 text-slate-600 group-hover:text-slate-300 transition-colors mt-1" />
              </button>

              <button
                onClick={() => executeScenario(2, 85, 'USR_0001')}
                disabled={isSimulating}
                className={`w-full text-left p-3.5 rounded-xl border transition-all flex items-start justify-between group ${
                  activeScenario === '2'
                    ? 'bg-amber-950/40 border-amber-500/60'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 hover:bg-slate-800/50'
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                      Scenario 2
                    </span>
                    <span className="text-sm font-semibold text-slate-200">UEBA Insider Threat Spike</span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Volume spike (V=85 req/min, Z=19.63 &gt; 3.0). Triggers Keycloak Session Revocation.
                  </p>
                </div>
                <ChevronRight className="w-5 h-5 text-slate-600 group-hover:text-slate-300 transition-colors mt-1" />
              </button>

              <button
                onClick={() => executeScenario(3, 25, 'ATTACKER_IP')}
                disabled={isSimulating}
                className={`w-full text-left p-3.5 rounded-xl border transition-all flex items-start justify-between group ${
                  activeScenario === '3'
                    ? 'bg-rose-950/40 border-rose-500/60'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 hover:bg-slate-800/50'
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                      Scenario 3
                    </span>
                    <span className="text-sm font-semibold text-slate-200">S3 Canary Object Read</span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Layer-1 Trap Hit on `payroll_2026_canary.csv`. Deactivates LocalStack IAM Key.
                  </p>
                </div>
                <ChevronRight className="w-5 h-5 text-slate-600 group-hover:text-slate-300 transition-colors mt-1" />
              </button>

              <button
                onClick={() => executeScenario(4, 18, 'DB_ATTACKER')}
                disabled={isSimulating}
                className={`w-full text-left p-3.5 rounded-xl border transition-all flex items-start justify-between group ${
                  activeScenario === '4'
                    ? 'bg-purple-950/40 border-purple-500/60'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 hover:bg-slate-800/50'
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/10 text-purple-400 border border-purple-500/30">
                      Scenario 4
                    </span>
                    <span className="text-sm font-semibold text-slate-200">DB Honey-Record Access</span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Query touches PostgreSQL decoy `user_id=99999`. Terminates DB Socket & IP.
                  </p>
                </div>
                <ChevronRight className="w-5 h-5 text-slate-600 group-hover:text-slate-300 transition-colors mt-1" />
              </button>

              <button
                onClick={() => executeScenario(5, 110, 'BURST_ATTACKER')}
                disabled={isSimulating}
                className={`w-full text-left p-3.5 rounded-xl border transition-all flex items-start justify-between group ${
                  activeScenario === '5'
                    ? 'bg-cyan-950/40 border-cyan-500/60'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 hover:bg-slate-800/50'
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                      Scenario 5
                    </span>
                    <span className="text-sm font-semibold text-slate-200">Multi-Tenant Burst Breach</span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Dual Trigger: Deception Trap + Extreme UEBA Anomaly (V=110, Z=25.4). Full Containment.
                  </p>
                </div>
                <ChevronRight className="w-5 h-5 text-slate-600 group-hover:text-slate-300 transition-colors mt-1" />
              </button>
            </div>
          </div>

          {/* ACTIVE DECOY REGISTRY CARD */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Radio className="w-5 h-5 text-emerald-400 animate-pulse" />
                <h2 className="text-base font-bold text-white tracking-wide">Deception Registry</h2>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                {decoys.length} Armed Traps
              </span>
            </div>

            <div className="space-y-3">
              {decoys.map((decoy) => (
                <div
                  key={decoy.id}
                  className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-3.5 space-y-2 hover:border-slate-700 transition-all"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      {decoy.type.includes('IAM') && <Key className="w-4 h-4 text-amber-400" />}
                      {decoy.type.includes('S3') && <HardDrive className="w-4 h-4 text-cyan-400" />}
                      {decoy.type.includes('Database') && <Database className="w-4 h-4 text-purple-400" />}
                      <span className="text-xs font-bold text-slate-200">{decoy.type}</span>
                    </div>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                        decoy.hits > 0
                          ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse'
                          : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      }`}
                    >
                      {decoy.hits > 0 ? `TRIPPED (${decoy.hits})` : decoy.status}
                    </span>
                  </div>

                  <div className="bg-slate-900 rounded p-2 text-[11px] font-mono text-slate-300 break-all border border-slate-800/50">
                    {decoy.identifier}
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1">
                    <span>Plane: {decoy.plane}</span>
                    <span>Target: {decoy.target}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: SOAR Stats, Chart & Log Stream (7 Cols) */}
        <div className="lg:col-span-7 space-y-6">
          {/* SOAR REMEDIATION METRICS CARDS */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                  Keycloak Logout
                </span>
                <UserX className="w-4 h-4 text-indigo-400" />
              </div>
              <p className="text-2xl font-black text-white font-mono">
                {soarStats.keycloakRevocations}
              </p>
              <p className="text-[10px] text-slate-500">SSO Sessions Killed</p>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                  LocalStack IAM
                </span>
                <Lock className="w-4 h-4 text-amber-400" />
              </div>
              <p className="text-2xl font-black text-white font-mono">
                {soarStats.iamKeysDisabled}
              </p>
              <p className="text-[10px] text-slate-500">Access Keys Disabled</p>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                  Postgres DB
                </span>
                <Database className="w-4 h-4 text-purple-400" />
              </div>
              <p className="text-2xl font-black text-white font-mono">
                {soarStats.dbIpQuarantined}
              </p>
              <p className="text-[10px] text-slate-500">Sockets Terminated</p>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 space-y-1 bg-gradient-to-br from-cyan-950/30 to-slate-900">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider">
                  Total Neutralized
                </span>
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
              </div>
              <p className="text-2xl font-black text-cyan-400 font-mono">
                {soarStats.totalInterceptions}
              </p>
              <p className="text-[10px] text-cyan-500">SOAR Interceptions</p>
            </div>
          </div>

          {/* UEBA Z-SCORE CHART */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-3 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Activity className="w-5 h-5 text-cyan-400" />
                <h2 className="text-base font-bold text-white tracking-wide">
                  UEBA Real-Time Anomaly Detection Engine
                </h2>
              </div>
              <div className="flex items-center space-x-3 text-xs font-mono">
                <span className="flex items-center space-x-1 text-slate-400">
                  <span className="w-2 h-2 rounded-full bg-cyan-400" />
                  <span>Request Vol (req/min)</span>
                </span>
                <span className="flex items-center space-x-1 text-rose-400">
                  <span className="w-2 h-2 rounded-full bg-rose-500" />
                  <span>Threshold (Z &ge; 3.0)</span>
                </span>
              </div>
            </div>

            <div className="h-48 w-full pt-2">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="volGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 10 }} />
                  <YAxis stroke="#64748b" tick={{ fontSize: 10 }} domain={[0, 'dataMax + 15']} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '12px'
                    }}
                    itemStyle={{ color: '#38bdf8' }}
                  />
                  <ReferenceLine y={16} stroke="#f43f5e" strokeDasharray="4 4" label={{ value: 'Z = 3.0 Threshold (16 req/min)', fill: '#f43f5e', fontSize: 10, position: 'top' }} />
                  <Area
                    type="monotone"
                    dataKey="volume"
                    stroke="#06b6d4"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#volGradient)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* REAL-TIME SECURITY AUDIT LOG TERMINAL */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 space-y-3 shadow-xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2">
              <div className="flex items-center space-x-2">
                <Terminal className="w-5 h-5 text-emerald-400" />
                <h2 className="text-base font-bold text-white tracking-wide">Live Telemetry & Audit Stream</h2>
              </div>

              {/* Log Filters */}
              <div className="flex items-center space-x-2">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
                  <input
                    type="text"
                    placeholder="Search telemetry..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="bg-slate-950 border border-slate-800 text-xs text-slate-200 pl-8 pr-3 py-1 rounded-lg focus:outline-none focus:border-cyan-500 w-36 sm:w-48"
                  />
                </div>

                <select
                  value={logFilter}
                  onChange={(e) => setLogFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 text-xs text-slate-300 px-2.5 py-1 rounded-lg focus:outline-none focus:border-cyan-500"
                >
                  <option value="ALL">All Layers</option>
                  <option value="DECEPTION">Layer-1 (Deception)</option>
                  <option value="UEBA">Layer-2 (UEBA)</option>
                  <option value="SOAR">SOAR Remediation</option>
                  <option value="CRITICAL">Critical Alerts</option>
                </select>
              </div>
            </div>

            <div className="bg-slate-950 rounded-xl p-4 font-mono text-xs h-64 overflow-y-auto space-y-2 border border-slate-800/80 scrollbar-thin scrollbar-thumb-slate-800">
              {filteredLogs.length === 0 ? (
                <div className="h-full flex items-center justify-center text-slate-600 italic">
                  No telemetry logged yet. Launch a scenario from the Threat Simulation Suite.
                </div>
              ) : (
                filteredLogs.map((log) => (
                  <div
                    key={log.id}
                    onClick={() => setSelectedLog(log)}
                    className="p-2 rounded hover:bg-slate-900/90 cursor-pointer transition-colors border border-transparent hover:border-slate-800 group flex items-start justify-between space-x-2"
                  >
                    <div className="space-y-0.5">
                      <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                        <span className="text-slate-500 text-[10px]">[{log.timestamp}]</span>
                        <span
                          className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                            log.level === 'CRITICAL'
                              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                              : log.level === 'WARNING'
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                              : log.level === 'SOAR'
                              ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {log.layer}
                        </span>
                        <span className="text-slate-300 font-semibold">{log.event}</span>
                      </div>
                      <p className="text-slate-400 pl-1">{log.message}</p>
                    </div>
                    <FileText className="w-3.5 h-3.5 text-slate-600 group-hover:text-cyan-400 flex-shrink-0 mt-1" />
                  </div>
                ))
              )}
              <div ref={terminalEndRef} />
            </div>
          </div>
        </div>
      </div>

      {/* EVENT INSPECTOR MODAL */}
      {selectedLog && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <FileText className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">Telemetry Event Payload</h3>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="text-slate-400 hover:text-white p-1"
              >
                ✕
              </button>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Event ID: {selectedLog.id}</span>
                <span>Time: {selectedLog.timestamp}</span>
              </div>
              <pre className="bg-slate-950 p-4 rounded-xl text-xs font-mono text-cyan-300 overflow-x-auto border border-slate-800">
                {JSON.stringify(selectedLog, null, 2)}
              </pre>
            </div>

            <div className="flex items-center justify-between pt-2">
              <button
                onClick={() => copyLogJSON(selectedLog)}
                className="flex items-center space-x-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied JSON' : 'Copy JSON'}</span>
              </button>
              <button
                onClick={() => setSelectedLog(null)}
                className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded-lg"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}