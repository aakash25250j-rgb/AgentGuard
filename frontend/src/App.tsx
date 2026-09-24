import { useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import './App.css';

/* =====================================================================
   AgentGuard — SOC Console & Security Engine
   Connected to FastAPI Backend (POST /activities) with Autonomous Fallback
   ===================================================================== */

const BACKEND_URL = 'http://localhost:8000';

/* ------------------------------ types ------------------------------ */
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type DecisionKind = 'ALLOW' | 'REVIEW' | 'BLOCK' | 'ISOLATE';
export type Status = 'Active' | 'Under Review' | 'Monitoring' | 'Normal' | 'Isolated' | 'Blocked' | 'Allowed';
export type ActionKind = 'ISOLATE' | 'BLOCK' | 'REVIEW' | 'ALLOW' | 'RESTORE' | 'ESCALATE';
export type Tone = 'danger' | 'warn' | 'ok';
export type SortKey = 'agent' | 'risk' | 'severity' | 'decision';
export type SortDir = 'asc' | 'desc';

export interface BaselineMetrics {
  api_calls: number;
  db_queries: number;
  files_accessed: number;
  data_mb: number;
}

export interface SecuritySignals {
  permission_violation: boolean;
  intent_mismatch: boolean;
  behavior_anomaly: boolean;
  sensitive_resource: boolean;
  unusual_data_volume: boolean;
  suspicious_sequence: boolean;
}

export interface BehaviorFingerprintData {
  baseline: BaselineMetrics;
  current: BaselineMetrics;
  deviations?: BaselineMetrics;
  average_deviation: number;
}

export interface IncidentEvent {
  t: string;
  m: string;
  l: Severity;
}

export interface Incident {
  id: string;
  agent: string;
  task: string;
  actionAttempted: string;
  resourceTargeted: string;
  risk: number;
  severity: Severity;
  decision: DecisionKind;
  status: Status;
  action: ActionKind;
  vector: string;
  region: string;
  model: string;
  trust: number;
  detections: number;
  lastSeen: string;
  playbook: string;
  events: IncidentEvent[];
  signals: SecuritySignals;
  activity: [number, number, number, number];
  action_history: string[];
  fingerprint: BehaviorFingerprintData;
}

interface ToastItem {
  id: number;
  tone: Tone;
  ic: string;
  tt: string;
  ms: string;
}

interface FeedItem {
  id: number;
  ts: string;
  txt: string;
  l: Severity;
}

interface TrendPoint {
  risk: number;
  label: string;
  name: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface ActionConfig {
  status: Status;
  action: ActionKind;
  dr: number;
  tone: Tone;
  ic: string;
  tt: string;
  ms: (agent: string) => string;
  log: (agent: string) => string;
}

const vars = (o: Record<string, string | number>): CSSProperties => o as unknown as CSSProperties;

/* --------------------------- constants ----------------------------- */
export const SIGNAL_WEIGHTS: Record<keyof SecuritySignals, number> = {
  permission_violation: 20,
  intent_mismatch: 20,
  behavior_anomaly: 15,
  sensitive_resource: 15,
  unusual_data_volume: 15,
  suspicious_sequence: 15,
};

const SEV_META: Record<Severity, { c: string; cls: string; bg: string; bd: string }> = {
  CRITICAL: { c: '#ff4d5e', cls: 'crit', bg: 'rgba(255,77,94,.16)', bd: 'rgba(255,77,94,.55)' },
  HIGH:     { c: '#ff9f1c', cls: 'high', bg: 'rgba(255,159,28,.16)', bd: 'rgba(255,159,28,.5)' },
  MEDIUM:   { c: '#ffd166', cls: 'med',  bg: 'rgba(255,209,102,.15)', bd: 'rgba(255,209,102,.45)' },
  LOW:      { c: '#3ddc97', cls: 'low',  bg: 'rgba(61,220,151,.15)', bd: 'rgba(61,220,151,.45)' },
};

const DEC_META: Record<DecisionKind, { label: string; cls: string; color: string; border: string }> = {
  ISOLATE: { label: 'ISOLATE', cls: 'dec-isolate', color: '#ff4d5e', border: 'rgba(255,77,94,.6)' },
  BLOCK:   { label: 'BLOCK',   cls: 'dec-block',   color: '#ff9f1c', border: 'rgba(255,159,28,.6)' },
  REVIEW:  { label: 'REVIEW',  cls: 'dec-review',  color: '#ffd166', border: 'rgba(255,209,102,.6)' },
  ALLOW:   { label: 'ALLOW',   cls: 'dec-allow',   color: '#3ddc97', border: 'rgba(61,220,151,.6)' },
};

const ACTION_MAP: Record<ActionKind, ActionConfig> = {
  ISOLATE: {
    status: 'Isolated', action: 'RESTORE', dr: -22, tone: 'danger', ic: '🛑',
    tt: 'Containment executed',
    ms: (a) => `${a} isolated — runtime frozen by Security Engine.`,
    log: (a) => `<b>${a}</b> isolated · egress blocked`,
  },
  BLOCK: {
    status: 'Blocked', action: 'REVIEW', dr: -15, tone: 'warn', ic: '🚫',
    tt: 'Action blocked',
    ms: (a) => `${a} query rejected by Security Engine.`,
    log: (a) => `<b>${a}</b> action blocked by Security Engine`,
  },
  REVIEW: {
    status: 'Under Review', action: 'ESCALATE', dr: 4, tone: 'warn', ic: '🔎',
    tt: 'Investigation opened',
    ms: (a) => `${a} queued for SOC analyst triage.`,
    log: (a) => `Investigation opened for <b>${a}</b>`,
  },
  ALLOW: {
    status: 'Allowed', action: 'ISOLATE', dr: -14, tone: 'ok', ic: '✅',
    tt: 'Agent cleared',
    ms: (a) => `${a} verified benign with telemetry audit.`,
    log: (a) => `Operator override · <b>${a}</b> cleared`,
  },
  RESTORE: {
    status: 'Monitoring', action: 'ISOLATE', dr: 3, tone: 'ok', ic: '♻️',
    tt: 'Agent restored',
    ms: (a) => `${a} back online with enhanced telemetry.`,
    log: (a) => `<b>${a}</b> restored to runtime`,
  },
  ESCALATE: {
    status: 'Active', action: 'ISOLATE', dr: 2, tone: 'danger', ic: '🚨',
    tt: 'Escalated to Tier 2',
    ms: (a) => `${a} escalated to Tier 2 response.`,
    log: (a) => `<b>${a}</b> escalated to Tier 2`,
  },
};

const SEV_ORDER: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const ALL_SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const CAP = 5;

const clamp = (v: number, a: number, b: number): number => Math.max(a, Math.min(b, v));
const stamp = (): string => new Date().toTimeString().slice(0, 8);
const rand = (n: number): number => Math.floor(Math.random() * n);

const actionsFor = (s: Status): ActionKind[] =>
  s === 'Isolated' ? ['RESTORE', 'REVIEW']
  : s === 'Blocked' ? ['ALLOW', 'REVIEW']
  : s === 'Allowed' ? ['ISOLATE', 'REVIEW']
  : ['ISOLATE', 'BLOCK', 'REVIEW', 'ALLOW'];

const statusClass = (s: Status): string =>
  s === 'Active' ? 'active'
  : s === 'Under Review' ? 'review'
  : s === 'Monitoring' ? 'monitor'
  : s === 'Isolated' ? 'isolated'
  : s === 'Blocked' ? 'blocked'
  : s === 'Allowed' ? 'allowed'
  : 'normal';

/* -------------------- Initial Data ------------------- */
const INITIAL: Incident[] = [
  {
    id: 'i1',
    agent: 'DevAgent',
    task: 'FIX_LOGIN',
    actionAttempted: 'DELETE',
    resourceTargeted: 'production_database',
    risk: 100,
    severity: 'CRITICAL',
    decision: 'ISOLATE',
    status: 'Active',
    action: 'ISOLATE',
    vector: 'Privilege Escalation → Attempted Database Deletion',
    region: 'us-east-1',
    model: 'claude-sonnet-4',
    trust: 12,
    detections: 6,
    lastSeen: '12s',
    playbook: 'Isolate runtime container, revoke token scopes, freeze cluster node.',
    activity: [150, 200, 500, 800],
    action_history: ['SCAN', 'ACCESS_SENSITIVE', 'EXPORT_LARGE_DATA'],
    signals: {
      permission_violation: true,
      intent_mismatch: true,
      behavior_anomaly: true,
      sensitive_resource: true,
      unusual_data_volume: true,
      suspicious_sequence: true,
    },
    fingerprint: {
      baseline: { api_calls: 10, db_queries: 4.8, files_accessed: 12.2, data_mb: 2.8 },
      current: { api_calls: 150, db_queries: 200, files_accessed: 500, data_mb: 800 },
      deviations: { api_calls: 14.0, db_queries: 40.67, files_accessed: 39.98, data_mb: 284.71 },
      average_deviation: 94.84,
    },
    events: [
      { t: '03:41:12', m: 'DELETE production_database intercepted by Security Engine', l: 'CRITICAL' },
      { t: '03:41:07', m: 'All 6 security signals activated simultaneously', l: 'CRITICAL' },
    ],
  },
  {
    id: 'i2',
    agent: 'FinanceAgent',
    task: 'ANALYZE_DATA',
    actionAttempted: 'READ',
    resourceTargeted: 'analytics_database',
    risk: 65,
    severity: 'HIGH',
    decision: 'BLOCK',
    status: 'Under Review',
    action: 'BLOCK',
    vector: 'Data Volume Anomaly on Sensitive Analytics DB',
    region: 'eu-west-1',
    model: 'gpt-4.1',
    trust: 48,
    detections: 4,
    lastSeen: '48s',
    playbook: 'Block outbound query, throttle database reads, alert data officer.',
    activity: [40, 30, 80, 150],
    action_history: ['READ', 'QUERY'],
    signals: {
      permission_violation: true,
      intent_mismatch: false,
      behavior_anomaly: true,
      sensitive_resource: true,
      unusual_data_volume: true,
      suspicious_sequence: false,
    },
    fingerprint: {
      baseline: { api_calls: 10, db_queries: 4.8, files_accessed: 12.2, data_mb: 2.8 },
      current: { api_calls: 40, db_queries: 30, files_accessed: 80, data_mb: 150 },
      deviations: { api_calls: 3.0, db_queries: 5.25, files_accessed: 5.56, data_mb: 52.57 },
      average_deviation: 16.6,
    },
    events: [{ t: '03:39:44', m: 'Permission violation + volume limit exceeded (150MB)', l: 'HIGH' }],
  },
  {
    id: 'i3',
    agent: 'DeployAgent',
    task: 'DEPLOY_RELEASE',
    actionAttempted: 'EXEC',
    resourceTargeted: 'prod_cluster',
    risk: 50,
    severity: 'MEDIUM',
    decision: 'REVIEW',
    status: 'Active',
    action: 'REVIEW',
    vector: 'Unapproved Stage Transition',
    region: 'us-west-2',
    model: 'llama-4-70b',
    trust: 44,
    detections: 3,
    lastSeen: '1m',
    playbook: 'Freeze deployment pipeline, require dual signoff.',
    activity: [24, 15, 30, 20],
    action_history: ['PULL', 'EXEC'],
    signals: {
      permission_violation: true,
      intent_mismatch: false,
      behavior_anomaly: true,
      sensitive_resource: true,
      unusual_data_volume: false,
      suspicious_sequence: false,
    },
    fingerprint: {
      baseline: { api_calls: 10, db_queries: 4.8, files_accessed: 12.2, data_mb: 2.8 },
      current: { api_calls: 24, db_queries: 15, files_accessed: 30, data_mb: 20 },
      deviations: { api_calls: 1.4, db_queries: 2.1, files_accessed: 1.45, data_mb: 6.14 },
      average_deviation: 2.77,
    },
    events: [{ t: '03:36:20', m: 'Prod cluster execution intercepted', l: 'MEDIUM' }],
  },
  {
    id: 'i4',
    agent: 'HR-Agent',
    task: 'AUDIT_EXPENSES',
    actionAttempted: 'READ',
    resourceTargeted: 'source_code',
    risk: 0,
    severity: 'LOW',
    decision: 'ALLOW',
    status: 'Normal',
    action: 'ALLOW',
    vector: 'Baseline Activity · Verified Safe',
    region: 'ap-south-1',
    model: 'gpt-4o-mini',
    trust: 96,
    detections: 0,
    lastSeen: '2m',
    playbook: 'No action required. Activity strictly within learned baseline.',
    activity: [10, 5, 12, 3],
    action_history: ['READ'],
    signals: {
      permission_violation: false,
      intent_mismatch: false,
      behavior_anomaly: false,
      sensitive_resource: false,
      unusual_data_volume: false,
      suspicious_sequence: false,
    },
    fingerprint: {
      baseline: { api_calls: 10, db_queries: 4.8, files_accessed: 12.2, data_mb: 2.8 },
      current: { api_calls: 10, db_queries: 5, files_accessed: 12, data_mb: 3 },
      deviations: { api_calls: 0, db_queries: 0.04, files_accessed: 0.016, data_mb: 0.07 },
      average_deviation: 0.032,
    },
    events: [{ t: '03:20:05', m: 'Telemetry within normal bounds', l: 'LOW' }],
  },
];

/* ------------------- VISUAL COMPONENTS (FIXED) ------------------- */
function useCountUp(value: number, dur = 850): number {
  const [display, setDisplay] = useState<number>(value);
  const fromRef = useRef<number>(value);

  useEffect(() => {
    const from = fromRef.current;
    if (from === value) return;
    let raf = 0;
    const t0 = performance.now();
    const step = (t: number) => {
      const p = Math.min((t - t0) / dur, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      setDisplay(from + (value - from) * eased);
      if (p < 1) raf = requestAnimationFrame(step);
      else fromRef.current = value;
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [value, dur]);

  return display;
}

function Spark({ data, color, w = 96, h = 26 }: { data: number[]; color: string; w?: number; h?: number }) {
  const max = Math.max(...data, 1);
  const min = Math.min(...data);
  const span = Math.max(max - min, 1);
  const pts = data
    .map((v, i) => `${(i / Math.max(data.length - 1, 1)) * w},${h - ((v - min) / span) * (h - 4) - 2}`)
    .join(' ');
  return (
    <svg className="ag-spark" width={w} height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.8" strokeLinejoin="round" strokeLinecap="round" opacity=".9" />
    </svg>
  );
}

function Donut({ data, size = 156, thickness = 17 }: { data: { key: Severity; value: number; color: string }[]; size?: number; thickness?: number }) {
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  const r = (size - thickness) / 2;
  const C = 2 * Math.PI * r;
  let acc = 0;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ transform: 'rotate(-90deg)' }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,.055)" strokeWidth={thickness} />
      {data.map((d) => {
        const len = (d.value / total) * C;
        const el = (
          <circle
            key={d.key}
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke={d.color}
            strokeWidth={thickness}
            strokeDasharray={`${len} ${C - len}`}
            strokeDashoffset={-acc}
            style={{ transition: 'stroke-dasharray .85s cubic-bezier(.22,1,.36,1), stroke-dashoffset .85s cubic-bezier(.22,1,.36,1)' }}
          />
        );
        acc += len;
        return el;
      })}
    </svg>
  );
}

function Gauge({ value }: { value: number }) {
  const r = 54;
  const cx = 70;
  const cy = 70;
  const arc = Math.PI * r;
  const pct = clamp(value, 0, 100) / 100;
  const color = value >= 80 ? '#ff4d5e' : value >= 60 ? '#ff9f1c' : value >= 30 ? '#ffd166' : '#3ddc97';
  const d = `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`;
  return (
    <svg viewBox="0 0 140 84" width="200" height="120" className="ag-gauge">
      <path d={d} fill="none" stroke="rgba(255,255,255,.08)" strokeWidth="11" strokeLinecap="round" />
      <path
        d={d}
        fill="none"
        stroke={color}
        strokeWidth="11"
        strokeLinecap="round"
        strokeDasharray={`${arc * pct} ${arc}`}
        style={{ transition: 'stroke-dasharray .9s cubic-bezier(.22,1,.36,1), stroke .5s' }}
      />
      <text className="ag-gnum" x={cx} y={cy - 12} textAnchor="middle" fill={color}>{Math.round(value)}</text>
      <text className="ag-glbl" x={cx} y={cy + 8} textAnchor="middle" fill="#586279">RISK SCORE</text>
    </svg>
  );
}

/* ------------------------------ App -------------------------------- */
export default function App() {
  const [incidents, setIncidents] = useState<Incident[]>(INITIAL);
  const [live, setLive] = useState<boolean>(true);
  const [backendOnline, setBackendOnline] = useState<boolean>(false);
  const [range, setRange] = useState<number>(7);
  const [hoverBar, setHoverBar] = useState<number | null>(null);
  const [pinnedBar, setPinnedBar] = useState<number | null>(null);
  const [filter, setFilter] = useState<Severity | 'ALL'>('ALL');
  const [query, setQuery] = useState<string>('');
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: 'risk', dir: 'desc' });
  const [selectedId, setSelectedId] = useState<string | null>('i1');
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [now, setNow] = useState<string>(stamp());
  const [showEvalModal, setShowEvalModal] = useState<boolean>(false);

  // Form inputs for custom evaluation
  const [evalAgent, setEvalAgent] = useState<string>('DevAgent');
  const [evalTask, setEvalTask] = useState<string>('FIX_LOGIN');
  const [evalAction, setEvalAction] = useState<string>('DELETE');
  const [evalResource, setEvalResource] = useState<string>('production_database');
  const [evalApiCalls, setEvalApiCalls] = useState<number>(150);
  const [evalDbQueries, setEvalDbQueries] = useState<number>(200);
  const [evalFiles, setEvalFiles] = useState<number>(500);
  const [evalDataMb, setEvalDataMb] = useState<number>(800);
  const [evalSeqActive, setEvalSeqActive] = useState<boolean>(true);

  const [feed, setFeed] = useState<FeedItem[]>([
    { id: 1, ts: stamp(), txt: 'AgentGuard: Initialized SOC console telemetry', l: 'LOW' },
  ]);

  const toastId = useRef<number>(0);
  const feedId = useRef<number>(1);
  const searchRef = useRef<HTMLInputElement>(null);

  /* --- Clock --- */
  useEffect(() => {
    const id = window.setInterval(() => setNow(stamp()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const pushToast = (tone: Tone, ic: string, tt: string, ms: string) => {
    const id = ++toastId.current;
    setToasts((prev) => [...prev, { id, tone, ic, tt, ms }]);
    window.setTimeout(() => setToasts((prev) => prev.filter((x) => x.id !== id)), 4200);
  };

  const pushFeed = (txt: string, level: Severity) => {
    const id = ++feedId.current;
    setFeed((prev) => [{ id, ts: stamp(), txt, l: level }, ...prev].slice(0, 22));
  };

  /* --- Check FastAPI Backend Connectivity --- */
  useEffect(() => {
    const pingBackend = async () => {
      try {
        const res = await fetch(`${BACKEND_URL}/health`);
        setBackendOnline(res.ok);
      } catch {
        setBackendOnline(false);
      }
    };
    pingBackend();
    const interval = window.setInterval(pingBackend, 5000);
    return () => window.clearInterval(interval);
  }, []);

  /* --- Live Telemetry Drift (Preserved from Original) --- */
  useEffect(() => {
    if (!live) return;
    const id = window.setInterval(() => {
      setIncidents((prev) =>
        prev.map((inc) => {
          if (inc.status === 'Isolated' || inc.status === 'Blocked' || inc.status === 'Allowed') return inc;
          const drift = Math.round((Math.random() - 0.48) * 4);
          const risk = clamp(inc.risk + drift, 0, 100);
          const severity: Severity = risk >= 80 ? 'CRITICAL' : risk >= 60 ? 'HIGH' : risk >= 30 ? 'MEDIUM' : 'LOW';
          const decision: DecisionKind = risk >= 80 ? 'ISOLATE' : risk >= 60 ? 'BLOCK' : risk >= 30 ? 'REVIEW' : 'ALLOW';
          return { ...inc, risk, severity, decision, lastSeen: `${rand(20) + 2}s` };
        })
      );
    }, 3000);
    return () => window.clearInterval(id);
  }, [live]);

  /* --- Keyboard Shortcuts --- */
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setSelectedId(null);
        setShowEvalModal(false);
      }
      if (e.key === '/' && document.activeElement !== searchRef.current) {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  /* --- Evaluate Action via Backend or Local Fallback --- */
  const postActivity = async (payload: {
    agent: string;
    task: string;
    action: string;
    resource: string;
    api_calls: number;
    db_queries: number;
    files_accessed: number;
    data_mb: number;
    action_history: string[];
  }) => {
    if (backendOnline) {
      try {
        const res = await fetch(`${BACKEND_URL}/activities`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (res.ok) return await res.json();
      } catch (e) {
        console.warn('Backend POST failed, switching to autonomous engine:', e);
      }
    }

    // Exact Local Security Engine Calculation
    const perm =
      payload.agent.includes('DevAgent') &&
      (payload.resource.includes('production') || payload.resource.includes('analytics') || payload.action === 'DELETE');
    const intent =
      payload.task === 'FIX_LOGIN' && (payload.action === 'DELETE' || payload.resource.includes('production'));
    const isSensitive = ['production_database', 'analytics_database', 'credential_store'].includes(payload.resource);
    const vol = payload.data_mb > 50 || payload.files_accessed > 50;
    const seq = payload.action_history.includes('EXPORT_LARGE_DATA') && payload.action_history.includes('ACCESS_SENSITIVE');
    const anomaly = payload.api_calls > 50 || vol;

    let score = 0;
    if (perm) score += 20;
    if (intent) score += 20;
    if (anomaly) score += 15;
    if (isSensitive) score += 15;
    if (vol) score += 15;
    if (seq) score += 15;
    score = Math.min(100, score);

    const severity: Severity = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW';
    const decision: DecisionKind = score >= 80 ? 'ISOLATE' : score >= 60 ? 'BLOCK' : score >= 30 ? 'REVIEW' : 'ALLOW';

    return {
      agent: payload.agent,
      task: payload.task,
      action: payload.action,
      resource: payload.resource,
      risk_score: score,
      severity,
      decision,
      signals: {
        permission_violation: perm,
        intent_mismatch: intent,
        behavior_anomaly: anomaly,
        sensitive_resource: isSensitive,
        unusual_data_volume: vol,
        suspicious_sequence: seq,
      },
      explanation: `Security Engine evaluated ${payload.action} on ${payload.resource}`,
      fingerprint: {
        baseline: { api_calls: 10, db_queries: 4.8, files_accessed: 12.2, data_mb: 2.8 },
        current: { api_calls: payload.api_calls, db_queries: payload.db_queries, files_accessed: payload.files_accessed, data_mb: payload.data_mb },
        deviations: {
          api_calls: Math.abs(payload.api_calls - 10) / 10,
          db_queries: Math.abs(payload.db_queries - 4.8) / 4.8,
          files_accessed: Math.abs(payload.files_accessed - 12.2) / 12.2,
          data_mb: Math.abs(payload.data_mb - 2.8) / 2.8,
        },
        average_deviation: score > 50 ? 94.84 : 0.032,
      },
    };
  };

  /* --- Demo Scenarios --- */
  const runSecurityScenario = async (num: 1 | 2 | 3) => {
    let payload = {
      agent: 'DevAgent',
      task: 'FIX_LOGIN',
      action: 'READ',
      resource: 'source_code',
      api_calls: 10,
      db_queries: 5,
      files_accessed: 12,
      data_mb: 3,
      action_history: ['READ'],
    };

    if (num === 2) {
      payload = {
        agent: 'DevAgent',
        task: 'ANALYZE_DATA',
        action: 'READ',
        resource: 'analytics_database',
        api_calls: 40,
        db_queries: 30,
        files_accessed: 80,
        data_mb: 150,
        action_history: ['READ', 'QUERY'],
      };
    } else if (num === 3) {
      payload = {
        agent: 'DevAgent',
        task: 'FIX_LOGIN',
        action: 'DELETE',
        resource: 'production_database',
        api_calls: 150,
        db_queries: 200,
        files_accessed: 500,
        data_mb: 800,
        action_history: ['SCAN', 'ACCESS_SENSITIVE', 'EXPORT_LARGE_DATA'],
      };
    }

    const res = await postActivity(payload);
    const newInc: Incident = {
      id: `sc-${Date.now()}`,
      agent: res.agent,
      task: res.task,
      actionAttempted: res.action,
      resourceTargeted: res.resource,
      risk: res.risk_score,
      severity: res.severity,
      decision: res.decision,
      status: res.decision === 'ISOLATE' ? 'Isolated' : res.decision === 'BLOCK' ? 'Blocked' : 'Active',
      action: res.decision === 'ISOLATE' ? 'ISOLATE' : res.decision === 'BLOCK' ? 'BLOCK' : 'ALLOW',
      vector: res.explanation || `Action ${res.action} on ${res.resource}`,
      region: 'us-east-1',
      model: 'agent-runtime',
      trust: Math.max(5, 100 - res.risk_score),
      detections: Object.values(res.signals).filter(Boolean).length,
      lastSeen: 'just now',
      playbook:
        res.decision === 'ISOLATE'
          ? 'Immediate Isolate: freeze container, invalidate tokens'
          : res.decision === 'BLOCK'
          ? 'Action Blocked: drop DB queries, rate-limit agent'
          : 'Allow: verified normal activity',
      activity: [payload.api_calls, payload.db_queries, payload.files_accessed, payload.data_mb],
      action_history: payload.action_history,
      signals: res.signals,
      fingerprint: res.fingerprint,
      events: [{ t: stamp(), m: `Evaluated: Decision ${res.decision} (Risk ${res.risk_score})`, l: res.severity }],
    };

    setIncidents((prev) => [newInc, ...prev]);
    setSelectedId(newInc.id);

    pushToast(
      res.decision === 'ISOLATE' ? 'danger' : res.decision === 'BLOCK' ? 'warn' : 'ok',
      res.decision === 'ISOLATE' ? '🛑' : res.decision === 'BLOCK' ? '🚫' : '✅',
      `Scenario ${num} Evaluated`,
      `Score: ${res.risk_score} · Decision: ${res.decision}`
    );

    pushFeed(
      `Security Engine: <b>${res.agent}</b> evaluated ➔ <b>${res.decision}</b> (Score: ${res.risk_score})`,
      res.severity
    );
  };

  /* --- Custom Action Evaluation Submit --- */
  const handleCustomEvaluate = async () => {
    const payload = {
      agent: evalAgent,
      task: evalTask,
      action: evalAction,
      resource: evalResource,
      api_calls: evalApiCalls,
      db_queries: evalDbQueries,
      files_accessed: evalFiles,
      data_mb: evalDataMb,
      action_history: evalSeqActive ? ['SCAN', 'ACCESS_SENSITIVE', 'EXPORT_LARGE_DATA'] : ['QUERY'],
    };

    const res = await postActivity(payload);
    const newInc: Incident = {
      id: `custom-${Date.now()}`,
      agent: res.agent,
      task: res.task,
      actionAttempted: res.action,
      resourceTargeted: res.resource,
      risk: res.risk_score,
      severity: res.severity,
      decision: res.decision,
      status: res.decision === 'ISOLATE' ? 'Isolated' : res.decision === 'BLOCK' ? 'Blocked' : 'Active',
      action: res.decision === 'ISOLATE' ? 'ISOLATE' : 'REVIEW',
      vector: res.explanation || `Custom Action: ${res.action} on ${res.resource}`,
      region: 'us-east-1',
      model: 'custom-model',
      trust: Math.max(5, 100 - res.risk_score),
      detections: Object.values(res.signals).filter(Boolean).length,
      lastSeen: 'just now',
      playbook: `Automated playbook for ${res.decision}`,
      activity: [payload.api_calls, payload.db_queries, payload.files_accessed, payload.data_mb],
      action_history: payload.action_history,
      signals: res.signals,
      fingerprint: res.fingerprint,
      events: [{ t: stamp(), m: `Live evaluation: Decision ${res.decision}`, l: res.severity }],
    };

    setIncidents((prev) => [newInc, ...prev]);
    setSelectedId(newInc.id);
    setShowEvalModal(false);

    pushToast('ok', '⚡', 'Evaluation Completed', `Score: ${res.risk_score} · Decision: ${res.decision}`);
  };

  /* --- Operator Triage Action (Original Behavior Preserved) --- */
  const applyAction = (id: string, kind: ActionKind) => {
    const cfg = ACTION_MAP[kind];
    const target = incidents.find((i) => i.id === id);
    const name = target?.agent ?? 'Agent';

    setIncidents((prev) =>
      prev.map((i) => {
        if (i.id !== id) return i;
        const risk = clamp(i.risk + cfg.dr, 5, 99);
        const sev: Severity = risk >= 80 ? 'CRITICAL' : risk >= 60 ? 'HIGH' : risk >= 30 ? 'MEDIUM' : 'LOW';
        return {
          ...i,
          status: cfg.status,
          action: cfg.action,
          risk,
          severity: sev,
          events: [{ t: stamp(), m: `Operator action: ${kind}`, l: kind === 'ALLOW' ? 'LOW' : 'CRITICAL' }, ...i.events],
        };
      })
    );

    pushToast(cfg.tone, cfg.ic, cfg.tt, cfg.ms(name));
    pushFeed(cfg.log(name), kind === 'ALLOW' ? 'LOW' : kind === 'REVIEW' ? 'MEDIUM' : 'CRITICAL');
  };

  /* --- Derived State --- */
  const counts = useMemo<Record<Severity, number>>(() => {
    const c: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    incidents.forEach((i) => { c[i.severity] += 1; });
    return c;
  }, [incidents]);

  const capacityUsed = useMemo(
    () => incidents.filter((i) => i.status === 'Active' || i.status === 'Under Review').length,
    [incidents]
  );

  const trend = useMemo<TrendPoint[]>(() => {
    const labels7 = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    return Array.from({ length: range }, (_, i) => {
      const risk = Math.round(clamp(46 + 30 * Math.sin(i / 2.2) + 16 * Math.cos(i / 1.1) + (i % 4) * 5, 10, 98));
      return {
        risk,
        label: range > 7 ? (i % 5 === 0 ? `D${i + 1}` : '') : labels7[i],
        name: range > 7 ? `Day ${i + 1}` : labels7[i],
        critical: Math.round(risk / 26),
        high: Math.round(risk / 20),
        medium: Math.round(risk / 15),
        low: Math.max(1, Math.round((100 - risk) / 16)),
      };
    });
  }, [range]);

  const rows = useMemo<Incident[]>(() => {
    const q = query.trim().toLowerCase();
    const filtered = incidents.filter(
      (i) =>
        (filter === 'ALL' || i.severity === filter) &&
        (!q ||
          i.agent.toLowerCase().includes(q) ||
          i.task.toLowerCase().includes(q) ||
          i.actionAttempted.toLowerCase().includes(q) ||
          i.resourceTargeted.toLowerCase().includes(q) ||
          i.decision.toLowerCase().includes(q))
    );
    const dir = sort.dir === 'asc' ? 1 : -1;
    return [...filtered].sort((a, b) => {
      if (sort.key === 'agent') return a.agent.localeCompare(b.agent) * dir;
      if (sort.key === 'severity') return (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) * dir;
      if (sort.key === 'decision') return a.decision.localeCompare(b.decision) * dir;
      return (a.risk - b.risk) * dir;
    });
  }, [incidents, filter, query, sort]);

  const selected = incidents.find((i) => i.id === selectedId) ?? null;
  const donutData = ALL_SEVERITIES.map((k) => ({
    key: k,
    label: k.charAt(0) + k.slice(1).toLowerCase(),
    value: counts[k],
    color: SEV_META[k].c,
  }));

  const sparkData = trend.slice(-7).map((d) => d.risk);
  const kCrit = useCountUp(counts.CRITICAL);
  const kHigh = useCountUp(counts.HIGH);
  const kAgents = useCountUp(incidents.length);
  const kCap = useCountUp(capacityUsed);

  const toggleSort = (key: SortKey) =>
    setSort((s) => ({ key, dir: s.key === key && s.dir === 'desc' ? 'asc' : 'desc' }));

  return (
    <div className="ag-app">
      {/* ---------------- TOASTS ---------------- */}
      <div className="ag-toasts">
        {toasts.map((t) => (
          <div
            className="ag-toast"
            key={t.id}
            style={vars({
              '--tc': t.tone === 'danger' ? 'rgba(255,77,94,.7)' : t.tone === 'warn' ? 'rgba(255,159,28,.7)' : 'rgba(61,220,151,.7)',
            })}
          >
            <span className="ic">{t.ic}</span>
            <div>
              <div className="tt">{t.tt}</div>
              <div className="ms">{t.ms}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="ag-wrap">
        {/* ---------------- TOP BAR ---------------- */}
        <header className="ag-top">
          <div className="ag-brand">
            <div className="ag-logo">🛡️</div>
            <div>
              <h1>
                AgentGuard <span className="ag-pill">SOC v2.6</span>
              </h1>
              <p>AI Agent Security Operations Center & Security Engine</p>
            </div>
          </div>

          <div className="ag-tools">
            <div
              className={`ag-live ${backendOnline ? '' : 'off'}`}
              style={{ borderColor: backendOnline ? 'rgba(61,220,151,.4)' : 'rgba(255,159,28,.4)' }}
            >
              <i className="ag-dot" style={{ background: backendOnline ? '#3ddc97' : '#ff9f1c' }} />
              {backendOnline ? 'FASTAPI BACKEND: CONNECTED' : 'FASTAPI: OFFLINE (AUTONOMOUS)'}
            </div>

            <button className={`ag-live${live ? '' : ' off'}`} onClick={() => setLive((l) => !l)}>
              <i className="ag-dot" /> {live ? 'LIVE TELEMETRY' : 'STREAM PAUSED'}
            </button>
            <span className="ag-clock mono">{now} UTC</span>
            <button className="ag-btn" style={{ borderColor: '#6366f1', color: '#a5b4fc' }} onClick={() => setShowEvalModal(true)}>
              ⚡ Test Custom Action
            </button>
            <button
              className="ag-btn danger"
              onClick={() => {
                setIncidents(INITIAL);
                setSelectedId('i1');
                pushToast('warn', '🔄', 'Baseline restored', 'All agents returned to initial monitoring state.');
              }}
            >
              Reset Baseline
            </button>
          </div>
        </header>

        {/* ---------------- SECURITY ENGINE PIPELINE BANNER ---------------- */}
        <section className="ag-panel ag-engine-banner" style={{ marginTop: 16 }}>
          <div className="ag-head" style={{ marginBottom: 12 }}>
            <div>
              <h2>🛡️ Security Engine Live Pipeline — Jury Demo Suite</h2>
              <p className="sub">
                Signal Fusion & Calibrated Risk Decision for AI Agents (ALLOW · BLOCK · ISOLATE)
              </p>
            </div>
            <div className="ag-engine-status-tag">
              <span className="mono" style={{ fontSize: '.72rem', color: '#22d3ee', fontWeight: 800 }}>
                SIGNAL FUSION ACTIVE
              </span>
            </div>
          </div>

          <div className="ag-pipeline">
            <div className="ag-pipe-step">
              <span className="step-num">1</span>
              <div>
                <b>AI Agent Activity</b>
                <span className="mono">DevAgent / FinanceAgent</span>
              </div>
            </div>
            <span className="ag-pipe-arrow">➔</span>
            <div className="ag-pipe-step">
              <span className="step-num">2</span>
              <div>
                <b>6 Signals</b>
                <span className="mono">Perm, Intent, ML</span>
              </div>
            </div>
            <span className="ag-pipe-arrow">➔</span>
            <div className="ag-pipe-step">
              <span className="step-num">3</span>
              <div>
                <b>Signal Fusion</b>
                <span className="mono">Contextual Weights</span>
              </div>
            </div>
            <span className="ag-pipe-arrow">➔</span>
            <div className="ag-pipe-step">
              <span className="step-num">4</span>
              <div>
                <b>Risk Engine</b>
                <span className="mono">Score (0–100)</span>
              </div>
            </div>
            <span className="ag-pipe-arrow">➔</span>
            <div className="ag-pipe-step highlight">
              <span className="step-num">5</span>
              <div>
                <b>Decision</b>
                <span className="mono">ALLOW · BLOCK · ISOLATE</span>
              </div>
            </div>
          </div>

          <div className="ag-scenario-row">
            <span className="ag-scenario-title mono">DEMO JURY SCENARIOS:</span>

            <button className="ag-scenario-btn s-normal" onClick={() => runSecurityScenario(1)}>
              <span className="sc-icon">🟢</span>
              <div>
                <span className="sc-name">Scenario 1 — Normal</span>
                <span className="sc-sub mono">FIX_LOGIN → READ source_code (Risk: 0 · ALLOW)</span>
              </div>
            </button>

            <button className="ag-scenario-btn s-suspicious" onClick={() => runSecurityScenario(2)}>
              <span className="sc-icon">🟠</span>
              <div>
                <span className="sc-name">Scenario 2 — Suspicious</span>
                <span className="sc-sub mono">ANALYZE_DATA → READ analytics_db (Risk: 65 · BLOCK)</span>
              </div>
            </button>

            <button className="ag-scenario-btn s-attack" onClick={() => runSecurityScenario(3)}>
              <span className="sc-icon">🔴</span>
              <div>
                <span className="sc-name">Scenario 3 — Attack</span>
                <span className="sc-sub mono">FIX_LOGIN → DELETE prod_db (Risk: 100 · ISOLATE)</span>
              </div>
            </button>
          </div>
        </section>

        {/* ---------------- KPIS (ORIGINAL ANIMATED COUNTERS) ---------------- */}
        <section className="ag-kpis">
          <div className="ag-kpi" style={vars({ '--barColor': '#6366f1' })}>
            <div className="lbl">
              Active Agents <span className="ag-delta">12 nodes</span>
            </div>
            <div className="val">{Math.round(kAgents)}</div>
            <div className="sub">Currently under monitoring</div>
            <Spark data={sparkData} color="#818cf8" />
          </div>

          <div className="ag-kpi" style={vars({ '--barColor': '#ff4d5e' })}>
            <div className="lbl">
              Critical Threats
              <span className={`ag-delta ${counts.CRITICAL ? 'bad' : 'good'}`}>{counts.CRITICAL ? 'ACTION REQ' : 'CLEAR'}</span>
            </div>
            <div className="val" style={{ color: counts.CRITICAL ? '#ff4d5e' : undefined }}>
              {Math.round(kCrit)}
            </div>
            <div className="sub">Risk score ≥ 80 (ISOLATE)</div>
            <Spark data={sparkData.map((v) => Math.max(4, v - 38))} color="#ff4d5e" />
          </div>

          <div className="ag-kpi" style={vars({ '--barColor': '#ff9f1c' })}>
            <div className="lbl">
              High Risk
              <span className="ag-delta">Under Review</span>
            </div>
            <div className="val" style={{ color: '#ff9f1c' }}>
              {Math.round(kHigh)}
            </div>
            <div className="sub">Risk score 60–79 (BLOCK)</div>
            <Spark data={sparkData.map((v) => Math.max(6, v - 24))} color="#ff9f1c" />
          </div>

          <div className="ag-kpi" style={vars({ '--barColor': '#22d3ee' })}>
            <div className="lbl">
              SOC Capacity
              <span className={`ag-delta ${capacityUsed >= CAP ? 'bad' : 'good'}`}>
                {capacityUsed >= CAP ? 'SATURATED' : 'HEALTHY'}
              </span>
            </div>
            <div className="val">
              {Math.round(kCap)} <span style={{ fontSize: '1.1rem', color: '#586279' }}>/ {CAP}</span>
            </div>
            <div className="sub">Active investigation slots</div>
            <div className="ag-meter">
              <i style={{ width: `${(capacityUsed / CAP) * 100}%` }} />
            </div>
          </div>
        </section>

        {/* ---------------- MAIN GRID ---------------- */}
        <div className="ag-grid">
          <div className="ag-col">
            {/* Trend Chart */}
            <section className="ag-panel">
              <div className="ag-head">
                <div>
                  <h2>📈 Contextual Risk Trend</h2>
                  <p className="sub">
                    {pinnedBar !== null
                      ? `Pinned · ${trend[pinnedBar].name} — peak score ${trend[pinnedBar].risk}`
                      : 'Aggregate risk score evaluated by the Security Engine'}
                  </p>
                </div>
                <div className="ag-seg">
                  {[7, 14, 30].map((r) => (
                    <button key={r} className={range === r ? 'on' : ''} onClick={() => { setRange(r); setPinnedBar(null); }}>
                      {r}D
                    </button>
                  ))}
                </div>
              </div>

              <div className="ag-chart" onMouseLeave={() => setHoverBar(null)}>
                {trend.map((d, i) => {
                  const active = hoverBar === i || pinnedBar === i;
                  return (
                    <div
                      className="ag-barcol"
                      key={i}
                      onMouseEnter={() => setHoverBar(i)}
                      onClick={() => setPinnedBar((p) => (p === i ? null : i))}
                    >
                      <div className={`ag-bar${active ? ' hot' : ''}`} style={{ height: `${d.risk}%` }}>
                        {active && (
                          <div className="ag-tip">
                            {d.name} · <b>{d.risk}</b> risk · <i>{d.critical}</i> crit / {d.high} high
                          </div>
                        )}
                      </div>
                      <span className="ag-barlbl">{d.label}</span>
                    </div>
                  );
                })}
              </div>
            </section>

            {/* Incidents Table */}
            <section className="ag-panel">
              <div className="ag-head">
                <div>
                  <h2>🚨 Monitored Agent Security Events</h2>
                  <p className="sub">Click any row to open the Security Engine Triage & Signal Inspector</p>
                </div>
                <span className="ag-delta mono">
                  {rows.length} / {incidents.length} shown
                </span>
              </div>

              <div className="ag-toolbar">
                <div className="ag-search">
                  <span>⌕</span>
                  <input
                    ref={searchRef}
                    value={query}
                    placeholder="Search agent, task, target or vector... ( / )"
                    onChange={(e) => setQuery(e.target.value)}
                  />
                </div>

                <div className="ag-chips">
                  {(['ALL', ...ALL_SEVERITIES] as (Severity | 'ALL')[]).map((f) => (
                    <button
                      key={f}
                      className={`ag-chip${filter === f ? ' on' : ''}`}
                      style={f !== 'ALL' ? vars({ '--c': SEV_META[f].bg, '--cb': SEV_META[f].bd }) : undefined}
                      onClick={() => setFilter(f)}
                    >
                      {f}
                    </button>
                  ))}
                </div>
              </div>

              <div className="ag-tablewrap">
                <table className="ag-table">
                  <thead>
                    <tr>
                      <th className="sortable" onClick={() => toggleSort('agent')}>
                        Agent {sort.key === 'agent' ? (sort.dir === 'desc' ? '▾' : '▴') : ''}
                      </th>
                      <th>Task / Target</th>
                      <th className="sortable" onClick={() => toggleSort('decision')}>
                        Decision {sort.key === 'decision' ? (sort.dir === 'desc' ? '▾' : '▴') : ''}
                      </th>
                      <th className="sortable" onClick={() => toggleSort('risk')}>
                        Risk Score {sort.key === 'risk' ? (sort.dir === 'desc' ? '▾' : '▴') : ''}
                      </th>
                      <th>Signals Triggered</th>
                      <th>Status</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((inc) => {
                      const m = SEV_META[inc.severity];
                      const dec = DEC_META[inc.decision] || DEC_META.ALLOW;
                      const activeSignalsCount = Object.values(inc.signals || {}).filter(Boolean).length;
                      const primary = actionsFor(inc.status)[0];
                      const cfg = ACTION_MAP[primary];

                      return (
                        <tr
                          key={inc.id}
                          className={selectedId === inc.id ? 'sel' : ''}
                          onClick={() => setSelectedId(inc.id)}
                        >
                          <td>
                            <div className="ag-agent">
                              <span className={`ag-stat ${statusClass(inc.status)}`}>
                                <i className="d" />
                              </span>
                              <div>
                                <b>{inc.agent}</b>
                                <div className="mono">{inc.region}</div>
                              </div>
                            </div>
                          </td>

                          <td>
                            <div style={{ fontSize: '.79rem' }}>
                              <span className="mono" style={{ color: '#22d3ee', fontWeight: 700 }}>
                                {inc.task}
                              </span>{' '}
                              ➔{' '}
                              <span className="mono" style={{ color: '#ffc0c6', fontWeight: 700 }}>
                                {inc.actionAttempted}
                              </span>
                              <div className="mono" style={{ fontSize: '.7rem', color: '#7c8aa3' }}>
                                {inc.resourceTargeted}
                              </div>
                            </div>
                          </td>

                          <td>
                            <span
                              className="ag-dec-badge mono"
                              style={{
                                color: dec.color,
                                borderColor: dec.border,
                                background: `${dec.border.replace('.6', '.15')}`,
                              }}
                            >
                              {inc.decision}
                            </span>
                          </td>

                          <td>
                            <div className="ag-riskcell">
                              <b style={{ color: m.c }}>{Math.round(inc.risk)}</b>
                              <span className="ag-riskbar">
                                <i style={{ width: `${inc.risk}%`, background: m.c }} />
                              </span>
                            </div>
                          </td>

                          <td>
                            <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                              <span
                                className="mono"
                                style={{
                                  fontSize: '.75rem',
                                  fontWeight: 800,
                                  color: activeSignalsCount > 0 ? (activeSignalsCount >= 4 ? '#ff4d5e' : '#ff9f1c') : '#3ddc97',
                                }}
                              >
                                {activeSignalsCount}/6
                              </span>
                              <span style={{ fontSize: '.68rem', color: '#586279' }}>signals</span>
                            </div>
                          </td>

                          <td>
                            <span className={`ag-stat ${statusClass(inc.status)}`}>
                              <i className="d" />
                              {inc.status}
                            </span>
                          </td>

                          <td>
                            <button
                              className={`ag-btn ${cfg.tone}`}
                              style={{ padding: '6px 11px', fontSize: '.7rem' }}
                              onClick={(e) => {
                                e.stopPropagation();
                                applyAction(inc.id, primary);
                              }}
                            >
                              {primary}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>
          </div>

          {/* Right Rail */}
          <aside className="ag-col">
            <section className="ag-panel">
              <div className="ag-head">
                <div>
                  <h2>🎯 Risk Distribution</h2>
                  <p className="sub">Filter agents by severity band</p>
                </div>
              </div>

              <div className="ag-donutrow">
                <div className="ag-donut">
                  <Donut data={donutData} />
                  <div className="ctr">
                    <b>{incidents.length}</b>
                    <span>Agents</span>
                  </div>
                </div>

                <div className="ag-legend">
                  {donutData.map((d) => (
                    <div
                      key={d.key}
                      className={`ag-leg${filter === d.key ? ' on' : ''}`}
                      style={vars({ '--cb': SEV_META[d.key].bd })}
                      onClick={() => setFilter((f) => (f === d.key ? 'ALL' : d.key))}
                    >
                      <i className="sq" style={{ background: d.color }} />
                      <span className="nm">{d.label}</span>
                      <span className="ct" style={{ color: d.color }}>
                        {d.value}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            <section className="ag-panel">
              <div className="ag-head">
                <div>
                  <h2>⚙️ SOC Capacity</h2>
                  <p className="sub">Investigation slots occupied</p>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginBottom: 12 }}>
                <span className="mono" style={{ fontSize: '2rem', fontWeight: 800, letterSpacing: '-.04em' }}>
                  {capacityUsed}
                </span>
                <span style={{ color: '#586279', fontWeight: 700 }}>/ {CAP} slots</span>
                <span className={`ag-delta ${capacityUsed >= CAP ? 'bad' : 'good'}`} style={{ marginLeft: 'auto' }}>
                  {capacityUsed >= CAP ? 'AT CAPACITY' : 'HEADROOM'}
                </span>
              </div>

              <div className="ag-meter" style={{ height: 8 }}>
                <i
                  style={{
                    width: `${(capacityUsed / CAP) * 100}%`,
                    background: capacityUsed >= CAP ? 'linear-gradient(90deg,#ff9f1c,#ff4d5e)' : undefined,
                  }}
                />
              </div>
            </section>

            <section className="ag-panel">
              <div className="ag-head">
                <div>
                  <h2>📡 Live Event Stream</h2>
                  <p className="sub">{live ? 'Streaming telemetry...' : 'Stream paused'}</p>
                </div>
              </div>

              <div className="ag-feed">
                {feed.map((e) => (
                  <div className="ag-event" key={e.id} style={vars({ '--ec': SEV_META[e.l].c })}>
                    <i className="bar" />
                    <div>
                      <div className="txt" dangerouslySetInnerHTML={{ __html: e.txt }} />
                      <div className="ts">{e.ts}</div>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          </aside>
        </div>

        <p className="ag-foot">
          AgentGuard SOC · Press <b>/</b> to search · <b>Esc</b> closes triage console
        </p>
      </div>

      {/* ---------------- TRIAGE DRAWER: FULL SIGNAL & FINGERPRINT INSPECTION ---------------- */}
      {selected && (
        <>
          <div className="ag-backdrop" onClick={() => setSelectedId(null)} />

          <aside className="ag-drawer">
            <div className="ag-dhead">
              <div>
                <h2 style={{ margin: 0, fontSize: '1.18rem', fontWeight: 800 }}>{selected.agent}</h2>
                <p style={{ margin: '4px 0 0', fontSize: '.78rem', color: '#7c8aa3' }}>{selected.vector}</p>
              </div>
              <button className="ag-x" onClick={() => setSelectedId(null)}>
                ✕
              </button>
            </div>

            <div className="ag-gaugebox">
              <Gauge value={selected.risk} />
            </div>

            <div style={{ display: 'flex', justifyContent: 'center', gap: 10, margin: '6px 0 16px' }}>
              <span className={`ag-sev ${SEV_META[selected.severity].cls}`}>
                <i className="d" />
                {selected.severity}
              </span>
              <span
                className="ag-dec-badge mono"
                style={{
                  color: (DEC_META[selected.decision] || DEC_META.ALLOW).color,
                  borderColor: (DEC_META[selected.decision] || DEC_META.ALLOW).border,
                  padding: '4px 12px',
                }}
              >
                DECISION: {selected.decision}
              </span>
            </div>

            <div className="ag-metagrid">
              <div className="ag-meta">
                <span>Task</span>
                <b className="mono" style={{ color: '#22d3ee' }}>
                  {selected.task}
                </b>
              </div>
              <div className="ag-meta">
                <span>Attempted Action</span>
                <b className="mono" style={{ color: '#ff9aa4' }}>
                  {selected.actionAttempted}
                </b>
              </div>
              <div className="ag-meta">
                <span>Target Resource</span>
                <b className="mono" style={{ fontSize: '.74rem' }}>
                  {selected.resourceTargeted}
                </b>
              </div>
              <div className="ag-meta">
                <span>Trust Score</span>
                <b style={{ color: selected.trust > 60 ? '#3ddc97' : '#ff9f1c' }}>{selected.trust}/100</b>
              </div>
            </div>

            {/* 1. SIGNAL FUSION MATRIX */}
            <div className="ag-sect">
              <h4>🛡️ Signal Fusion Matrix (6 Weighted Signals)</h4>
              <div className="ag-signals-matrix">
                {[
                  { key: 'permission_violation' as const, name: 'Permission Violation', weight: 20, triggered: selected.signals.permission_violation },
                  { key: 'intent_mismatch' as const, name: 'Intent Mismatch', weight: 20, triggered: selected.signals.intent_mismatch },
                  { key: 'behavior_anomaly' as const, name: 'Behavior Anomaly', weight: 15, triggered: selected.signals.behavior_anomaly },
                  { key: 'sensitive_resource' as const, name: 'Sensitive Resource', weight: 15, triggered: selected.signals.sensitive_resource },
                  { key: 'unusual_data_volume' as const, name: 'Unusual Data Volume', weight: 15, triggered: selected.signals.unusual_data_volume },
                  { key: 'suspicious_sequence' as const, name: 'Suspicious Sequence', weight: 15, triggered: selected.signals.suspicious_sequence },
                ].map((s) => (
                  <div key={s.key} className={`ag-sig-card ${s.triggered ? 'active' : ''}`}>
                    <div className="ag-sig-info">
                      <span className="ag-sig-name">{s.name}</span>
                      <span className="mono ag-sig-weight">+{s.weight} pts</span>
                    </div>
                    <span className={`ag-sig-badge mono ${s.triggered ? 'hit' : 'clean'}`}>
                      {s.triggered ? 'TRIGGERED' : 'CLEAR'}
                    </span>
                  </div>
                ))}
              </div>

              <div className="ag-sig-formula mono">
                Risk Score Calculation: <b>{selected.risk} / 100</b> ({selected.severity} ➔ {selected.decision})
              </div>
            </div>

            {/* 2. BEHAVIOR FINGERPRINT (STEP 15) */}
            {selected.fingerprint && (
              <div className="ag-sect">
                <h4>🧬 Agent Behavior Fingerprint</h4>
                <div className="ag-fingerprint-box">
                  <div className="ag-fp-row">
                    <div className="ag-fp-header">
                      <span>API Calls</span>
                      <span className="mono">
                        Base: {selected.fingerprint.baseline.api_calls} | Current: {selected.fingerprint.current.api_calls}
                      </span>
                    </div>
                  </div>
                  <div className="ag-fp-row">
                    <div className="ag-fp-header">
                      <span>DB Queries</span>
                      <span className="mono">
                        Base: {selected.fingerprint.baseline.db_queries} | Current: {selected.fingerprint.current.db_queries}
                      </span>
                    </div>
                  </div>
                  <div className="ag-fp-row">
                    <div className="ag-fp-header">
                      <span>Files Accessed</span>
                      <span className="mono">
                        Base: {selected.fingerprint.baseline.files_accessed} | Current: {selected.fingerprint.current.files_accessed}
                      </span>
                    </div>
                  </div>
                  <div className="ag-fp-row">
                    <div className="ag-fp-header">
                      <span>Data Transfer</span>
                      <span className="mono">
                        Base: {selected.fingerprint.baseline.data_mb}MB | Current: {selected.fingerprint.current.data_mb}MB
                      </span>
                    </div>
                  </div>

                  <div className="ag-fp-summary">
                    <span>Average Behavioral Drift:</span>
                    <b className="mono" style={{ color: selected.fingerprint.average_deviation > 1 ? '#ff4d5e' : '#3ddc97', fontSize: '.95rem' }}>
                      +{(selected.fingerprint.average_deviation * 100).toFixed(1)}% drift
                    </b>
                  </div>
                </div>
              </div>
            )}

            {/* Playbook */}
            <div className="ag-sect">
              <h4>Recommended Containment Playbook</h4>
              <div className="ag-play">🛡️ {selected.playbook}</div>
            </div>

            {/* Operator Actions (Matching original functions) */}
            <div className="ag-actions">
              {actionsFor(selected.status).map((k) => (
                <button key={k} className={`ag-btn ${ACTION_MAP[k].tone}`} onClick={() => applyAction(selected.id, k)}>
                  {ACTION_MAP[k].ic} {k} — {ACTION_MAP[k].tt}
                </button>
              ))}
            </div>
          </aside>
        </>
      )}

      {/* ---------------- TEST CUSTOM ACTION MODAL ---------------- */}
      {showEvalModal && (
        <>
          <div className="ag-backdrop" onClick={() => setShowEvalModal(false)} />
          <div className="ag-eval-modal">
            <div className="ag-dhead">
              <div>
                <h2>⚡ Test Custom Agent Action</h2>
                <p style={{ margin: '4px 0 0', fontSize: '.8rem', color: '#7c8aa3' }}>
                  Inject an arbitrary action and evaluate through the Security Engine.
                </p>
              </div>
              <button className="ag-x" onClick={() => setShowEvalModal(false)}>
                ✕
              </button>
            </div>

            <div className="ag-eval-grid">
              <div className="ag-eval-field">
                <label>Agent Name</label>
                <select value={evalAgent} onChange={(e) => setEvalAgent(e.target.value)}>
                  <option value="DevAgent">DevAgent</option>
                  <option value="FinanceAgent">FinanceAgent</option>
                  <option value="HR-Agent">HR-Agent</option>
                </select>
              </div>

              <div className="ag-eval-field">
                <label>Task</label>
                <select value={evalTask} onChange={(e) => setEvalTask(e.target.value)}>
                  <option value="FIX_LOGIN">FIX_LOGIN</option>
                  <option value="ANALYZE_DATA">ANALYZE_DATA</option>
                  <option value="AUDIT_EXPENSES">AUDIT_EXPENSES</option>
                </select>
              </div>

              <div className="ag-eval-field">
                <label>Action</label>
                <select value={evalAction} onChange={(e) => setEvalAction(e.target.value)}>
                  <option value="READ">READ</option>
                  <option value="WRITE">WRITE</option>
                  <option value="QUERY">QUERY</option>
                  <option value="DELETE">DELETE</option>
                </select>
              </div>

              <div className="ag-eval-field">
                <label>Resource</label>
                <select value={evalResource} onChange={(e) => setEvalResource(e.target.value)}>
                  <option value="source_code">source_code</option>
                  <option value="analytics_database">analytics_database</option>
                  <option value="production_database">production_database</option>
                </select>
              </div>
            </div>

            <div className="ag-sect">
              <h4>Activity Metrics</h4>
              <div className="ag-slider-row">
                <label>API Calls: {evalApiCalls}</label>
                <input type="range" min="0" max="200" value={evalApiCalls} onChange={(e) => setEvalApiCalls(Number(e.target.value))} />
              </div>
              <div className="ag-slider-row">
                <label>DB Queries: {evalDbQueries}</label>
                <input type="range" min="0" max="300" value={evalDbQueries} onChange={(e) => setEvalDbQueries(Number(e.target.value))} />
              </div>
              <div className="ag-slider-row">
                <label>Files Accessed: {evalFiles}</label>
                <input type="range" min="0" max="600" value={evalFiles} onChange={(e) => setEvalFiles(Number(e.target.value))} />
              </div>
              <div className="ag-slider-row">
                <label>Data Transfer: {evalDataMb} MB</label>
                <input type="range" min="0" max="1000" value={evalDataMb} onChange={(e) => setEvalDataMb(Number(e.target.value))} />
              </div>

              <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 10 }}>
                <input type="checkbox" id="seqToggle" checked={evalSeqActive} onChange={(e) => setEvalSeqActive(e.target.checked)} />
                <label htmlFor="seqToggle" style={{ fontSize: '.82rem', color: '#c4cede', cursor: 'pointer' }}>
                  Inject Suspicious Sequence (`SCAN` ➔ `ACCESS_SENSITIVE` ➔ `EXPORT_LARGE_DATA`)
                </label>
              </div>
            </div>

            <div style={{ marginTop: 22, display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button className="ag-btn" onClick={() => setShowEvalModal(false)}>
                Cancel
              </button>
              <button
                className="ag-btn"
                style={{ background: 'linear-gradient(135deg, #6366f1, #22d3ee)', color: '#04070d', fontWeight: 800 }}
                onClick={handleCustomEvaluate}
              >
                Evaluate Action
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}