import axios from "axios";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

export interface LiveMetrics {
  tentatives_ssh: number;
  connexions_ok: number;
  invalid_user: number;
  tentatives_root: number;
  sudo_cmds: number;
  erreurs_sys: number;
  warnings_sys: number;
  erreurs_kernel: number;
  source: "reel" | "simulation";
}

export interface Alert {
  timestamp: string;
  type: string;
  ip: string;
  severite: "CRITIQUE" | "AVERTISSEMENT" | "NORMAL";
  action: string;
  score: number;
  message: string;
  domain: string;
}

export interface DashboardStats {
  overall_score: number;
  status: "CRITIQUE" | "AVERTISSEMENT" | "NORMAL";
  layer_scores: {
    post_breach: number;
    privilege_escalation: number;
    root_abuse: number;
    behavioral_deviation: number;
    combined_risk: number;
  };
  alarms: Alert[];
  total_events: number;
}

// ── Mock data (utilisé si le backend n'est pas disponible) ──
export const getMockLiveMetrics = (): LiveMetrics => ({
  tentatives_ssh: Math.floor(Math.random() * 40 + 120),
  connexions_ok: Math.floor(Math.random() * 10 + 8),
  invalid_user: Math.floor(Math.random() * 20 + 30),
  tentatives_root: Math.floor(Math.random() * 15 + 5),
  sudo_cmds: Math.floor(Math.random() * 8 + 2),
  erreurs_sys: Math.floor(Math.random() * 5 + 1),
  warnings_sys: Math.floor(Math.random() * 12 + 4),
  erreurs_kernel: Math.floor(Math.random() * 3),
  source: "simulation",
});

export const getMockStats = (): DashboardStats => ({
  overall_score: 72.4,
  status: "CRITIQUE",
  layer_scores: {
    post_breach: 85,
    privilege_escalation: 62,
    root_abuse: 40,
    behavioral_deviation: 55,
    combined_risk: 78,
  },
  alarms: [
    {
      timestamp: new Date().toISOString(),
      type: "BRUTE_FORCE_SSH",
      ip: "192.168.1.45",
      severite: "CRITIQUE",
      action: "BLOCK_24H",
      score: 91.2,
      message: "🔴 BRUTE FORCE SSH | 143 tentatives | IP: 192.168.1.45",
      domain: "SSH",
    },
    {
      timestamp: new Date(Date.now() - 120000).toISOString(),
      type: "PRIVILEGE_ESCALATION",
      ip: "local",
      severite: "CRITIQUE",
      action: "BLOCK_24H",
      score: 76.5,
      message: "🟠 PRIVILEGE ESCALATION | sudo su, chmod 777 | Score: 76/100",
      domain: "SESSION",
    },
    {
      timestamp: new Date(Date.now() - 300000).toISOString(),
      type: "BEHAVIORAL_ANOMALY",
      ip: "10.0.0.12",
      severite: "AVERTISSEMENT",
      action: "WATCHLIST_30MIN",
      score: 48.3,
      message: "🟡 BEHAVIORAL ANOMALY | 2 user(s) | Score: 48/100",
      domain: "SESSION",
    },
    {
      timestamp: new Date(Date.now() - 600000).toISOString(),
      type: "PORT_SCAN",
      ip: "172.16.0.5",
      severite: "AVERTISSEMENT",
      action: "WATCHLIST_30MIN",
      score: 39.1,
      message: "🟡 PORT SCAN NMAP | 256 ports scannés | IP: 172.16.0.5",
      domain: "NETWORK",
    },
  ],
  total_events: 1847,
});

// ── Appels API réels (avec fallback mock) ──────────────────
export const fetchLiveMetrics = async (): Promise<LiveMetrics> => {
  try {
    const res = await axios.get(`${API_BASE}/live`, { timeout: 2000 });
    return res.data;
  } catch {
    return getMockLiveMetrics();
  }
};

export const fetchDashboardStats = async (token: string): Promise<DashboardStats> => {
  try {
    const res = await axios.get(`${API_BASE}/dashboard/stats`, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: 3000,
    });
    return res.data;
  } catch {
    return getMockStats();
  }
};