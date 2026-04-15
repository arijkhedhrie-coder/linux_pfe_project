import { useState, useEffect, useCallback, useRef } from "react";
import {
  fetchLiveMetrics,
  fetchDashboardStats,
  getMockLiveMetrics,
  getMockStats,
  type LiveMetrics,
  type DashboardStats,
  type Alert,
} from "../api/dashboardApi";

const POLL_INTERVAL = 5000; // 5 secondes

export interface SshDataPoint {
  time: string;
  tentatives: number;
  connexions: number;
  invalides: number;
}

export interface DashboardData {
  metrics: LiveMetrics;
  stats: DashboardStats;
  alerts: Alert[];
  sshHistory: SshDataPoint[];
  isLive: boolean;
  lastUpdate: Date;
  loading: boolean;
}

export const useDashboardData = (token?: string): DashboardData => {
  const [metrics, setMetrics] = useState<LiveMetrics>(getMockLiveMetrics());
  const [stats, setStats] = useState<DashboardStats>(getMockStats());
  const [sshHistory, setSshHistory] = useState<SshDataPoint[]>([]);
  const [isLive, setIsLive] = useState(false);
  const [lastUpdate, setLastUpdate] = useState(new Date());
  const [loading, setLoading] = useState(true);
  const historyRef = useRef<SshDataPoint[]>([]);

  const buildHistoryPoint = useCallback((m: LiveMetrics): SshDataPoint => {
    const now = new Date();
    return {
      time: `${now.getHours().toString().padStart(2, "0")}:${now
        .getMinutes()
        .toString()
        .padStart(2, "0")}:${now.getSeconds().toString().padStart(2, "0")}`,
      tentatives: m.tentatives_ssh,
      connexions: m.connexions_ok,
      invalides: m.invalid_user,
    };
  }, []);

  const refresh = useCallback(async () => {
    const [liveData, statsData] = await Promise.all([
      fetchLiveMetrics(),
      token ? fetchDashboardStats(token) : Promise.resolve(getMockStats()),
    ]);

    setMetrics(liveData);
    setStats(statsData);
    setIsLive(liveData.source === "reel");
    setLastUpdate(new Date());
    setLoading(false);

    const point = buildHistoryPoint(liveData);
    historyRef.current = [...historyRef.current.slice(-19), point];
    setSshHistory([...historyRef.current]);
  }, [token, buildHistoryPoint]);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [refresh]);

  return {
    metrics,
    stats,
    alerts: stats.alarms,
    sshHistory,
    isLive,
    lastUpdate,
    loading,
  };
};