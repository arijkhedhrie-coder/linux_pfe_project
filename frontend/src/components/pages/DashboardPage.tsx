import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { useDashboardData } from "../../hooks/UseDashboardData";
import { Sidebar } from "../../components/dashboard/sidebar";
import { TopBar } from "../../components/dashboard/topBar";
import { KpiCard } from "../../components/dashboard/KpiCard";
import { AlertsTable } from "../../components/dashboard/AlertsTable";
import { SshChart } from "../../components/dashboard/SshChart";
import { RiskGauge } from "../../components/dashboard/RiskGauge";

const layerLabels: Record<string, string> = {
  post_breach: "Post-Breach",
  privilege_escalation: "Priv. Escalation",
  root_abuse: "Root Abuse",
  behavioral_deviation: "Déviation Comportementale",
  combined_risk: "Risque Combiné",
};

export const DashboardPage = () => {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [activeSection, setActiveSection] = useState("overview");

  // Get token from localStorage
  const token = localStorage.getItem("token") || undefined;
  const { metrics, stats, alerts, sshHistory, isLive, lastUpdate, loading } = useDashboardData(token);

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  // Get username from localStorage or context
  const username = localStorage.getItem("username") || "admin";

  return (
    <div style={{
      display: "flex",
      minHeight: "100vh",
      background: "#080c18",
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
    }}>
      <style>{`
        @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.5;transform:scale(0.8)} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(0,212,255,0.2); border-radius: 2px; }
      `}</style>

      <Sidebar
        activeSection={activeSection}
        onSectionChange={setActiveSection}
        username={username}
        onLogout={handleLogout}
      />

      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <TopBar isLive={isLive} lastUpdate={lastUpdate} totalEvents={stats.total_events} />

        <main style={{
          flex: 1,
          overflow: "auto",
          padding: "24px",
          animation: "fadeIn 0.4s ease",
        }}>
          {loading ? (
            <div style={{
              display: "flex", alignItems: "center", justifyContent: "center",
              height: "300px", color: "rgba(0,212,255,0.5)", fontSize: "13px", letterSpacing: "0.1em",
            }}>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: "32px", marginBottom: "16px", animation: "pulse 1.5s infinite" }}>◎</div>
                INITIALISATION DU SYSTÈME...
              </div>
            </div>
          ) : (
            <>
              {/* ── Vue d'ensemble ── */}
              {activeSection === "overview" && (
                <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
                  {/* KPI Grid */}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))", gap: "12px" }}>
                    <KpiCard label="Tentatives SSH" value={metrics.tentatives_ssh} icon="🔐" color="#ff3b30" alert={metrics.tentatives_ssh > 100} />
                    <KpiCard label="Connexions OK" value={metrics.connexions_ok} icon="✓" color="#30d158" />
                    <KpiCard label="Users Invalides" value={metrics.invalid_user} icon="✗" color="#ff9f0a" alert={metrics.invalid_user > 20} />
                    <KpiCard label="Tentatives Root" value={metrics.tentatives_root} icon="⚡" color="#ff3b30" alert={metrics.tentatives_root > 10} />
                    <KpiCard label="Cmds Sudo" value={metrics.sudo_cmds} icon="⌘" color="#bf5af2" />
                    <KpiCard label="Erreurs Système" value={metrics.erreurs_sys} icon="⚠" color="#ff9f0a" />
                    <KpiCard label="Warnings" value={metrics.warnings_sys} icon="△" color="#ffd60a" />
                    <KpiCard label="Erreurs Kernel" value={metrics.erreurs_kernel} icon="◈" color="#ff453a" alert={metrics.erreurs_kernel > 0} />
                  </div>

                  {/* Score + Chart */}
                  <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: "16px" }}>
                    <RiskGauge score={stats.overall_score} status={stats.status} />
                    <SshChart data={sshHistory} />
                  </div>

                  {/* Layer Scores */}
                  <div style={{
                    background: "linear-gradient(135deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01))",
                    border: "1px solid rgba(255,255,255,0.07)",
                    borderRadius: "12px", padding: "20px",
                  }}>
                    <div style={{ color: "#fff", fontWeight: 600, fontSize: "13px", letterSpacing: "0.05em", marginBottom: "16px" }}>
                      ⬡ SCORES PAR COUCHE DE DÉTECTION
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                      {Object.entries(stats.layer_scores).map(([key, val]) => {
                        const color = val > 70 ? "#ff3b30" : val > 50 ? "#ff9f0a" : "#30d158";
                        return (
                          <div key={key} style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                            <div style={{ width: "180px", color: "rgba(255,255,255,0.4)", fontSize: "11px", flexShrink: 0 }}>
                              {layerLabels[key] || key}
                            </div>
                            <div style={{ flex: 1, height: "6px", background: "rgba(255,255,255,0.06)", borderRadius: "3px", overflow: "hidden" }}>
                              <div style={{
                                height: "100%", width: `${val}%`,
                                background: `linear-gradient(90deg, ${color}88, ${color})`,
                                borderRadius: "3px",
                                transition: "width 1s ease",
                              }} />
                            </div>
                            <div style={{ color, fontSize: "12px", fontFamily: "monospace", fontWeight: 700, width: "36px", textAlign: "right" }}>
                              {val}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Alerts preview */}
                  <AlertsTable alerts={alerts.slice(0, 4)} />
                </div>
              )}

              {/* ── SSH Section ── */}
              {activeSection === "ssh" && (
                <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
                  <SshChart data={sshHistory} />
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "12px" }}>
                    <KpiCard label="Tentatives SSH" value={metrics.tentatives_ssh} icon="🔐" color="#ff3b30" sub="Dernière minute" alert />
                    <KpiCard label="Connexions Réussies" value={metrics.connexions_ok} icon="✓" color="#30d158" sub="Sessions actives" />
                    <KpiCard label="Utilisateurs Invalides" value={metrics.invalid_user} icon="✗" color="#ff9f0a" sub="Inconnus refusés" />
                  </div>
                </div>
              )}

              {/* ── Alertes ── */}
              {activeSection === "alerts" && (
                <AlertsTable alerts={alerts} />
              )}

              {/* ── Kernel ── */}
              {activeSection === "kernel" && (
                <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: "12px" }}>
                    <KpiCard label="Erreurs Kernel" value={metrics.erreurs_kernel} icon="◈" color="#ff453a" alert={metrics.erreurs_kernel > 0} sub="dmesg errors" />
                    <KpiCard label="Erreurs Système" value={metrics.erreurs_sys} icon="⚠" color="#ff9f0a" sub="syslog errors" />
                    <KpiCard label="Warnings" value={metrics.warnings_sys} icon="△" color="#ffd60a" sub="syslog warnings" />
                  </div>
                  <div style={{
                    background: "rgba(255,59,48,0.05)", border: "1px solid rgba(255,59,48,0.15)",
                    borderRadius: "12px", padding: "20px",
                    color: "rgba(255,255,255,0.4)", fontSize: "12px", fontFamily: "monospace",
                    lineHeight: "1.8",
                  }}>
                    <div style={{ color: "#ff3b30", marginBottom: "12px", fontWeight: 600 }}>◈ LOG KERNEL SIMULÉ</div>
                    {[
                      "[kernel] EXT4-fs error: device sda1, io error",
                      "[kernel] oom-killer: Memory limit reached",
                      "[systemd] Failed to start NetworkManager.service",
                      "[audit] SYSCALL arch=0x3e syscall=59 success=yes",
                      "[kernel] TCP: out of memory -- consider tuning tcp_mem",
                    ].map((line, i) => (
                      <div key={i} style={{ marginBottom: "4px" }}>
                        <span style={{ color: "rgba(0,212,255,0.4)" }}>[{new Date().toLocaleTimeString("fr-FR")}]</span> {line}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ── Sessions ── */}
              {activeSection === "sessions" && (
                <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "12px" }}>
                    <KpiCard label="Tentatives Root" value={metrics.tentatives_root} icon="⚡" color="#ff3b30" alert sub="su / sudo su" />
                    <KpiCard label="Commandes Sudo" value={metrics.sudo_cmds} icon="⌘" color="#bf5af2" sub="privilèges élevés" />
                  </div>
                  <RiskGauge score={stats.overall_score} status={stats.status} />
                </div>
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
};
