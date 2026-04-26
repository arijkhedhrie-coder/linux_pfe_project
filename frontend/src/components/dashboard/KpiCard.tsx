// src/components/dashboard/KpiCard.tsx
import type { FC } from "react";
import '../../style/KpiCard.css';

interface Props {
  label: string;
  value: string | number;
  sub?: string;
  color?: "green" | "red" | "amber" | "default";
}

const colors = { green: "#0F6E56", red: "#A32D2D", amber: "#854F0B", default: "var(--text)" };

export const KpiCard: FC<Props> = ({ label, value, sub, color = "default" }) => (
  <div style={{ background: "var(--card, #fff)", border: "0.5px solid var(--border, #e5e7eb)", borderRadius: 8, padding: "10px 12px" }}>
    <div style={{ fontSize: 10, color: "var(--muted, #6b7280)", marginBottom: 4, textTransform: "uppercase", letterSpacing: ".06em" }}>{label}</div>
    <div style={{ fontSize: 22, fontWeight: 500, color: colors[color], lineHeight: 1 }}>{value}</div>
    {sub && <div style={{ fontSize: 10, color: "var(--muted, #6b7280)", marginTop: 4 }}>{sub}</div>}
  </div>
);
kpicard.tsx
// src/components/dashboard/Sidebar.tsx
import type { FC } from "react";
import '../../style/Sidebar.css';

interface Props {
  activeSection: "dashboard" | "track";
  onSectionChange: (s: "dashboard" | "track") => void;
  username: string;
  onLogout: () => void;
  sessionStats?: { session: number; logsAnalysed: number; lastUpdate: string; threat: string };
}

export const Sidebar: FC<Props> = ({
  activeSection, onSectionChange, username,
  sessionStats = { session: 36, logsAnalysed: 31322, lastUpdate: "02:47:33", threat: "ELEVATED" }
}) => {
  const s: React.CSSProperties = {
    width: 220, background: "var(--card, #fff)", borderRight: "0.5px solid var(--border, #e5e7eb)",
    display: "flex", flexDirection: "column", flexShrink: 0, height: "100vh", position: "sticky", top: 0
  };
  const navBtn = (active: boolean): React.CSSProperties => ({
    display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "9px 10px",
    borderRadius: 8, border: "none", cursor: "pointer", fontSize: 12, fontFamily: "inherit",
    textAlign: "left", marginBottom: 2, transition: "background .15s, color .15s",
    background: active ? "#E1F5EE" : "transparent",
    color: active ? "#0F6E56" : "var(--muted, #6b7280)",
    fontWeight: active ? 500 : 400,
  });
  const iconBox = (active: boolean): React.CSSProperties => ({
    width: 24, height: 24, borderRadius: 6, display: "flex", alignItems: "center",
    justifyContent: "center", flexShrink: 0,
    background: active ? "#0F6E56" : "var(--color-background-secondary, #f3f4f6)",
  });

  return (
    <div style={s}>
      {/* Logo */}
      <div style={{ padding: "16px 16px 12px", borderBottom: "0.5px solid var(--border, #e5e7eb)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 28, height: 28, borderRadius: 6, background: "#0F6E56", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <svg viewBox="0 0 16 16" width={16} height={16} fill="none" stroke="#9FE1CB" strokeWidth="1.5" strokeLinecap="round">
              <rect x="2" y="2" width="5" height="5" rx="1"/><rect x="9" y="2" width="5" height="5" rx="1"/>
              <rect x="2" y="9" width="5" height="5" rx="1"/><rect x="9" y="9" width="5" height="5" rx="1"/>
            </svg>
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 500 }}>IDPS — SOC</div>
            <div style={{ fontSize: 10, color: "var(--muted, #6b7280)" }}>v2.4 · Pipeline actif</div>
          </div>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#1D9E75", marginLeft: "auto", animation: "pulse-dot 2s ease-in-out infinite" }} />
        </div>
      </div>

      {/* Nav */}
      <div style={{ padding: "12px 8px", flex: 1 }}>
        <div style={{ fontSize: 10, color: "var(--muted, #6b7280)", textTransform: "uppercase", letterSpacing: ".08em", padding: "0 8px 6px" }}>Navigation</div>

        <button style={navBtn(activeSection === "track")} onClick={() => onSectionChange("track")}>
          <div style={iconBox(activeSection === "track")}>
            <svg viewBox="0 0 14 14" width={13} height={13} fill="none" stroke={activeSection === "track" ? "#9FE1CB" : "currentColor"} strokeWidth="1.5" strokeLinecap="round">
              <rect x="1" y="1" width="5" height="5" rx="1.5"/><rect x="8" y="1" width="5" height="5" rx="1.5"/>
              <rect x="1" y="8" width="5" height="5" rx="1.5"/><rect x="8" y="8" width="5" height="5" rx="1.5"/>
            </svg>
          </div>
          Track Servers
          <span style={{ marginLeft: "auto", fontSize: 10, padding: "1px 6px", borderRadius: 20, background: "#E1F5EE", color: "#0F6E56", fontWeight: 500 }}>3</span>
        </button>

        <button style={navBtn(activeSection === "dashboard")} onClick={() => onSectionChange("dashboard")}>
          <div style={iconBox(activeSection === "dashboard")}>
            <svg viewBox="0 0 14 14" width={13} height={13} fill="none" stroke={activeSection === "dashboard" ? "#9FE1CB" : "currentColor"} strokeWidth="1.5" strokeLinecap="round">
              <path d="M1 10L4 7l2 2 3-4 3 3"/>
            </svg>
          </div>
          Dashboard
          <span style={{ marginLeft: "auto", fontSize: 10, padding: "1px 6px", borderRadius: 20, background: "#FCEBEB", color: "#A32D2D", fontWeight: 500 }}>3</span>
        </button>

        <div style={{ marginTop: 16 }}>
          <div style={{ fontSize: 10, color: "var(--muted, #6b7280)", textTransform: "uppercase", letterSpacing: ".08em", padding: "0 8px 6px" }}>Agents</div>
          <button style={navBtn(false)}>
            <div style={iconBox(false)}>
              <svg viewBox="0 0 14 14" width={13} height={13} fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                <circle cx="7" cy="4" r="2"/><path d="M3 11c0-2.2 1.8-4 4-4s4 1.8 4 4"/>
              </svg>
            </div>
            Agents CrewAI
          </button>
          <button style={navBtn(false)}>
            <div style={iconBox(false)}>
              <svg viewBox="0 0 14 14" width={13} height={13} fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                <path d="M7 1l1.5 3 3.5.5-2.5 2.5.6 3.5L7 9l-3.1 1.5.6-3.5L2 4.5 5.5 4z"/>
              </svg>
            </div>
            Trust Gate
          </button>
        </div>
      </div>

      {/* Footer */}
      <div style={{ padding: "12px 16px", borderTop: "0.5px solid var(--border, #e5e7eb)", fontSize: 10, color: "var(--muted, #6b7280)", lineHeight: 1.8 }}>
        Session <span style={{ color: "var(--text)", fontWeight: 500 }}>#{sessionStats.session}</span><br/>
        Logs analysés <span style={{ color: "var(--text)", fontWeight: 500 }}>{sessionStats.logsAnalysed.toLocaleString()}</span><br/>
        Dernière MAJ <span style={{ color: "var(--text)", fontWeight: 500 }}>{sessionStats.lastUpdate}</span><br/>
        Threat <span style={{ color: "#A32D2D", fontWeight: 500 }}>{sessionStats.threat}</span>
      </div>

      <style>{`@keyframes pulse-dot { 0%,100%{opacity:1} 50%{opacity:.4} }`}</style>
    </div>
  );
};