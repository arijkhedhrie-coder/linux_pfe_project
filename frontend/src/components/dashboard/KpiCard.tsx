interface KpiCardProps {
  label: string;
  value: number | string;
  icon: string;
  color: string;
  sub?: string;
  alert?: boolean;
}

export const KpiCard = ({ label, value, icon, color, sub, alert }: KpiCardProps) => (
  <div style={{
    background: "linear-gradient(135deg, rgba(255,255,255,0.04) 0%, rgba(255,255,255,0.01) 100%)",
    border: `1px solid ${alert ? "rgba(255,59,48,0.35)" : "rgba(255,255,255,0.07)"}`,
    borderRadius: "12px",
    padding: "20px",
    position: "relative",
    overflow: "hidden",
    transition: "transform 0.2s, border-color 0.2s",
  }}>
    {/* Glow */}
    <div style={{
      position: "absolute", top: 0, right: 0,
      width: "80px", height: "80px",
      background: `radial-gradient(circle, ${color}22 0%, transparent 70%)`,
      borderRadius: "0 12px 0 100%",
    }} />
    {/* Alert pulse */}
    {alert && (
      <div style={{
        position: "absolute", top: "12px", right: "12px",
        width: "8px", height: "8px", borderRadius: "50%",
        background: "#ff3b30",
        boxShadow: "0 0 8px #ff3b30",
        animation: "pulse 1.5s infinite",
      }} />
    )}
    <div style={{ fontSize: "22px", marginBottom: "10px" }}>{icon}</div>
    <div style={{ color, fontSize: "28px", fontWeight: 700, fontFamily: "monospace", lineHeight: 1 }}>
      {value}
    </div>
    <div style={{ color: "rgba(255,255,255,0.5)", fontSize: "11px", marginTop: "6px", letterSpacing: "0.06em", textTransform: "uppercase" }}>
      {label}
    </div>
    {sub && (
      <div style={{ color: "rgba(255,255,255,0.3)", fontSize: "10px", marginTop: "4px" }}>{sub}</div>
    )}
  </div>
);
