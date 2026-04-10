import { useEffect, useRef, useState } from "react"

// ─── Types ────────────────────────────────────────────────────────────────────
interface KPI { cpu_load: number; ssh_failures: number; active_connections: number; error_rate: number }
interface Alert { timestamp: string; type: string; source_ip: string; severity: string; message: string }
interface Report { summary: string; agents: string[]; recommendation: string }

// ─── Mock hooks (replace with your real hooks) ────────────────────────────────
function useKPIs(): KPI { return { cpu_load: 92.4, ssh_failures: 4, active_connections: 110, error_rate: 0 } }
function useAlerts(): Alert[] {
  return [
    { timestamp: "23:14:02", type: "BRUTE-FORCE SSH", source_ip: "192.168.1.55", severity: "HIGH", message: "68.5 failed attempts/min" },
    { timestamp: "23:13:45", type: "WEB_ENUMERATION", source_ip: "10.0.0.10", severity: "MED", message: "81.0 suspicious paths" },
    { timestamp: "23:12:11", type: "BRUTE-FORCE SSH", source_ip: "192.168.1.55", severity: "HIGH", message: "68.5 failed attempts/min" },
  ]
}
function useReport(): Report {
  return { summary: "System under active brute-force attack", agents: ["SSH", "WEB", "FTP", "KERNEL"], recommendation: "Block 192.168.1.55 immediately" }
}

// ─── Gauge Component ──────────────────────────────────────────────────────────
function Gauge({ value, max, color, label, sublabel }: { value: number; max: number; color: string; label: string; sublabel?: string }) {
  const r = 52, cx = 70, cy = 70
  const startAngle = -220, endAngle = 40
  const totalArc = endAngle - startAngle
  const pct = Math.min(value / max, 1)
  const filled = pct * totalArc
  const toRad = (d: number) => (d * Math.PI) / 180
  const arcPath = (start: number, end: number) => {
    const s = toRad(start), e = toRad(end)
    const x1 = cx + r * Math.cos(s), y1 = cy + r * Math.sin(s)
    const x2 = cx + r * Math.cos(e), y2 = cy + r * Math.sin(e)
    const large = end - start > 180 ? 1 : 0
    return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
      <svg width={140} height={100} viewBox="0 0 140 100">
        <path d={arcPath(startAngle, endAngle)} fill="none" stroke="#1e2a1e" strokeWidth={8} strokeLinecap="round" />
        {pct > 0 && <path d={arcPath(startAngle, startAngle + filled)} fill="none" stroke={color} strokeWidth={8} strokeLinecap="round" />}
        <text x={cx} y={cy - 4} textAnchor="middle" fill="white" fontSize={22} fontWeight="700" fontFamily="monospace">{value}</text>
        {sublabel && <text x={cx} y={cy + 12} textAnchor="middle" fill="#6b7c6b" fontSize={9} fontFamily="monospace">{sublabel}</text>}
      </svg>
      <span style={{ color: "#8a9e8a", fontSize: 10, letterSpacing: 2, textTransform: "uppercase", marginTop: -8 }}>{label}</span>
    </div>
  )
}

// ─── Mini area chart using SVG ────────────────────────────────────────────────
function AreaChart() {
  const W = 660, H = 160
  const datasets = [
    { color: "#3b9ef8", data: [40,55,80,110,90,140,170,200,150,180,160,130,100,80,60,90,110,130,150,170,190,210,190,170] },
    { color: "#e05252", data: [20,30,50,70,60,90,100,130,100,120,110,90,70,50,40,60,80,100,110,120,130,140,130,110] },
    { color: "#9b59b6", data: [10,15,25,35,30,45,50,65,50,60,55,45,35,25,20,30,40,50,55,60,65,70,65,55] },
    { color: "#e0525b", data: [5,10,15,20,18,25,30,35,25,30,28,22,18,14,10,18,22,28,30,35,38,42,38,32] },
  ]
  const allVals = datasets.flatMap(d => d.data)
  const maxV = Math.max(...allVals)
  const scaleY = (v: number) => H - 10 - (v / maxV) * (H - 20)
  const scaleX = (i: number, len: number) => (i / (len - 1)) * W
  const toPath = (data: number[]) => data.map((v, i) => `${i === 0 ? "M" : "L"} ${scaleX(i, data.length)} ${scaleY(v)}`).join(" ")
  const toArea = (data: number[]) => toPath(data) + ` L ${scaleX(data.length - 1, data.length)} ${H} L 0 ${H} Z`

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ display: "block" }}>
      {[0, 50, 100, 150, 200].map(v => (
        <line key={v} x1={0} x2={W} y1={scaleY(v)} y2={scaleY(v)} stroke="#1e2a1e" strokeWidth={1} />
      ))}
      {datasets.map((ds, i) => (
        <g key={i}>
          <path d={toArea(ds.data)} fill={ds.color} fillOpacity={0.15} />
          <path d={toPath(ds.data)} fill="none" stroke={ds.color} strokeWidth={2} />
        </g>
      ))}
      {[0, 50, 100, 150, 200].map(v => (
        <text key={v} x={4} y={scaleY(v) - 3} fill="#4a5a4a" fontSize={9} fontFamily="monospace">{v}</text>
      ))}
      {["24 hr", "6 hr", "12 hr", "18 hr", "24 hr"].map((t, i) => (
        <text key={i} x={(i / 4) * W} y={H - 2} fill="#4a5a4a" fontSize={9} fontFamily="monospace" textAnchor="middle">{t}</text>
      ))}
    </svg>
  )
}

// ─── Risk Score Bar Chart ─────────────────────────────────────────────────────
function RiskBars() {
  const bars = [
    { label: "SSH", score: 5.0, color: "#3b9ef8" },
    { label: "WEB", score: 2.8, color: "#f5a623" },
    { label: "FTP", score: 7.0, color: "#3b9ef8" },
    { label: "SESSION", score: 3.0, color: "#e8575a" },
    { label: "KERNEL", score: 1.5, color: "#e85a8a" },
    { label: "PREDICTION", score: 2.8, color: "#e85a8a" },
  ]
  const maxS = 10, H = 140, W = 300, barW = 30, gap = 14
  const totalW = bars.length * (barW + gap) - gap
  const startX = (W - totalW) / 2
  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H + 40}`}>
      {bars.map((b, i) => {
        const barH = (b.score / maxS) * H
        const x = startX + i * (barW + gap)
        const y = H - barH + 10
        return (
          <g key={i}>
            <rect x={x} y={10} width={barW} height={H} rx={3} fill="#1a261a" />
            <rect x={x} y={y} width={barW} height={barH} rx={3} fill={b.color} fillOpacity={0.85} />
            <text x={x + barW / 2} y={y - 4} textAnchor="middle" fill="#ccc" fontSize={9} fontFamily="monospace">{b.score}</text>
            <text x={x + barW / 2} y={H + 24} textAnchor="middle" fill="#6b7c6b" fontSize={8} fontFamily="monospace">{b.label}</text>
          </g>
        )
      })}
    </svg>
  )
}

// ─── Correlation Map (SVG) ────────────────────────────────────────────────────
function CorrelationMap() {
  const nodes = [
    { id: "server", x: 150, y: 110, r: 28, color: "#2a5caa", label: "SERVER", textColor: "#7ab3f5" },
    { id: "blue", x: 150, y: 110, r: 0, color: "transparent", label: "" },
    { id: "ssh", x: 260, y: 60, r: 22, color: "#1a3a1a", label: "SSH", textColor: "#4a9a4a" },
    { id: "web", x: 265, y: 155, r: 22, color: "#3a1a3a", label: "WEB", textColor: "#c87ad4" },
    { id: "kernel", x: 265, y: 230, r: 22, color: "#3a1a3a", label: "KERNEL", textColor: "#c87ad4" },
    { id: "red1", x: 55, y: 75, r: 20, color: "#5a1a1a", label: "RED", textColor: "#e87a7a" },
    { id: "red2", x: 55, y: 175, r: 20, color: "#5a1a1a", label: "RED", textColor: "#e87a7a" },
    { id: "blue2", x: 150, y: 115, r: 28, color: "#1a2a5a", label: "BLUE", textColor: "#7a9ae8" },
  ]
  const links = [
    { from: [150, 115], to: [260, 60] },
    { from: [150, 115], to: [265, 155] },
    { from: [150, 115], to: [265, 230] },
    { from: [55, 75], to: [150, 115] },
    { from: [55, 175], to: [150, 115] },
  ]
  return (
    <svg width="100%" viewBox="0 0 320 280" style={{ display: "block" }}>
      {links.map((l, i) => (
        <line key={i} x1={l.from[0]} y1={l.from[1]} x2={l.to[0]} y2={l.to[1]} stroke="#2a4a2a" strokeWidth={1.5} strokeDasharray="4 3" />
      ))}
      {[
        { x: 150, y: 115, r: 28, fill: "#1a2a5a", label: "BLUE", tc: "#7a9ae8" },
        { x: 260, y: 60, r: 22, fill: "#1a3a1a", label: "SSH", tc: "#4a9a4a" },
        { x: 265, y: 155, r: 22, fill: "#3a1a3a", label: "WEB", tc: "#c87ad4" },
        { x: 265, y: 230, r: 22, fill: "#3a1a3a", label: "KERNEL", tc: "#c87ad4" },
        { x: 55, y: 75, r: 20, fill: "#5a1a1a", label: "RED", tc: "#e87a7a" },
        { x: 55, y: 175, r: 20, fill: "#5a1a1a", label: "RED", tc: "#e87a7a" },
      ].map((n, i) => (
        <g key={i}>
          <circle cx={n.x} cy={n.y} r={n.r} fill={n.fill} stroke={n.tc} strokeWidth={1} strokeOpacity={0.4} />
          <text x={n.x} y={n.y + 4} textAnchor="middle" fill={n.tc} fontSize={9} fontWeight="600" fontFamily="monospace">{n.label}</text>
        </g>
      ))}
      <text x={150} y={252} textAnchor="middle" fill="#4a5a4a" fontSize={9} fontFamily="monospace">192.168.1.55</text>
      <text x={150} y={262} textAnchor="middle" fill="#4a5a4a" fontSize={8} fontFamily="monospace">SERVER</text>
    </svg>
  )
}

// ─── Live Clock ───────────────────────────────────────────────────────────────
function LiveClock() {
  const [t, setT] = useState(new Date())
  useEffect(() => { const id = setInterval(() => setT(new Date()), 1000); return () => clearInterval(id) }, [])
  return <span style={{ fontFamily: "monospace", fontSize: 28, color: "white", letterSpacing: 2 }}>{t.toTimeString().slice(0, 8)}</span>
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────
export default function Dashboard() {
  const kpis = useKPIs()
  const alerts = useAlerts()
  const report = useReport()

  const panel = (children: React.ReactNode, style?: React.CSSProperties) => (
    <div style={{ background: "#0d1a0d", border: "1px solid #1e3a1e", borderRadius: 8, padding: "14px 16px", ...style }}>
      {children}
    </div>
  )

  const sectionTitle = (title: string) => (
    <p style={{ margin: "0 0 10px", color: "#6b9a6b", fontSize: 11, letterSpacing: 2, textTransform: "uppercase", fontFamily: "monospace" }}>{title}</p>
  )

  return (
    <div style={{ background: "#060e06", minHeight: "100vh", padding: "0", fontFamily: "monospace", color: "white" }}>

      {/* ── Header ── */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 20px", borderBottom: "1px solid #1e3a1e", background: "#080f08" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <svg width={32} height={32} viewBox="0 0 32 32">
            <path d="M16 2 L28 8 L28 18 Q28 26 16 30 Q4 26 4 18 L4 8 Z" fill="none" stroke="#3b9e3b" strokeWidth={2} />
            <path d="M16 8 L22 11 L22 17 Q22 22 16 24 Q10 22 10 17 L10 11 Z" fill="#1a3a1a" stroke="#3b9e3b" strokeWidth={1} />
          </svg>
          <div>
            <p style={{ margin: 0, fontSize: 16, fontWeight: 700, color: "#e8ffe8" }}>Linux IDPS</p>
            <p style={{ margin: 0, fontSize: 10, color: "#4a6a4a", letterSpacing: 1 }}>Security Operations Center</p>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, background: "#0a1e0a", border: "1px solid #2a5a2a", borderRadius: 6, padding: "4px 10px" }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#3ddc84", boxShadow: "0 0 6px #3ddc84", display: "inline-block" }} />
            <span style={{ color: "#3ddc84", fontSize: 11, fontWeight: 700, letterSpacing: 2 }}>LIVE</span>
          </div>
          <LiveClock />
        </div>
      </div>

      <div style={{ padding: "14px 16px", display: "flex", flexDirection: "column", gap: 12 }}>

        {/* ── KPI Row ── */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10 }}>
          {panel(<>
            <Gauge value={kpis.cpu_load} max={100} color="#3ddc84" label="System Health" sublabel="Under threshold" />
          </>, { textAlign: "center" })}
          {panel(<>
            <Gauge value={kpis.ssh_failures} max={20} color="#3ddc84" label="SSH Failures / Tick" sublabel="Under threshold" />
          </>, { textAlign: "center" })}
          {panel(<>
            <Gauge value={kpis.active_connections} max={200} color="#3b9ef8" label="Web Requests" sublabel="Under threshold" />
          </>, { textAlign: "center" })}
          {panel(<>
            <Gauge value={2} max={10} color="#e05a8a" label="Blocked IPs" sublabel="Under threshold" />
          </>, { textAlign: "center" })}
          {panel(<>
            <Gauge value={kpis.error_rate} max={10} color="#f5a623" label="Kernel Errors" sublabel="Under threshold" />
          </>, { textAlign: "center" })}
        </div>

        {/* ── Middle Row ── */}
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 10 }}>
          {/* Attack Timeline */}
          {panel(<>
            {sectionTitle("Attack Timeline — 24h window")}
            <div style={{ display: "flex", gap: 14, marginBottom: 8 }}>
              {[{ c: "#3b9ef8", l: "Web" }, { c: "#e05252", l: "SSH" }, { c: "#9b59b6", l: "FTP" }, { c: "#e0525b", l: "Kernel" }].map(d => (
                <span key={d.l} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 10, color: "#8a9e8a" }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: d.c, display: "inline-block" }} />{d.l}
                </span>
              ))}
            </div>
            <AreaChart />
          </>)}

          {/* Risk Score */}
          {panel(<>
            {sectionTitle("Risk Score by Engine")}
            <RiskBars />
          </>)}

          {/* Pre-Attack Forecast */}
          {panel(<>
            {sectionTitle("Pre-Attack Forecast")}
            <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 10 }}>
              <span style={{ fontSize: 48, fontWeight: 700, color: "#e8ffe8", lineHeight: 1 }}>18</span>
              <div>
                <p style={{ margin: 0, fontSize: 11, color: "#6b9a6b" }}>Score</p>
                <p style={{ margin: 0, fontSize: 11, color: "#6b9a6b" }}>Progress</p>
              </div>
            </div>
            <div style={{ background: "#1a2a1a", height: 6, borderRadius: 3, marginBottom: 14 }}>
              <div style={{ width: "72%", height: "100%", background: "linear-gradient(90deg,#3b9ef8,#3ddc84)", borderRadius: 3 }} />
            </div>
            {["WEB_SCAN_WARMUP", "USER_IMPERSONATION"].map(tag => (
              <div key={tag} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                <span style={{ fontSize: 10, color: "#e05252" }}>⚑</span>
                <span style={{ background: "#2a1a0a", border: "1px solid #5a3a0a", borderRadius: 4, padding: "2px 8px", fontSize: 10, color: "#f5a623", letterSpacing: 1 }}>{tag}</span>
              </div>
            ))}
          </>)}
        </div>

        {/* ── Bottom Row ── */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1.1fr 1fr", gap: 10 }}>

          {/* Active Alarms */}
          {panel(<>
            {sectionTitle("Active Alarms")}
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {alerts.map((a, i) => (
                <div key={i} style={{ background: "#0a160a", border: `1px solid ${a.severity === "HIGH" ? "#5a1a1a" : "#1a3a5a"}`, borderRadius: 6, padding: "8px 10px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ width: 10, height: 10, borderRadius: "50%", background: a.severity === "HIGH" ? "#e05252" : "#3b9ef8", display: "inline-block", flexShrink: 0 }} />
                    <div>
                      <p style={{ margin: 0, fontSize: 11, color: a.severity === "HIGH" ? "#e07a7a" : "#7ab3f5", fontWeight: 700 }}>{a.type}</p>
                      <p style={{ margin: 0, fontSize: 10, color: "#4a6a4a" }}>{a.source_ip}</p>
                    </div>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ background: a.severity === "HIGH" ? "#4a0a0a" : "#0a2a4a", border: `1px solid ${a.severity === "HIGH" ? "#aa2a2a" : "#2a5a9a"}`, borderRadius: 4, padding: "2px 7px", fontSize: 9, color: a.severity === "HIGH" ? "#ff6666" : "#7ab3f5", letterSpacing: 1 }}>{a.severity === "HIGH" ? "CRITIQUE" : "INFO"}</span>
                    <span style={{ fontSize: 13, fontWeight: 700, color: "#e8ffe8" }}>{a.message.split(" ")[0]}</span>
                    <div style={{ width: 60, height: 4, background: "#1a2a1a", borderRadius: 2 }}>
                      <div style={{ width: `${Math.min(parseFloat(a.message) / 100 * 100, 100)}%`, height: "100%", background: a.severity === "HIGH" ? "#e05252" : "#3b9ef8", borderRadius: 2 }} />
                    </div>
                    <span style={{ fontSize: 10, color: "#6b9a6b" }}>Score</span>
                  </div>
                </div>
              ))}
            </div>
          </>)}

          {/* Correlation Map */}
          {panel(<>
            {sectionTitle("Correlation Map")}
            <CorrelationMap />
          </>)}

          {/* Top Threats */}
          {panel(<>
            {sectionTitle("Top Threats")}
            <div style={{ display: "grid", gridTemplateColumns: "1fr auto auto", gap: "4px 12px", alignItems: "center", fontSize: 10, color: "#4a6a4a", marginBottom: 8 }}>
              <span>Threat</span><span>Threat</span><span>Services</span>
            </div>
            {[
              { ip: "192.168.1.55", score: 68.5, svc: 3 },
              { ip: "192.168.1.55", score: 68.5, svc: 3 },
              { ip: "192.168.1.55", score: 72.3, svc: 1 },
            ].map((t, i) => (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr auto auto", gap: "4px 12px", alignItems: "center", marginBottom: 10 }}>
                <span style={{ color: "#7ab3f5", fontSize: 11 }}>{t.ip}</span>
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <div style={{ width: 80, height: 4, background: "#1a2a1a", borderRadius: 2 }}>
                    <div style={{ width: `${t.score}%`, height: "100%", background: "#e05252", borderRadius: 2 }} />
                  </div>
                  <span style={{ fontSize: 10, color: "#e8ffe8", minWidth: 28 }}>{t.score}</span>
                </div>
                <span style={{ fontSize: 11, color: "#6b9a6b", textAlign: "right" }}>{t.svc}</span>
              </div>
            ))}
            <div style={{ marginTop: 8, paddingTop: 8, borderTop: "1px solid #1e3a1e" }}>
              <p style={{ margin: 0, fontSize: 10, color: "#4a6a4a" }}>Recommendation:</p>
              <p style={{ margin: "4px 0 0", fontSize: 11, color: "#f5a623" }}>{report.recommendation}</p>
            </div>
          </>)}
        </div>

        {/* ── Footer ── */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingTop: 4 }}>
          <span style={{ fontSize: 10, color: "#3a5a3a", letterSpacing: 1 }}>10-layer IDPS · SSH · Web · Session · FTP · Kernel · Prediction</span>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 10, color: "#3a5a3a" }}>Last update: {new Date().toLocaleString()}</span>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#3ddc84", display: "inline-block" }} />
            <span style={{ fontSize: 10, color: "#3ddc84", letterSpacing: 2 }}>LIVE</span>
          </div>
        </div>

      </div>
    </div>
  )
}