import { useAuth } from "../context/AuthContext";
import { useNavigate } from "react-router-dom";

export const DashboardPage = () => {
  const { logout } = useAuth();
  const navigate = useNavigate();

  return (
    <div style={{
      minHeight: "100vh", background: "#0a0e1a",
      display: "flex", alignItems: "center",
      justifyContent: "center", flexDirection: "column", gap: "20px"
    }}>
      <h1 style={{ color: "#00d4ff", fontSize: "28px" }}>
        ✅ Dashboard — Accès autorisé
      </h1>
      <p style={{ color: "rgba(255,255,255,0.5)" }}>
        Sprint 2 → KPIs & Layout (prochaine étape)
      </p>
      <button
        onClick={() => { logout(); navigate("/login"); }}
        style={{
          background: "rgba(255,59,48,0.15)", border: "1px solid rgba(255,59,48,0.4)",
          color: "#ff6b6b", borderRadius: "8px", padding: "10px 24px",
          cursor: "pointer", fontSize: "14px"
        }}
      >
        Se déconnecter
      </button>
    </div>
  );
};