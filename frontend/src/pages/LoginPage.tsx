import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { loginRequest } from "../api/authApi";
import "./LoginPage.css";

export const LoginPage = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [error, setError] = useState<string | null>(null); // Correction ici : spécifier le type
  const [loading, setLoading] = useState<boolean>(false);

  // Generate floating particles
  const [particles, setParticles] = useState<Array<{
    id: number;
    left: string;
    width: string;
    height: string;
    animationDuration: string;
    animationDelay: string;
    opacity: number;
  }>>([]);

  useEffect(() => {
    const particleCount = 50;
    const newParticles = [];
    for (let i = 0; i < particleCount; i++) {
      newParticles.push({
        id: i,
        left: `${Math.random() * 100}%`,
        width: `${Math.random() * 4 + 2}px`,
        height: `${Math.random() * 4 + 2}px`,
        animationDuration: `${Math.random() * 10 + 8}s`,
        animationDelay: `${Math.random() * 5}s`,
        opacity: Math.random() * 0.5 + 0.2,
      });
    }
    setParticles(newParticles);
  }, []);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const response = await loginRequest({ username, password });
      login(response.access_token);
      navigate("/dashboard");
    } catch {
      setError("Identifiants invalides. Accès refusé.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-wrapper">
      {/* Floating particles */}
      <div className="particles">
        {particles.map((particle) => (
          <div
            key={particle.id}
            className="particle"
            style={{
              left: particle.left,
              width: particle.width,
              height: particle.height,
              animationDuration: particle.animationDuration,
              animationDelay: particle.animationDelay,
              opacity: particle.opacity,
            }}
          />
        ))}
      </div>

      <div className="login-card">
        <div className="login-header">
          <div className="shield-icon">🛡️</div>
          <h1>Security Dashboard</h1>
          <p>Accès Administrateur Uniquement</p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          <div className="input-group">
            <label>
              <span className="label-icon">👤</span>
              Nom d'utilisateur
            </label>
            <input
              type="text"
              placeholder="admin"
              value={username}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUsername(e.target.value)}
              required
              autoComplete="username"
            />
          </div>

          <div className="input-group">
            <label>
              <span className="label-icon">🔒</span>
              Mot de passe
            </label>
            <input
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
            />
          </div>

          {error && <div className="error-msg">⚠ {error}</div>}

          <button type="submit" className="login-btn" disabled={loading}>
            {loading ? "Authentification..." : "Se connecter"}
          </button>
        </form>

        <div className="login-footer">
          <span> Connexion chiffrée JWT · HTTPS</span>
        </div>
      </div>
    </div>
  );
};