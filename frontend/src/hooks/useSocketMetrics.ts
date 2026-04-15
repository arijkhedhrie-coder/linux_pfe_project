import { useEffect, useRef, useState } from "react";
import { io, type Socket } from "socket.io-client";
import { type LiveMetrics, getMockLiveMetrics } from "../api/dashboardApi";

const WS_URL = import.meta.env.VITE_WS_URL || "http://localhost:5001";

export interface SocketStatus {
  connected: boolean;
  transport: string;
}

export const useSocketMetrics = () => {
  const socketRef = useRef<Socket | null>(null);
  const [metrics, setMetrics] = useState<LiveMetrics>(getMockLiveMetrics());
  const [status, setStatus] = useState<SocketStatus>({ connected: false, transport: "none" });

  useEffect(() => {
    const socket = io(WS_URL, {
      transports: ["websocket", "polling"],
      timeout: 3000,
      reconnectionAttempts: 3,
    });
    socketRef.current = socket;

    socket.on("connect", () => {
      setStatus({ connected: true, transport: socket.io.engine.transport.name });
    });

    socket.on("disconnect", () => {
      setStatus({ connected: false, transport: "none" });
    });

    // Écoute les événements live émis par le serveur
    socket.on("live_update", (data: LiveMetrics) => {
      setMetrics(data);
    });

    // Fallback : si pas de socket.io, on ignore silencieusement
    socket.on("connect_error", () => {
      setStatus({ connected: false, transport: "polling_fallback" });
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  return { metrics, status };
};