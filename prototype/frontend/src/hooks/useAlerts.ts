import { useState, useEffect } from "react"
import axios from "axios"
import type { Alert } from "../types"

export function useAlerts() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  useEffect(() => {
    axios.get("http://127.0.0.1:8000/api/alerts")
      .then(r => setAlerts(r.data))
  }, [])
  return alerts
}