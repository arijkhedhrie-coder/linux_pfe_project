import { useState, useEffect } from "react"
import axios from "axios"
import type { KPI } from "../types"

export function useKPIs() {
  const [kpis, setKpis] = useState<KPI | null>(null)
  useEffect(() => {
    axios.get("http://127.0.0.1:8000/api/kpis")
      .then(r => setKpis(r.data))
  }, [])
  return kpis
}