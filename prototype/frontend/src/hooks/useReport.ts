import { useState, useEffect } from "react"
import axios from "axios"
import type { Report } from "../types"

export function useReport() {
  const [report, setReport] = useState<Report | null>(null)
  useEffect(() => {
    axios.get("http://127.0.0.1:8000/api/reports")
      .then(r => setReport(r.data))
  }, [])
  return report
}