export interface Alert {
  timestamp: string
  type: string
  source_ip: string
  severity: "LOW" | "MEDIUM" | "HIGH"
  message: string
}

export interface KPI {
  cpu_load: number
  ssh_failures: number
  active_connections: number
  error_rate: number
}

export interface Report {
  summary: string
  agents: string[]
  recommendation: string
}