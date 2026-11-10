export type SeverityLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"

export type DecisionAction = "ALLOW" | "ALERT" | "BLOCK"

export interface AlertData {
  alert_id: number
  timestamp: number
  datetime_str: string
  source_ip: string
  destination_ip: string
  source_port?: number
  destination_port?: number
  protocol: string
  category: string
  severity: SeverityLevel
  matched_rule: string
  action: DecisionAction
  client_tag?: string
  evidence?: string
  is_simulated_block?: boolean
}

export interface FlowData {
  flow_id: number
  source_ip: string
  destination_ip: string
  source_port: number
  destination_port: number
  protocol: string
  application_protocol: string
  tcp_state: string
  total_packets: number
  total_bytes: number
  duration_seconds: number
  is_active: boolean
}

export interface PacketMetadata {
  packet_id: number
  timestamp: number
  datetime_str: string
  network_type: string
  transport_type: string
  source_ip: string
  destination_ip: string
  source_port?: number
  destination_port?: number
  packet_length_bytes: number
  application_protocol?: string
  flags?: string
  decision: DecisionAction
  alerts_count: number
}

export interface FirewallRuleData {
  rule_id: string
  rule_name: string
  ip_address: string
  direction: "INBOUND" | "OUTBOUND" | "BOTH"
  action: "BLOCK" | "ALLOW"
  created_at: number
  duration_seconds: number
  expires_at?: number
  reason: string
  is_simulated: boolean
  is_active: boolean
}

export interface SystemStats {
  pipeline_status: string
  active_prevention: boolean
  total_packets_processed: number
  total_bytes_processed: number
  packets_per_sec: number
  bytes_per_sec: number
  active_workers: number
  total_flows: number
  active_flows: number
  protocol_distribution: Record<string, number>
  alerts_by_severity: Record<string, number>
  alerts_by_category: Record<string, number>
  total_alerts: number
  total_blocks: number
}

export interface MLTelemetry {
  status: string
  enabled: boolean
  random_forest_loaded: boolean
  isolation_forest_loaded: boolean
  queue_depth: number
  queue_capacity: number
  jobs_submitted: number
  jobs_processed: number
  queue_drops: number
  inference_failures: number
  rf_classifications: number
  if_anomalies: number
  avg_inference_latency_ms: number
}

export interface NotificationStatus {
  enabled: boolean
  smtp_status: "configured" | "not_configured"
  recipients_count: number
  cooldown_seconds: number
  queue_depth: number
  queue_capacity: number
  emails_submitted: number
  emails_delivered: number
  emails_failed: number
  emails_suppressed: number
  queue_full_drops: number
}

