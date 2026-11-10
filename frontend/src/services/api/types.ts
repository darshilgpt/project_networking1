/**
 * TypeScript Interfaces strictly matching FastAPI Backend Schemas.
 * (Source: backend/api/schemas/rest_schemas.py & backend/api/websocket/events.py)
 */

export interface PaginationMeta {
  total: number
  limit: number
  offset: number
  returned: number
}

export interface ApiErrorResponse {
  error: string
  message: string
  path?: string
  details?: Record<string, unknown>
}

// Alerts
export interface AlertItem {
  alert_id: number
  timestamp: number
  datetime_str: string
  source_ip: string
  destination_ip: string
  source_port?: number | null
  destination_port?: number | null
  protocol: string
  category: string
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string
  matched_rule: string
  action: string
  client_tag?: string | null
  evidence?: string | null
}

export interface AlertListResponse {
  alerts: AlertItem[]
  pagination: PaginationMeta
}

export interface AlertFilterParams {
  limit?: number
  offset?: number
  severity?: string
  category?: string
  source_ip?: string
  date_from?: number
  date_to?: number
}

// Flows
export interface FlowItem {
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

export interface FlowListResponse {
  flows: FlowItem[]
  pagination: PaginationMeta
}

export interface FlowFilterParams {
  limit?: number
  offset?: number
  protocol?: string
  source_ip?: string
  destination_ip?: string
  is_active?: boolean
}

// Packets
export interface PacketItem {
  packet_id: number
  timestamp: number
  datetime_str: string
  network_type: string
  transport_type: string
  source_ip: string
  destination_ip: string
  source_port?: number | null
  destination_port?: number | null
  packet_length_bytes: number
  application_protocol?: string | null
  flags?: string | null
  decision: string
  alerts_count: number
}

export interface PacketListResponse {
  packets: PacketItem[]
  pagination: PaginationMeta
}

// System Statistics
export interface StatisticsResponse {
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

// Machine Learning
export interface MLMetricsResponse {
  jobs_submitted: number
  jobs_processed: number
  queue_drops: number
  inference_failures: number
  rf_classifications: number
  if_anomalies: number
  avg_inference_latency_ms: number
}

export interface MLStatusResponse {
  status: string
  enabled: boolean
  random_forest_loaded: boolean
  isolation_forest_loaded: boolean
  queue_depth: number
  queue_capacity: number
  metrics: MLMetricsResponse
}

// Firewall
export interface FirewallRuleItem {
  rule_id: string
  rule_name: string
  ip_address: string
  direction: string
  action: string
  created_at: number
  duration_seconds: number
  expires_at?: number | null
  reason: string
  is_simulated: boolean
  is_active: boolean
}

export interface FirewallRulesListResponse {
  active_prevention_enabled: boolean
  enforcement_mechanism: string
  total_active_rules: number
  rules: FirewallRuleItem[]
}

export interface FirewallBlockRequest {
  ip_address: string
  duration_seconds?: number
  reason?: string
}

export interface FirewallOperationResponse {
  success: boolean
  operation: "BLOCK" | "UNBLOCK" | string
  ip_address: string
  effective_mode: "ACTUAL_ENFORCEMENT" | "SIMULATION" | string
  message: string
  rule_id?: string | null
}

// Notification Status
export interface NotificationStatusResponse {
  enabled: boolean
  smtp_status: "configured" | "not_configured" | string
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

// WebSocket Real-Time Events
export type WebSocketEventType =
  | "new_alert"
  | "traffic_update"
  | "new_flow"
  | "ml_event"
  | "firewall_event"
  | "notification_event"
  | "system_status"

export interface WebSocketMessage<T = Record<string, unknown>> {
  event: WebSocketEventType
  timestamp: string
  data: T
}

export interface SystemStatusEventData {
  api_status: string
  pipeline_status: string
  ml_status: string
  notification_status: string
  active_clients: number
}

export interface TrafficUpdateEventData {
  packets_per_sec: number
  bytes_per_sec: number
  total_packets: number
  total_bytes: number
  active_flows: number
  total_flows: number
  active_workers: number
  total_alerts: number
  total_blocks: number
}
