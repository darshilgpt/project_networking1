import React, { createContext, useContext, useEffect, useState, useMemo } from "react"
import { wsManager, type WebSocketStatus } from "../services/websocket"
import type {
  SystemStatusEventData,
  TrafficUpdateEventData,
  AlertItem,
  WebSocketMessage,
} from "../services/api/types"

interface SecurityContextValue {
  wsStatus: WebSocketStatus
  latestSystemStatus: SystemStatusEventData | null
  latestTraffic: TrafficUpdateEventData | null
  liveAlerts: AlertItem[]
  clearLiveAlerts: () => void
  adminApiKey: string | null
  setAdminApiKey: (key: string | null) => void
}

const SecurityContext = createContext<SecurityContextValue | null>(null)

export const SecurityProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [wsStatus, setWsStatus] = useState<WebSocketStatus>(wsManager.getStatus())
  const [latestSystemStatus, setLatestSystemStatus] = useState<SystemStatusEventData | null>(null)
  const [latestTraffic, setLatestTraffic] = useState<TrafficUpdateEventData | null>(null)
  const [liveAlerts, setLiveAlerts] = useState<AlertItem[]>([])
  const [adminApiKey, setAdminApiKey] = useState<string | null>(null)

  useEffect(() => {
    // Connect WebSocket on app mount
    wsManager.connect()

    const unsubStatus = wsManager.onStatusChange(setWsStatus)

    const unsubSystem = wsManager.subscribe("system_status", (msg: WebSocketMessage) => {
      setLatestSystemStatus(msg.data as unknown as SystemStatusEventData)
    })

    const unsubTraffic = wsManager.subscribe("traffic_update", (msg: WebSocketMessage) => {
      setLatestTraffic(msg.data as unknown as TrafficUpdateEventData)
    })

    const unsubAlert = wsManager.subscribe("new_alert", (msg: WebSocketMessage) => {
      const alert = msg.data as unknown as AlertItem
      if (alert && alert.alert_id) {
        setLiveAlerts((prev) => {
          // Keep bounded at latest 50 alerts in memory
          const deduped = prev.filter((a) => a.alert_id !== alert.alert_id)
          return [alert, ...deduped].slice(0, 50)
        })
      }
    })

    return () => {
      unsubStatus()
      unsubSystem()
      unsubTraffic()
      unsubAlert()
      wsManager.disconnect()
    }
  }, [])

  const value = useMemo(
    () => ({
      wsStatus,
      latestSystemStatus,
      latestTraffic,
      liveAlerts,
      clearLiveAlerts: () => setLiveAlerts([]),
      adminApiKey,
      setAdminApiKey,
    }),
    [wsStatus, latestSystemStatus, latestTraffic, liveAlerts, adminApiKey]
  )

  return <SecurityContext.Provider value={value}>{children}</SecurityContext.Provider>
}

export const useSecurityContext = (): SecurityContextValue => {
  const ctx = useContext(SecurityContext)
  if (!ctx) {
    throw new Error("useSecurityContext must be used within a SecurityProvider")
  }
  return ctx
}

