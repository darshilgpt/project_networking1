import type { WebSocketEventType, WebSocketMessage } from "./api/types"

export type WebSocketStatus = "connecting" | "connected" | "disconnected" | "error"

export type WebSocketEventHandler = (event: WebSocketMessage) => void

export interface WebSocketManagerConfig {
  url?: string
  token?: string
  reconnectInterval?: number
  maxReconnectInterval?: number
  heartbeatInterval?: number
}

class WebSocketManager {
  private ws: WebSocket | null = null
  private status: WebSocketStatus = "disconnected"
  private subscribers: Map<string, Set<WebSocketEventHandler>> = new Map()
  private statusListeners: Set<(status: WebSocketStatus) => void> = new Set()
  private reconnectAttempts = 0
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null
  private explicitClose = false

  private baseWsUrl: string
  private token: string | null = null
  private reconnectInterval: number
  private maxReconnectInterval: number

  constructor() {
    const rawWsUrl =
      import.meta.env.VITE_WS_URL ||
      (import.meta.env.VITE_API_BASE_URL
        ? import.meta.env.VITE_API_BASE_URL.replace(/^http/, "ws") + "/ws/monitor"
        : "ws://127.0.0.1:8000/ws/monitor")

    this.baseWsUrl = rawWsUrl
    this.token = import.meta.env.VITE_WS_TOKEN || "dpi-admin-secret-key"
    this.reconnectInterval = 2000
    this.maxReconnectInterval = 30000
  }

  public getStatus(): WebSocketStatus {
    return this.status
  }

  public onStatusChange(callback: (status: WebSocketStatus) => void): () => void {
    this.statusListeners.add(callback)
    callback(this.status)
    return () => {
      this.statusListeners.delete(callback)
    }
  }

  private setStatus(newStatus: WebSocketStatus) {
    if (this.status !== newStatus) {
      this.status = newStatus
      this.statusListeners.forEach((cb) => cb(newStatus))
    }
  }

  public subscribe(eventType: WebSocketEventType | "*", handler: WebSocketEventHandler): () => void {
    if (!this.subscribers.has(eventType)) {
      this.subscribers.set(eventType, new Set())
    }
    this.subscribers.get(eventType)!.add(handler)

    return () => {
      const set = this.subscribers.get(eventType)
      if (set) {
        set.delete(handler)
        if (set.size === 0) {
          this.subscribers.delete(eventType)
        }
      }
    }
  }

  public connect(config?: WebSocketManagerConfig): void {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return
    }

    this.explicitClose = false
    this.setStatus("connecting")

    if (config?.url) this.baseWsUrl = config.url
    if (config?.token !== undefined) this.token = config.token

    // Security Hardening: Never append authentication tokens to the WebSocket URL.
    // Instead, pass credentials via standard WebSocket subprotocol negotiation: ['dpi-auth', token]
    const cleanUrl = this.baseWsUrl
    const protocols: string[] = this.token ? ["dpi-auth", this.token] : []

    try {
      this.ws = protocols.length > 0 ? new WebSocket(cleanUrl, protocols) : new WebSocket(cleanUrl)

      this.ws.onopen = () => {
        this.setStatus("connected")
        this.reconnectAttempts = 0
        this.startHeartbeat()
      }

      this.ws.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data) as WebSocketMessage
          if (!parsed || typeof parsed !== "object" || !parsed.event) {
            return
          }

          // Dispatch to wildcard subscribers
          const wildcardSubscribers = this.subscribers.get("*")
          if (wildcardSubscribers) {
            wildcardSubscribers.forEach((handler) => {
              try {
                handler(parsed)
              } catch (err) {
                console.error("Error in WS wildcard subscriber handler:", err)
              }
            })
          }

          // Dispatch to event-specific subscribers
          const specificSubscribers = this.subscribers.get(parsed.event)
          if (specificSubscribers) {
            specificSubscribers.forEach((handler) => {
              try {
                handler(parsed)
              } catch (err) {
                console.error(`Error in WS subscriber handler for ${parsed.event}:`, err)
              }
            })
          }
        } catch {
          // Ignore malformed JSON frames safely
        }
      }

      this.ws.onerror = () => {
        this.setStatus("error")
      }

      this.ws.onclose = () => {
        this.stopHeartbeat()
        this.setStatus("disconnected")
        this.ws = null

        if (!this.explicitClose) {
          this.scheduleReconnect()
        }
      }
    } catch {
      this.setStatus("error")
      this.scheduleReconnect()
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
    }

    this.reconnectAttempts++
    // Exponential backoff with jitter
    const delay = Math.min(
      this.reconnectInterval * Math.pow(1.5, this.reconnectAttempts - 1) + Math.random() * 500,
      this.maxReconnectInterval
    )

    this.reconnectTimer = setTimeout(() => {
      this.connect()
    }, delay)
  }

  private startHeartbeat(): void {
    this.stopHeartbeat()
    this.heartbeatTimer = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        // Send lightweight client ping frame if needed
        try {
          this.ws.send(JSON.stringify({ type: "ping" }))
        } catch {
          // Handled by onclose/onerror
        }
      }
    }, 15000)
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer)
      this.heartbeatTimer = null
    }
  }

  public disconnect(): void {
    this.explicitClose = true
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    this.stopHeartbeat()
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
    this.setStatus("disconnected")
  }
}

export const wsManager = new WebSocketManager()

