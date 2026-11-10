import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { wsManager } from "../../websocket"
import type { WebSocketMessage } from "../types"

// Mock native WebSocket
class MockWebSocket {
  static instances: MockWebSocket[] = []
  public url: string
  public readyState: number = WebSocket.CONNECTING
  public onopen: (() => void) | null = null
  public onclose: (() => void) | null = null
  public onmessage: ((ev: { data: string }) => void) | null = null
  public onerror: (() => void) | null = null
  public sentData: string[] = []

  constructor(url: string) {
    this.url = url
    MockWebSocket.instances.push(this)
    setTimeout(() => {
      this.readyState = WebSocket.OPEN
      if (this.onopen) this.onopen()
    }, 10)
  }

  send(data: string) {
    this.sentData.push(data)
  }

  close() {
    this.readyState = WebSocket.CLOSED
    if (this.onclose) this.onclose()
  }

  triggerMessage(msg: WebSocketMessage) {
    if (this.onmessage) {
      this.onmessage({ data: JSON.stringify(msg) })
    }
  }

  triggerMalformedMessage(raw: string) {
    if (this.onmessage) {
      this.onmessage({ data: raw })
    }
  }
}

describe("WebSocket Manager", () => {
  const originalWs = globalThis.WebSocket

  beforeEach(() => {
    MockWebSocket.instances = []
    // @ts-ignore
    globalThis.WebSocket = MockWebSocket as any
    wsManager.disconnect()
  })

  afterEach(() => {
    wsManager.disconnect()
    // @ts-ignore
    globalThis.WebSocket = originalWs
  })

  it("establishes connection and handles open event", async () => {
    wsManager.connect({ url: "ws://127.0.0.1:8000/ws/monitor" })
    await new Promise((r) => setTimeout(r, 30))
    expect(wsManager.getStatus()).toBe("connected")
  })

  it("dispatches typed real-time events to subscribers", async () => {
    wsManager.connect({ url: "ws://127.0.0.1:8000/ws/monitor" })
    await new Promise((r) => setTimeout(r, 30))

    const mockAlertHandler = vi.fn()
    const unsubscribe = wsManager.subscribe("new_alert", mockAlertHandler)

    const testMsg: WebSocketMessage = {
      event: "new_alert",
      timestamp: new Date().toISOString(),
      data: {
        alert_id: 101,
        category: "PORT_SCAN",
        severity: "HIGH",
      },
    }

    const currentWs = MockWebSocket.instances[MockWebSocket.instances.length - 1]
    currentWs.triggerMessage(testMsg)

    expect(mockAlertHandler).toHaveBeenCalledTimes(1)
    expect(mockAlertHandler).toHaveBeenCalledWith(testMsg)

    unsubscribe()
  })

  it("safely handles and ignores malformed JSON frames", async () => {
    wsManager.connect({ url: "ws://127.0.0.1:8000/ws/monitor" })
    await new Promise((r) => setTimeout(r, 30))

    const mockHandler = vi.fn()
    wsManager.subscribe("*", mockHandler)

    const currentWs = MockWebSocket.instances[MockWebSocket.instances.length - 1]
    // Send broken JSON frame
    currentWs.triggerMalformedMessage("INVALID_JSON_CORRUPT_FRAME{{{")

    expect(mockHandler).not.toHaveBeenCalled()
  })

  it("cleans up connection on disconnect", async () => {
    wsManager.connect({ url: "ws://127.0.0.1:8000/ws/monitor" })
    await new Promise((r) => setTimeout(r, 30))
    expect(wsManager.getStatus()).toBe("connected")

    wsManager.disconnect()
    expect(wsManager.getStatus()).toBe("disconnected")
  })
})
