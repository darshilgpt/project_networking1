import { describe, it, expect, beforeEach, afterEach } from "vitest"
import { wsManager } from "../../websocket"
import type { WebSocketMessage } from "../types"

// Mock native WebSocket
class MockWebSocket {
  static instances: MockWebSocket[] = []
  public url: string
  public protocols?: string | string[]
  public readyState: number = WebSocket.CONNECTING
  public onopen: (() => void) | null = null
  public onclose: (() => void) | null = null
  public onmessage: ((ev: { data: string }) => void) | null = null
  public onerror: (() => void) | null = null
  public sentData: string[] = []

  constructor(url: string, protocols?: string | string[]) {
    this.url = url
    this.protocols = protocols
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

describe("WebSocket Manager Subprotocol Authentication", () => {
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

  it("never appends authentication token to the WebSocket URL", async () => {
    wsManager.connect({
      url: "ws://127.0.0.1:8000/ws/monitor",
      token: "secret-auth-key-12345",
    })
    await new Promise((r) => setTimeout(r, 30))

    const currentWs = MockWebSocket.instances[MockWebSocket.instances.length - 1]
    expect(currentWs).toBeDefined()
    // URL must remain clean with zero query strings
    expect(currentWs.url).toBe("ws://127.0.0.1:8000/ws/monitor")
    expect(currentWs.url).not.toContain("token=")
    expect(currentWs.url).not.toContain("secret-auth-key")

    // Credentials passed via WebSocket subprotocol
    expect(currentWs.protocols).toEqual(["dpi-auth", "secret-auth-key-12345"])
    expect(wsManager.getStatus()).toBe("connected")
  })

  it("connects without subprotocol if no token is provided", async () => {
    wsManager.connect({
      url: "ws://127.0.0.1:8000/ws/monitor",
      token: "",
    })
    await new Promise((r) => setTimeout(r, 30))

    const currentWs = MockWebSocket.instances[MockWebSocket.instances.length - 1]
    expect(currentWs.url).toBe("ws://127.0.0.1:8000/ws/monitor")
    expect(currentWs.protocols).toBeUndefined()
  })
})
