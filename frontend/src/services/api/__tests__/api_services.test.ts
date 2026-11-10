import { describe, it, expect, vi, beforeEach } from "vitest"
import { alertsApi } from "../alerts"
import { flowsApi } from "../flows"
import { packetsApi } from "../packets"
import { statsApi } from "../stats"
import { mlApi } from "../ml"
import { firewallApi } from "../firewall"
import { notificationsApi } from "../notifications"
import { setSessionAdminApiKey, getSessionAdminApiKey } from "../client"

// Mock axios instance methods
vi.mock("axios", async () => {
  const actual = await vi.importActual<any>("axios")
  const mockAxiosInstance = {
    get: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  }
  return {
    ...actual,
    default: {
      ...actual.default,
      create: vi.fn(() => mockAxiosInstance),
    },
  }
})

describe("API Service Layer Integration Tests", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setSessionAdminApiKey(null)
  })

  it("handles in-memory administrative API key without persistence", () => {
    expect(getSessionAdminApiKey()).toBeNull()
    setSessionAdminApiKey("test-admin-secret-key")
    expect(getSessionAdminApiKey()).toBe("test-admin-secret-key")
    setSessionAdminApiKey(null)
    expect(getSessionAdminApiKey()).toBeNull()
  })

  it("exports all API modules correctly", () => {
    expect(alertsApi).toBeDefined()
    expect(flowsApi).toBeDefined()
    expect(packetsApi).toBeDefined()
    expect(statsApi).toBeDefined()
    expect(mlApi).toBeDefined()
    expect(firewallApi).toBeDefined()
    expect(notificationsApi).toBeDefined()
  })
})
