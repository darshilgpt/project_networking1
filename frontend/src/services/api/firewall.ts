import { apiClient } from "./client"
import type {
  FirewallRulesListResponse,
  FirewallBlockRequest,
  FirewallOperationResponse,
} from "./types"

export const firewallApi = {
  getRules: async (): Promise<FirewallRulesListResponse> => {
    const res = await apiClient.get<FirewallRulesListResponse>("/firewall/rules")
    return res.data
  },

  blockIp: async (
    data: FirewallBlockRequest,
    adminApiKey?: string
  ): Promise<FirewallOperationResponse> => {
    const headers: Record<string, string> = {}
    if (adminApiKey) {
      headers["X-API-Key"] = adminApiKey.trim()
    }
    const res = await apiClient.post<FirewallOperationResponse>("/firewall/block", data, {
      headers,
    })
    return res.data
  },

  unblockRule: async (
    ruleId: string,
    adminApiKey?: string
  ): Promise<FirewallOperationResponse> => {
    const headers: Record<string, string> = {}
    if (adminApiKey) {
      headers["X-API-Key"] = adminApiKey.trim()
    }
    const res = await apiClient.delete<FirewallOperationResponse>(
      `/firewall/block/${encodeURIComponent(ruleId)}`,
      { headers }
    )
    return res.data
  },
}

