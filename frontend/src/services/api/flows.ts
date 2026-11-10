import { apiClient } from "./client"
import type { FlowItem, FlowListResponse, FlowFilterParams } from "./types"

export const flowsApi = {
  getFlows: async (params?: FlowFilterParams): Promise<FlowListResponse> => {
    const res = await apiClient.get<FlowListResponse>("/flows", { params })
    return res.data
  },

  getFlowById: async (flowId: number): Promise<FlowItem> => {
    const res = await apiClient.get<FlowItem>(`/flows/${flowId}`)
    return res.data
  },
}

