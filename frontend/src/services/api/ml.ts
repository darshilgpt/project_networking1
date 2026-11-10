import { apiClient } from "./client"
import type { MLMetricsResponse, MLStatusResponse } from "./types"

export const mlApi = {
  getMetrics: async (): Promise<MLMetricsResponse> => {
    const res = await apiClient.get<MLMetricsResponse>("/ml/metrics")
    return res.data
  },

  getStatus: async (): Promise<MLStatusResponse> => {
    const res = await apiClient.get<MLStatusResponse>("/ml/status")
    return res.data
  },
}

