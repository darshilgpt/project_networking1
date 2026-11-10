import { apiClient } from "./client"
import type { StatisticsResponse } from "./types"

export const statsApi = {
  getStatistics: async (): Promise<StatisticsResponse> => {
    const res = await apiClient.get<StatisticsResponse>("/stats")
    return res.data
  },
}

