import { apiClient } from "./client"
import type { AlertItem, AlertListResponse, AlertFilterParams } from "./types"

export const alertsApi = {
  getAlerts: async (params?: AlertFilterParams): Promise<AlertListResponse> => {
    const res = await apiClient.get<AlertListResponse>("/alerts", { params })
    return res.data
  },

  getAlertById: async (alertId: number): Promise<AlertItem> => {
    const res = await apiClient.get<AlertItem>(`/alerts/${alertId}`)
    return res.data
  },
}

