import { apiClient } from "./client"
import type { NotificationStatusResponse } from "./types"

export const notificationsApi = {
  getStatus: async (): Promise<NotificationStatusResponse> => {
    const res = await apiClient.get<NotificationStatusResponse>("/notifications/status")
    return res.data
  },
}

