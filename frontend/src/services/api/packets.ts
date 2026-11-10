import { apiClient } from "./client"
import type { PacketListResponse } from "./types"

export const packetsApi = {
  getPackets: async (params?: { limit?: number; offset?: number }): Promise<PacketListResponse> => {
    const res = await apiClient.get<PacketListResponse>("/packets", { params })
    return res.data
  },
}

