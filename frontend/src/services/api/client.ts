import axios, { type AxiosInstance, type AxiosError, type InternalAxiosRequestConfig } from "axios"
import type { ApiErrorResponse } from "./types"

// Resolve backend base URL with strict environment support
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000"

/**
 * Global API Key reference in memory.
 * Strictly avoids persisting administrative credentials to browser localStorage.
 */
let sessionAdminApiKey: string | null = null

export const setSessionAdminApiKey = (key: string | null): void => {
  sessionAdminApiKey = key ? key.trim() : null
}

export const getSessionAdminApiKey = (): string | null => {
  return sessionAdminApiKey
}

/**
 * Centralized Axios client instance.
 */
export const apiClient: AxiosInstance = axios.create({
  baseURL: `${API_BASE_URL.replace(/\/+$/, "")}/api/v1`,
  timeout: 10000,
  headers: {
    "Content-Type": "application/json",
    Accept: "application/json",
  },
})

// Request Interceptor: Inject administrative API key if available in memory
apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    if (sessionAdminApiKey && !config.headers["X-API-Key"] && !config.headers["Authorization"]) {
      config.headers["X-API-Key"] = sessionAdminApiKey
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Response Interceptor: Standardize error formatting
apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError<ApiErrorResponse>) => {
    const status = error.response?.status
    const customMessage = error.response?.data?.message || error.message

    const formattedError = {
      status,
      message: customMessage,
      error: error.response?.data?.error || (status ? `HTTP_${status}` : "NETWORK_ERROR"),
      path: error.response?.data?.path,
      details: error.response?.data?.details,
    }

    return Promise.reject(formattedError)
  }
)

