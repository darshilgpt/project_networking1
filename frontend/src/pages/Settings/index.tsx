import { useState } from "react"
import { Save, Server, Globe, Key } from "lucide-react"
import { PageHeader } from "../../components/common/PageHeader"
import { StatusBadge } from "../../components/common/StatusBadge"
import { useSecurityContext } from "../../context/SecurityContext"

export const SettingsPage: React.FC = () => {
  const { wsStatus, adminApiKey, setAdminApiKey } = useSecurityContext()
  const [apiUrl, setApiUrl] = useState(import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000")
  const [wsUrl, setWsUrl] = useState(import.meta.env.VITE_WS_URL || "ws://127.0.0.1:8000/ws/monitor")
  const [keyInput, setKeyInput] = useState(adminApiKey || "")
  const [savedNotification, setSavedNotification] = useState(false)

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault()
    setAdminApiKey(keyInput.trim() || null)
    setSavedNotification(true)
    setTimeout(() => setSavedNotification(false), 2500)
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <PageHeader
        title="Dashboard & Backend Settings"
        description="Inspect backend connectivity, WebSocket endpoint configuration, and session authorization keys."
        badge={
          <StatusBadge
            status={wsStatus === "connected" ? "Connected to Backend" : `WS: ${wsStatus.toUpperCase()}`}
            type={wsStatus === "connected" ? "operational" : "warning"}
          />
        }
      />

      {savedNotification && (
        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-medium flex items-center justify-between">
          <span>✓ Session preferences and in-memory authorization updated.</span>
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-6">
        {/* Backend Endpoints */}
        <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2 border-b border-slate-800 pb-3">
            <Server className="w-4 h-4 text-cyan-400" />
            Backend Connection Endpoints
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                FastAPI REST API Base URL
              </label>
              <input
                type="text"
                value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500/60"
              />
              <span className="text-[11px] text-slate-500 mt-1 block">
                Configured via VITE_API_BASE_URL
              </span>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                WebSocket Stream URL
              </label>
              <input
                type="text"
                value={wsUrl}
                onChange={(e) => setWsUrl(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500/60"
              />
              <span className="text-[11px] text-slate-500 mt-1 block">
                Configured via VITE_WS_URL
              </span>
            </div>
          </div>
        </div>

        {/* Administrative Authorization Key */}
        <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2 border-b border-slate-800 pb-3">
            <Key className="w-4 h-4 text-amber-400" />
            Session Administrative API Key
          </h3>

          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1">
              Admin API Key (X-API-Key or Bearer token for firewall block/unblock)
            </label>
            <input
              type="password"
              placeholder="Enter ADMIN_API_KEY for privileged operations..."
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500/60"
            />
            <span className="text-[11px] text-slate-500 mt-1 block">
              Held strictly in React state memory. Never written to localStorage or cookies.
            </span>
          </div>
        </div>

        {/* Security and Credentials Policy Note */}
        <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 flex items-start gap-3 text-xs text-slate-400">
          <Globe className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-slate-200 block mb-0.5">Zero Secret Persistence Policy</span>
            The DPI SOC frontend adheres to OWASP guidelines: administrative API keys and SMTP credentials are never saved to permanent browser storage. Reloading the browser clears all session secrets.
          </div>
        </div>

        {/* Submit Button */}
        <div className="flex justify-end">
          <button
            type="submit"
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-colors"
          >
            <Save className="w-4 h-4" />
            Save Session Preferences
          </button>
        </div>
      </form>
    </div>
  )
}
