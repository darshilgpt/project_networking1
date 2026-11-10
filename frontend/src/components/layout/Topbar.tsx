import { Bell, Wifi, WifiOff, Terminal } from "lucide-react"
import { useSecurityContext } from "../../context/SecurityContext"

export const Topbar: React.FC = () => {
  const { wsStatus, latestSystemStatus, liveAlerts } = useSecurityContext()

  return (
    <header className="h-14 border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md px-6 flex items-center justify-between shrink-0 select-none">
      {/* Left: Environment & Subnet */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300 font-mono">
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          <span>VPN SUBNET: 10.10.0.0/24</span>
        </div>
        <div className="hidden sm:flex items-center gap-1.5 text-xs text-slate-500">
          <span>INTERFACE:</span>
          <span className="font-mono text-slate-300">Ethernet / wg0</span>
        </div>
      </div>

      {/* Right: Telemetry Health Indicators */}
      <div className="flex items-center gap-4">
        {/* Pipeline Status */}
        {latestSystemStatus && (
          <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-slate-900 border border-slate-800 text-slate-300 text-[11px] font-mono">
            <span>PIPELINE:</span>
            <span
              className={
                latestSystemStatus.pipeline_status === "active"
                  ? "text-emerald-400 font-bold"
                  : "text-amber-400 font-bold"
              }
            >
              {latestSystemStatus.pipeline_status.toUpperCase()}
            </span>
          </div>
        )}

        {/* WebSocket Connection Status */}
        <div className="flex items-center gap-2 text-xs">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-slate-300">
            {wsStatus === "connected" ? (
              <>
                <Wifi className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-[11px] font-mono text-emerald-400">WS CONNECTED</span>
              </>
            ) : wsStatus === "connecting" ? (
              <>
                <Wifi className="w-3.5 h-3.5 text-amber-400 animate-pulse" />
                <span className="text-[11px] font-mono text-amber-400">WS CONNECTING</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3.5 h-3.5 text-rose-400" />
                <span className="text-[11px] font-mono text-rose-400">WS OFFLINE</span>
              </>
            )}
          </div>
        </div>

        {/* Notifications / Live Alerts Pill */}
        <div
          title={`${liveAlerts.length} live incoming security alerts captured`}
          className="relative p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
        >
          <Bell className="w-4 h-4" />
          {liveAlerts.length > 0 && (
            <span className="absolute -top-1 -right-1 px-1.5 py-0.2 rounded-full bg-rose-500 text-[10px] text-white font-bold font-mono">
              {liveAlerts.length}
            </span>
          )}
        </div>
      </div>
    </header>
  )
}
