import type { AlertData } from "../../types/security"
import { SeverityBadge } from "../common/SeverityBadge"
import { StatusBadge } from "../common/StatusBadge"
import { X, ShieldAlert, Terminal, Network } from "lucide-react"

interface AlertDetailsModalProps {
  alert: AlertData | null
  onClose: () => void
}

export const AlertDetailsModal: React.FC<AlertDetailsModalProps> = ({ alert, onClose }) => {
  if (!alert) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="flex items-center justify-between p-4 px-6 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400">ALERT #{alert.alert_id}</span>
                <SeverityBadge severity={alert.severity} />
                <StatusBadge status={alert.action} />
              </div>
              <h3 className="text-base font-bold text-slate-100 mt-0.5">{alert.matched_rule}</h3>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-md text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5 text-xs text-slate-300">
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 p-3.5 bg-slate-950/40 rounded-lg border border-slate-800/80">
            <div>
              <span className="text-[11px] text-slate-500 uppercase tracking-wider block">Category</span>
              <span className="font-semibold text-slate-200">{alert.category}</span>
            </div>
            <div>
              <span className="text-[11px] text-slate-500 uppercase tracking-wider block">Protocol</span>
              <span className="font-semibold text-slate-200">{alert.protocol}</span>
            </div>
            <div>
              <span className="text-[11px] text-slate-500 uppercase tracking-wider block">Time</span>
              <span className="font-mono text-slate-200">{alert.datetime_str}</span>
            </div>
            <div>
              <span className="text-[11px] text-slate-500 uppercase tracking-wider block">Client Tag</span>
              <span className="text-slate-200">{alert.client_tag || "Unknown"}</span>
            </div>
          </div>

          {/* Network Endpoints */}
          <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800">
            <div className="flex items-center gap-2 mb-2 text-slate-400 uppercase tracking-wider text-[11px] font-semibold">
              <Network className="w-4 h-4 text-cyan-400" />
              Endpoint Trajectory
            </div>
            <div className="flex items-center justify-between font-mono text-sm bg-slate-900/80 p-3 rounded border border-slate-800/60">
              <div>
                <span className="text-xs text-slate-500 block">SOURCE</span>
                <span className="text-rose-400 font-bold">{alert.source_ip}</span>
                {alert.source_port && <span className="text-slate-500">:{alert.source_port}</span>}
              </div>
              <div className="text-slate-600 font-sans text-xs">➔</div>
              <div className="text-right">
                <span className="text-xs text-slate-500 block">DESTINATION</span>
                <span className="text-slate-300 font-bold">{alert.destination_ip}</span>
                {alert.destination_port && <span className="text-slate-500">:{alert.destination_port}</span>}
              </div>
            </div>
          </div>

          {/* Technical Evidence */}
          <div>
            <div className="flex items-center gap-2 mb-2 text-slate-400 uppercase tracking-wider text-[11px] font-semibold">
              <Terminal className="w-4 h-4 text-amber-400" />
              Inspection Evidence & Signature Match
            </div>
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800/80 font-mono text-xs text-amber-300/90 whitespace-pre-wrap break-all">
              {alert.evidence || "No raw payload evidence logged for this signature."}
            </div>
          </div>

          {/* IPS Action status */}
          <div className="p-3 rounded-lg border border-slate-800/80 bg-slate-950/40 flex items-center justify-between">
            <div>
              <span className="text-[11px] text-slate-500 uppercase tracking-wider block">IPS Enforcement</span>
              <span className="text-slate-300">
                {alert.is_simulated_block
                  ? "Simulated Drop (Monitoring Mode — Traffic Not Disrupted)"
                  : alert.action === "BLOCK"
                  ? "Actual Block Rule Issued"
                  : "Passive Alert Monitored"}
              </span>
            </div>
            <StatusBadge
              status={alert.is_simulated_block ? "Simulated Block" : alert.action}
              type={alert.is_simulated_block ? "simulated" : alert.action === "BLOCK" ? "blocked" : "alert"}
            />
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 px-6 border-t border-slate-800 bg-slate-950/60 flex items-center justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
          >
            Close Details
          </button>
        </div>
      </div>
    </div>
  )
}
