import { useState, useEffect } from "react"
import { Plus, Trash2, AlertTriangle, RefreshCw, Key, Shield } from "lucide-react"
import { PageHeader } from "../../components/common/PageHeader"
import { DataTable, type Column } from "../../components/tables/DataTable"
import { StatusBadge } from "../../components/common/StatusBadge"
import { ConfirmationDialog } from "../../components/common/ConfirmationDialog"
import { LoadingState } from "../../components/common/LoadingState"
import { firewallApi } from "../../services/api"
import type { FirewallRuleItem, FirewallRulesListResponse } from "../../services/api/types"
import { useSecurityContext } from "../../context/SecurityContext"

export const FirewallPage: React.FC = () => {
  const [data, setData] = useState<FirewallRulesListResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [targetUnblock, setTargetUnblock] = useState<FirewallRuleItem | null>(null)
  const [isAddModalOpen, setIsAddModalOpen] = useState(false)
  const [newIp, setNewIp] = useState("")
  const [newDuration, setNewDuration] = useState(300)
  const [newReason, setNewReason] = useState("")
  const [actionMessage, setActionMessage] = useState<string | null>(null)

  const { adminApiKey, setAdminApiKey } = useSecurityContext()
  const [keyInput, setKeyInput] = useState(adminApiKey || "")

  const fetchRules = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await firewallApi.getRules()
      setData(res)
    } catch (err: any) {
      setError(err?.message || "Failed to load firewall rules from backend API")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchRules()
  }, [])

  const handleSaveApiKey = (e: React.FormEvent) => {
    e.preventDefault()
    setAdminApiKey(keyInput.trim() || null)
    setActionMessage("API key stored in session memory (never persisted to localStorage).")
    setTimeout(() => setActionMessage(null), 3000)
  }

  const handleConfirmUnblock = async () => {
    if (!targetUnblock) return
    setError(null)
    try {
      const res = await firewallApi.unblockRule(targetUnblock.rule_id, adminApiKey || undefined)
      setActionMessage(res.message)
      setTargetUnblock(null)
      fetchRules()
    } catch (err: any) {
      setError(err?.message || "Unblock operation failed. Check administrative authorization.")
      setTargetUnblock(null)
    }
  }

  const handleAddBlock = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newIp.trim()) return
    setError(null)

    try {
      const res = await firewallApi.blockIp(
        {
          ip_address: newIp.trim(),
          duration_seconds: newDuration,
          reason: newReason.trim() || "Manual Administrator Block",
        },
        adminApiKey || undefined
      )
      setActionMessage(res.message)
      setIsAddModalOpen(false)
      setNewIp("")
      fetchRules()
    } catch (err: any) {
      setError(err?.message || "Failed to add block rule. Ensure administrative key is authorized.")
    }
  }

  const rules = data?.rules || []

  const columns: Column<FirewallRuleItem>[] = [
    {
      header: "Rule ID",
      accessorKey: "rule_id",
      className: "w-28 font-mono text-slate-500",
    },
    {
      header: "Target IP",
      accessorKey: "ip_address",
      className: "font-mono font-bold text-rose-400",
    },
    {
      header: "Enforcement Type",
      cell: (r) => (
        <StatusBadge
          status={r.is_simulated ? "SIMULATED (Internal)" : "ACTIVE (OS Netsh/IPTables)"}
          type={r.is_simulated ? "simulated" : "blocked"}
        />
      ),
    },
    {
      header: "Reason / Threat Context",
      accessorKey: "reason",
      className: "text-slate-300 font-medium",
    },
    {
      header: "Duration",
      cell: (r) => <span className="font-mono text-slate-400">{r.duration_seconds}s</span>,
    },
    {
      header: "State",
      cell: (r) => (
        <StatusBadge
          status={r.is_active ? "Enforcing" : "Expired"}
          type={r.is_active ? "blocked" : "neutral"}
        />
      ),
    },
    {
      header: "Action",
      cell: (r) => (
        <button
          onClick={() => setTargetUnblock(r)}
          className="flex items-center gap-1 px-2.5 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 text-xs font-semibold transition-colors"
        >
          <Trash2 className="w-3.5 h-3.5" />
          <span>Unblock</span>
        </button>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title="Firewall & IPS Gateway Enforcement"
        description="Inspect and administer active kernel / netsh packet drop rules and simulated mitigation states."
        badge={
          <StatusBadge
            status={
              data?.enforcement_mechanism === "SIMULATION"
                ? "SIMULATION MODE (Safe Lab)"
                : `Active (${data?.enforcement_mechanism || "None"})`
            }
            type={data?.enforcement_mechanism === "SIMULATION" ? "simulated" : "active"}
          />
        }
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={fetchRules}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
              <span>Refresh</span>
            </button>
            <button
              onClick={() => setIsAddModalOpen(true)}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Block IP Address</span>
            </button>
          </div>
        }
      />

      {/* Enforcement Mechanism Guarantee Banner */}
      <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 flex items-start gap-3">
        <Shield className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 space-y-1">
          <div className="font-semibold text-slate-100 flex items-center gap-2">
            <span>Enforcement Truthfulness Notice</span>
            <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 text-[10px] uppercase font-mono">
              {data?.enforcement_mechanism || "SIMULATION"}
            </span>
          </div>
          <p className="text-slate-400 leading-relaxed">
            {data?.enforcement_mechanism === "SIMULATION"
              ? "All firewall drops recorded here are simulated within the DPI stream. They do NOT modify host Windows netsh or Linux iptables kernel tables. The system strictly separates simulated defensive actions from true OS-level packet drops."
              : "Active kernel mitigation is enabled. Dropped packets are rejected at the host network layer."}
          </p>
        </div>
      </div>

      {/* Admin Authorization Key Bar */}
      <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <form onSubmit={handleSaveApiKey} className="flex items-center gap-3 flex-1 max-w-lg">
          <Key className="w-4 h-4 text-cyan-400 shrink-0" />
          <input
            type="password"
            placeholder="Enter Admin API Key for block/unblock mutations..."
            value={keyInput}
            onChange={(e) => setKeyInput(e.target.value)}
            className="flex-1 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
          <button
            type="submit"
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium"
          >
            Apply Key
          </button>
        </form>
        <span className="text-xs text-slate-500 font-mono">
          {adminApiKey ? "✓ Key Set (In Memory)" : "⚠ Authorization Required for Changes"}
        </span>
      </div>

      {/* Status Banners */}
      {actionMessage && (
        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-medium">
          {actionMessage}
        </div>
      )}
      {error && (
        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-medium">
          {error}
        </div>
      )}

      {loading ? (
        <LoadingState message="Fetching active firewall rules from backend..." />
      ) : (
        <DataTable
          columns={columns}
          data={rules}
          emptyMessage="No active firewall block rules are currently configured."
        />
      )}

      {/* Add Block Modal */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-amber-400" />
              Configure Firewall Drop Rule
            </h3>
            <p className="text-xs text-slate-400">
              Drop inbound/outbound packets for the designated IP address. Requires administrative authorization.
            </p>

            <form onSubmit={handleAddBlock} className="space-y-3">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Target IP Address (IPv4 or IPv6)
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 198.51.100.44"
                  value={newIp}
                  onChange={(e) => setNewIp(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Block Duration (Seconds)
                </label>
                <input
                  type="number"
                  min="10"
                  max="86400"
                  value={newDuration}
                  onChange={(e) => setNewDuration(Number(e.target.value))}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Justification / Incident Note
                </label>
                <input
                  type="text"
                  placeholder="e.g. Hostile SYN Flood source"
                  value={newReason}
                  onChange={(e) => setNewReason(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsAddModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold"
                >
                  Apply Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Unblock Confirmation Dialog */}
      <ConfirmationDialog
        isOpen={!!targetUnblock}
        title="Confirm Firewall Rule Removal"
        message={`Are you sure you want to remove the block rule for ${targetUnblock?.ip_address}? Inbound and outbound packets from this IP will be re-allowed.`}
        confirmText="Remove Rule"
        isDestructive={true}
        onConfirm={handleConfirmUnblock}
        onCancel={() => setTargetUnblock(null)}
      />
    </div>
  )
}
