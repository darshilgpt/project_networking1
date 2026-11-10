import { useState, useEffect, useMemo } from "react"
import { Search, RefreshCw } from "lucide-react"
import { PageHeader } from "../../components/common/PageHeader"
import { DataTable, type Column } from "../../components/tables/DataTable"
import { StatusBadge } from "../../components/common/StatusBadge"
import { LoadingState } from "../../components/common/LoadingState"
import { flowsApi } from "../../services/api"
import type { FlowItem } from "../../services/api/types"
import { formatBytes, formatNumber } from "../../utils/cn"

const PROTOCOLS = ["ALL", "TCP", "UDP", "ICMP"]

export const FlowsPage: React.FC = () => {
  const [flows, setFlows] = useState<FlowItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState("")
  const [selectedProtocol, setSelectedProtocol] = useState("ALL")
  const [onlyActive, setOnlyActive] = useState(false)

  const fetchFlows = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await flowsApi.getFlows({
        limit: 100,
        protocol: selectedProtocol !== "ALL" ? selectedProtocol : undefined,
        is_active: onlyActive ? true : undefined,
      })
      setFlows(res.flows)
    } catch (err: any) {
      setError(err?.message || "Failed to load flow records from backend API")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchFlows()
  }, [selectedProtocol, onlyActive])

  const filteredFlows = useMemo(() => {
    return flows.filter((flow) => {
      const matchSearch =
        !search ||
        flow.source_ip.includes(search.trim()) ||
        flow.destination_ip.includes(search.trim()) ||
        flow.application_protocol.toLowerCase().includes(search.toLowerCase())
      return matchSearch
    })
  }, [flows, search])

  const columns: Column<FlowItem>[] = [
    {
      header: "Flow ID",
      accessorKey: "flow_id",
      className: "w-20 font-mono text-slate-500",
    },
    {
      header: "Protocol",
      cell: (f) => (
        <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-400 font-semibold">
          {f.protocol}
        </span>
      ),
    },
    {
      header: "Source (L3/L4)",
      cell: (f) => (
        <span className="font-mono text-slate-200">
          {f.source_ip}:{f.source_port}
        </span>
      ),
    },
    {
      header: "Destination (L3/L4)",
      cell: (f) => (
        <span className="font-mono text-slate-300">
          {f.destination_ip}:{f.destination_port}
        </span>
      ),
    },
    {
      header: "L7 Service",
      accessorKey: "application_protocol",
      className: "font-semibold text-slate-300",
    },
    {
      header: "TCP State",
      accessorKey: "tcp_state",
      className: "font-mono text-xs text-slate-400 uppercase",
    },
    {
      header: "Packets",
      cell: (f) => <span className="font-mono">{formatNumber(f.total_packets)}</span>,
    },
    {
      header: "Volume",
      cell: (f) => <span className="font-mono text-slate-400">{formatBytes(f.total_bytes)}</span>,
    },
    {
      header: "Duration",
      cell: (f) => <span className="font-mono text-slate-400">{f.duration_seconds.toFixed(1)}s</span>,
    },
    {
      header: "Status",
      cell: (f) => (
        <StatusBadge
          status={f.is_active ? "Active" : "Closed"}
          type={f.is_active ? "active" : "neutral"}
        />
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title="Network Connection Flows"
        description="Bidirectional IP 5-tuple tracking, TCP state machine transitions, and session volumes."
        badge={
          <StatusBadge
            status={`${filteredFlows.length} Flows`}
            type="operational"
          />
        }
        actions={
          <button
            onClick={fetchFlows}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
            <span>Refresh</span>
          </button>
        }
      />

      {/* Filter Bar */}
      <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-wrap gap-4 items-center justify-between">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by IP or protocol..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 font-mono"
            />
          </div>

          <select
            value={selectedProtocol}
            onChange={(e) => setSelectedProtocol(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/60"
          >
            {PROTOCOLS.map((p) => (
              <option key={p} value={p}>
                Protocol: {p}
              </option>
            ))}
          </select>

          <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={onlyActive}
              onChange={(e) => setOnlyActive(e.target.checked)}
              className="rounded bg-slate-950 border-slate-800 text-cyan-500 focus:ring-0"
            />
            <span>Active flows only</span>
          </label>
        </div>

        <div className="text-xs font-mono text-slate-500">
          Showing {filteredFlows.length} flows
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">
          {error}
        </div>
      )}

      {loading ? (
        <LoadingState message="Fetching flows from FastAPI backend..." />
      ) : (
        <DataTable
          columns={columns}
          data={filteredFlows}
          emptyMessage="No connection flows matching filter criteria."
        />
      )}
    </div>
  )
}
