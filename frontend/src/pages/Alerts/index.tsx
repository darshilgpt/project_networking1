import { useState, useEffect, useMemo } from "react"
import { Search, Download, RefreshCw } from "lucide-react"
import { PageHeader } from "../../components/common/PageHeader"
import { DataTable, type Column } from "../../components/tables/DataTable"
import { SeverityBadge } from "../../components/common/SeverityBadge"
import { StatusBadge } from "../../components/common/StatusBadge"
import { AlertDetailsModal } from "../../components/dashboard/AlertDetailsModal"
import { LoadingState } from "../../components/common/LoadingState"
import { alertsApi } from "../../services/api"
import type { AlertItem } from "../../services/api/types"
import { useSecurityContext } from "../../context/SecurityContext"

const CATEGORIES = [
  "ALL",
  "PORT_SCAN",
  "SYN_FLOOD",
  "SQL_INJECTION",
  "XSS",
  "PATH_TRAVERSAL",
  "COMMAND_INJECTION",
  "DNS_TUNNELING",
  "MALICIOUS_IP",
  "MALICIOUS_DOMAIN",
  "ML_CLASSIFICATION",
  "ML_ANOMALY",
]

const SEVERITIES = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]

export const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<AlertItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchIp, setSearchIp] = useState("")
  const [selectedCategory, setSelectedCategory] = useState("ALL")
  const [selectedSeverity, setSelectedSeverity] = useState("ALL")
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null)
  const { liveAlerts } = useSecurityContext()

  const fetchAlerts = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await alertsApi.getAlerts({
        limit: 100,
        category: selectedCategory !== "ALL" ? selectedCategory : undefined,
        severity: selectedSeverity !== "ALL" ? selectedSeverity : undefined,
        source_ip: searchIp.trim() || undefined,
      })
      setAlerts(res.alerts)
    } catch (err: any) {
      setError(err?.message || "Failed to load security alerts from backend API")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAlerts()
  }, [selectedCategory, selectedSeverity])

  // Merge live incoming alerts
  const combinedAlerts = useMemo(() => {
    const list = [...liveAlerts, ...alerts]
    const map = new Map<number, AlertItem>()
    list.forEach((a) => {
      if (!map.has(a.alert_id)) map.set(a.alert_id, a)
    })
    return Array.from(map.values())
  }, [liveAlerts, alerts])

  const filteredAlerts = useMemo(() => {
    return combinedAlerts.filter((item) => {
      const matchIp =
        !searchIp ||
        item.source_ip.includes(searchIp.trim()) ||
        item.destination_ip.includes(searchIp.trim())
      const matchCat = selectedCategory === "ALL" || item.category === selectedCategory
      const matchSev = selectedSeverity === "ALL" || item.severity === selectedSeverity
      return matchIp && matchCat && matchSev
    })
  }, [combinedAlerts, searchIp, selectedCategory, selectedSeverity])

  const handleExportJson = () => {
    const jsonStr = `data:text/json;charset=utf-8,${encodeURIComponent(
      JSON.stringify(filteredAlerts, null, 2)
    )}`
    const downloadAnchor = document.createElement("a")
    downloadAnchor.setAttribute("href", jsonStr)
    downloadAnchor.setAttribute("download", `security_alerts_${Date.now()}.json`)
    document.body.appendChild(downloadAnchor)
    downloadAnchor.click()
    downloadAnchor.remove()
  }

  const columns: Column<AlertItem>[] = [
    {
      header: "Alert ID",
      accessorKey: "alert_id",
      className: "w-20 font-mono text-slate-500",
    },
    {
      header: "Timestamp",
      accessorKey: "datetime_str",
      className: "w-28 font-mono text-slate-400 text-xs",
    },
    {
      header: "Severity",
      cell: (item) => <SeverityBadge severity={item.severity as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"} />,
    },
    {
      header: "Category",
      accessorKey: "category",
      className: "font-semibold text-slate-200",
    },
    {
      header: "Source IP",
      accessorKey: "source_ip",
      className: "font-mono font-medium text-rose-400",
    },
    {
      header: "Destination",
      cell: (item) => (
        <span className="font-mono text-slate-300">
          {item.destination_ip}:{item.destination_port || "-"}
        </span>
      ),
    },
    {
      header: "Protocol",
      accessorKey: "protocol",
      className: "font-mono text-slate-400 uppercase",
    },
    {
      header: "Action",
      cell: (item) => <StatusBadge status={item.action} />,
    },
    {
      header: "Inspect",
      cell: (item) => (
        <button
          onClick={() => setSelectedAlert(item)}
          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 text-xs font-medium transition-colors"
        >
          Details
        </button>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Alert Management"
        description="Comprehensive audit of intrusion attempts, malicious payloads, and anomaly triggers."
        badge={
          <StatusBadge
            status={`${filteredAlerts.length} Alerts Loaded`}
            type={filteredAlerts.length > 0 ? "warning" : "operational"}
          />
        }
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={fetchAlerts}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
              <span>Refresh</span>
            </button>
            <button
              onClick={handleExportJson}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              <span>Export JSON</span>
            </button>
          </div>
        }
      />

      {/* Filter Controls */}
      <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-wrap gap-4 items-center justify-between">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search by IP */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Filter by IP address..."
              value={searchIp}
              onChange={(e) => setSearchIp(e.target.value)}
              className="pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 font-mono"
            />
          </div>

          {/* Severity Dropdown */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/60"
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                Severity: {s}
              </option>
            ))}
          </select>

          {/* Category Dropdown */}
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/60"
          >
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>
                Category: {c.replace("_", " ")}
              </option>
            ))}
          </select>
        </div>

        <div className="text-xs font-mono text-slate-500">
          Showing {filteredAlerts.length} matching alerts
        </div>
      </div>

      {/* Error Notice */}
      {error && (
        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">
          {error}
        </div>
      )}

      {/* Table */}
      {loading ? (
        <LoadingState message="Fetching live alerts from FastAPI backend..." />
      ) : (
        <DataTable
          columns={columns}
          data={filteredAlerts}
          emptyMessage="No security alerts matched the selected filters."
        />
      )}

      {/* Detail Modal */}
      <AlertDetailsModal
        alert={selectedAlert as any}
        onClose={() => setSelectedAlert(null)}
      />
    </div>
  )
}
