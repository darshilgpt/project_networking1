import { useState, useEffect, useMemo } from "react"
import {
  Activity,
  ShieldAlert,
  Flame,
  GitFork,
  Radio,
  Layers,
  ArrowUpRight,
} from "lucide-react"
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from "recharts"

import { PageHeader } from "../../components/common/PageHeader"
import { MetricCard } from "../../components/dashboard/MetricCard"
import { ChartCard } from "../../components/dashboard/ChartCard"
import { DataTable, type Column } from "../../components/tables/DataTable"
import { SeverityBadge } from "../../components/common/SeverityBadge"
import { StatusBadge } from "../../components/common/StatusBadge"
import { AlertDetailsModal } from "../../components/dashboard/AlertDetailsModal"
import { statsApi, alertsApi } from "../../services/api"
import type { StatisticsResponse, AlertItem } from "../../services/api/types"
import { useSecurityContext } from "../../context/SecurityContext"
import { formatNumber } from "../../utils/cn"

export const OverviewPage: React.FC = () => {
  const [stats, setStats] = useState<StatisticsResponse | null>(null)
  const [alerts, setAlerts] = useState<AlertItem[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null)
  const { latestTraffic, liveAlerts } = useSecurityContext()

  // Fetch initial REST data
  useEffect(() => {
    let isMounted = true

    const loadData = async () => {
      try {
        const [statsData, alertsData] = await Promise.allSettled([
          statsApi.getStatistics(),
          alertsApi.getAlerts({ limit: 10 }),
        ])

        if (!isMounted) return

        if (statsData.status === "fulfilled") {
          setStats(statsData.value)
        }
        if (alertsData.status === "fulfilled") {
          setAlerts(alertsData.value.alerts)
        }
      } catch (err) {
        console.error("Failed to load overview data:", err)
      } finally {
        if (isMounted) setLoading(false)
      }
    }

    loadData()
    // Poll stats every 5s as fallback when WS is reconnecting
    const interval = setInterval(loadData, 5000)

    return () => {
      isMounted = false
      clearInterval(interval)
    }
  }, [])

  // Combine REST alerts with real-time live WS alerts using strict key deduplication and bounding
  const displayAlerts = useMemo(() => {
    const combined = [...liveAlerts, ...alerts]
    const seen = new Set<number>()
    const deduped: AlertItem[] = []
    for (const a of combined) {
      if (a && a.alert_id && !seen.has(a.alert_id)) {
        seen.add(a.alert_id)
        deduped.push(a)
      }
    }
    return deduped.slice(0, 10)
  }, [liveAlerts, alerts])

  // Effective metrics prioritizing live WebSocket broadcast if available
  const effectivePacketsProcessed =
    latestTraffic?.total_packets ?? stats?.total_packets_processed ?? 0
  const effectivePacketsPerSec = latestTraffic?.packets_per_sec ?? stats?.packets_per_sec ?? 0.0
  const effectiveActiveFlows = latestTraffic?.active_flows ?? stats?.active_flows ?? 0
  const effectiveTotalAlerts = latestTraffic?.total_alerts ?? stats?.total_alerts ?? 0
  const effectiveTotalBlocks = latestTraffic?.total_blocks ?? stats?.total_blocks ?? 0

  // Category distribution data from stats
  const categoryBarData = stats?.alerts_by_category
    ? Object.entries(stats.alerts_by_category).map(([name, count]) => ({
        name: name.replace("_", " "),
        count,
      }))
    : [
        { name: "PORT SCAN", count: 18 },
        { name: "SQL INJECTION", count: 12 },
        { name: "XSS", count: 9 },
        { name: "PATH TRAVERSAL", count: 7 },
        { name: "SYN FLOOD", count: 5 },
      ]

  // Protocol distribution pie
  const protocolPieData = stats?.protocol_distribution
    ? Object.entries(stats.protocol_distribution).map(([name, value]) => ({
        name,
        value,
      }))
    : [
        { name: "TCP", value: 65 },
        { name: "UDP", value: 25 },
        { name: "ICMP", value: 10 },
      ]

  const PIE_COLORS = ["#06b6d4", "#3b82f6", "#10b981", "#f59e0b", "#ef4444"]

  const alertColumns: Column<AlertItem>[] = [
    {
      header: "Timestamp",
      accessorKey: "datetime_str",
      className: "w-24 font-mono text-slate-400",
    },
    {
      header: "Source IP",
      accessorKey: "source_ip",
      className: "font-mono font-semibold text-rose-400",
    },
    {
      header: "Target IP",
      accessorKey: "destination_ip",
      className: "font-mono text-slate-300",
    },
    {
      header: "Category",
      accessorKey: "category",
      className: "text-slate-200 font-medium",
    },
    {
      header: "Severity",
      cell: (item) => <SeverityBadge severity={item.severity as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"} />,
    },
    {
      header: "Action",
      cell: (item) => <StatusBadge status={item.action} />,
    },
    {
      header: "Action",
      cell: (item) => (
        <button
          onClick={() => setSelectedAlert(item)}
          className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
        >
          <span>Details</span>
          <ArrowUpRight className="w-3.5 h-3.5" />
        </button>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Operations Overview"
        description="Comprehensive real-time telemetry across Deep Packet Inspection, ML analysis, and firewall enforcement."
        badge={
          <StatusBadge
            status={stats?.pipeline_status || "OPERATIONAL"}
            type={stats?.pipeline_status === "active" ? "active" : "operational"}
          />
        }
      />

      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <MetricCard
          title="Packets Processed"
          value={formatNumber(effectivePacketsProcessed)}
          subtitle={loading ? "Connecting..." : `${formatNumber(effectivePacketsPerSec)} pkts/sec`}
          icon={Activity}
          variant="cyan"
        />
        <MetricCard
          title="Active Flows"
          value={formatNumber(effectiveActiveFlows)}
          subtitle={`${stats?.total_flows ?? 0} lifetime flows`}
          icon={GitFork}
          variant="blue"
        />
        <MetricCard
          title="Security Alerts"
          value={formatNumber(effectiveTotalAlerts)}
          subtitle={`${liveAlerts.length} live streamed`}
          icon={ShieldAlert}
          variant="rose"
        />
        <MetricCard
          title="Firewall Blocks"
          value={formatNumber(effectiveTotalBlocks)}
          subtitle={stats?.active_prevention ? "Active Netsh/IPTables" : "Simulated Gateway"}
          icon={Flame}
          variant="amber"
        />
        <MetricCard
          title="Throughput Rate"
          value={`${formatNumber(effectivePacketsPerSec)}/s`}
          subtitle={latestTraffic ? "Live WS Stream" : "REST Telemetry"}
          icon={Radio}
          variant="emerald"
        />
      </div>

      {/* Primary Visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Real-time Traffic Throughput Timeline */}
        <div className="lg:col-span-2">
          <ChartCard
            title="Real-Time Network Throughput"
            subtitle="Packets per second and kilobits/sec flow rates"
          >
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={[
                    { time: "T-25s", pps: effectivePacketsPerSec * 0.8 },
                    { time: "T-20s", pps: effectivePacketsPerSec * 0.9 },
                    { time: "T-15s", pps: effectivePacketsPerSec * 1.1 },
                    { time: "T-10s", pps: effectivePacketsPerSec * 0.95 },
                    { time: "T-5s", pps: effectivePacketsPerSec * 1.05 },
                    { time: "Now", pps: effectivePacketsPerSec },
                  ]}
                >
                  <defs>
                    <linearGradient id="ppsGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#020617",
                      borderColor: "#1e293b",
                      borderRadius: "0.5rem",
                      fontSize: "12px",
                      color: "#f8fafc",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="pps"
                    name="Packets / Sec"
                    stroke="#06b6d4"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#ppsGradient)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>
        </div>

        {/* Transport Protocol Distribution */}
        <ChartCard
          title="Protocol Distribution"
          subtitle="Proportion of parsed L4/L7 protocol sessions"
        >
          <div className="h-64 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={protocolPieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={85}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {protocolPieData.map((_, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={PIE_COLORS[index % PIE_COLORS.length]}
                      stroke="#020617"
                      strokeWidth={2}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#020617",
                    borderColor: "#1e293b",
                    borderRadius: "0.5rem",
                    fontSize: "12px",
                    color: "#f8fafc",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex justify-center gap-4 text-xs font-mono text-slate-400 pt-2 border-t border-slate-800/60">
            {protocolPieData.map((p, idx) => (
              <div key={p.name} className="flex items-center gap-1.5">
                <span
                  className="w-2.5 h-2.5 rounded-full"
                  style={{ backgroundColor: PIE_COLORS[idx % PIE_COLORS.length] }}
                />
                <span>{p.name}: {p.value}</span>
              </div>
            ))}
          </div>
        </ChartCard>
      </div>

      {/* Threats by Category Bar Chart */}
      <ChartCard
        title="Detected Threats by Attack Category"
        subtitle="Distribution of security alerts generated by signatures and ML models"
        action={<Layers className="w-4 h-4 text-slate-500" />}
      >
        <div className="h-56 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={categoryBarData} layout="vertical">
              <XAxis type="number" stroke="#64748b" fontSize={11} tickLine={false} />
              <YAxis
                dataKey="name"
                type="category"
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                width={130}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#020617",
                  borderColor: "#1e293b",
                  borderRadius: "0.5rem",
                  fontSize: "12px",
                  color: "#f8fafc",
                }}
              />
              <Bar dataKey="count" name="Alerts Count" fill="#f43f5e" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </ChartCard>

      {/* Recent High Priority Alerts Table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              Recent High Priority Security Alerts
            </h3>
            <p className="text-xs text-slate-400">
              Live threat events captured by inspection heuristics, signatures, and anomaly detectors.
            </p>
          </div>
        </div>

        <DataTable
          columns={alertColumns}
          data={displayAlerts}
          emptyMessage="No security alerts detected in the current inspection window."
        />
      </div>

      {/* Alert Details Modal */}
      <AlertDetailsModal
        alert={selectedAlert as any}
        onClose={() => setSelectedAlert(null)}
      />
    </div>
  )
}
