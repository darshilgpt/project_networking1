import { useState, useEffect } from "react"
import { Activity, Radio, Cpu, Network, Play, Pause, RefreshCw } from "lucide-react"
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip } from "recharts"
import { PageHeader } from "../../components/common/PageHeader"
import { MetricCard } from "../../components/dashboard/MetricCard"
import { ChartCard } from "../../components/dashboard/ChartCard"
import { StatusBadge } from "../../components/common/StatusBadge"
import { statsApi } from "../../services/api"
import type { StatisticsResponse } from "../../services/api/types"
import { useSecurityContext } from "../../context/SecurityContext"
import { formatBytes, formatNumber } from "../../utils/cn"

interface TimelinePoint {
  time: string
  pps: number
  kbps: number
  flows: number
}

export const LiveMonitoringPage: React.FC = () => {
  const [isPaused, setIsPaused] = useState(false)
  const [stats, setStats] = useState<StatisticsResponse | null>(null)
  const [timeline, setTimeline] = useState<TimelinePoint[]>([])
  const { wsStatus, latestTraffic } = useSecurityContext()

  // Fetch baseline stats
  const fetchStats = async () => {
    try {
      const data = await statsApi.getStatistics()
      setStats(data)
    } catch (err) {
      console.error("Error fetching stats:", err)
    }
  }

  useEffect(() => {
    fetchStats()
  }, [])

  // Push new timeline points from either live WS traffic or polling fallback
  useEffect(() => {
    if (isPaused) return

    const nowStr = new Date().toLocaleTimeString().slice(3, 8)
    const currentPps = latestTraffic?.packets_per_sec ?? stats?.packets_per_sec ?? 0.0
    const currentBytesPerSec = latestTraffic?.bytes_per_sec ?? stats?.bytes_per_sec ?? 0.0
    const currentFlows = latestTraffic?.active_flows ?? stats?.active_flows ?? 0

    const newPoint: TimelinePoint = {
      time: nowStr,
      pps: Math.round(currentPps),
      kbps: Math.round((currentBytesPerSec * 8) / 1024),
      flows: currentFlows,
    }

    setTimeline((prev) => {
      const next = [...prev, newPoint]
      return next.slice(-20) // Keep latest 20 points
    })
  }, [latestTraffic, isPaused])

  const pps = latestTraffic?.packets_per_sec ?? stats?.packets_per_sec ?? 0
  const bps = latestTraffic?.bytes_per_sec ?? stats?.bytes_per_sec ?? 0
  const activeFlows = latestTraffic?.active_flows ?? stats?.active_flows ?? 0
  const activeWorkers = latestTraffic?.active_workers ?? stats?.active_workers ?? 1

  return (
    <div className="space-y-6">
      <PageHeader
        title="Live Traffic & Packet Monitoring"
        description="Continuous packet throughput, flow dynamics, and buffer processing telemetry."
        badge={
          <div className="flex items-center gap-2">
            <StatusBadge
              status={wsStatus === "connected" ? "WS: Stream Active" : `WS: ${wsStatus.toUpperCase()}`}
              type={wsStatus === "connected" ? "active" : "warning"}
            />
            <span className="text-xs font-mono text-slate-500">CADENCE: 1.0s</span>
          </div>
        }
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsPaused(!isPaused)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
            >
              {isPaused ? (
                <>
                  <Play className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Resume Stream</span>
                </>
              ) : (
                <>
                  <Pause className="w-3.5 h-3.5 text-amber-400" />
                  <span>Pause Stream</span>
                </>
              )}
            </button>
            <button
              onClick={fetchStats}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
              <span>Refresh Stats</span>
            </button>
          </div>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Instantaneous Packet Rate"
          value={`${formatNumber(pps)} pkts/s`}
          subtitle="Real-time DPI ingestion buffer"
          icon={Radio}
          variant="cyan"
        />
        <MetricCard
          title="Network Bandwidth"
          value={`${formatBytes(bps)}/s`}
          subtitle={`Total: ${formatBytes(latestTraffic?.total_bytes ?? stats?.total_bytes_processed ?? 0)}`}
          icon={Activity}
          variant="blue"
        />
        <MetricCard
          title="Concurrent Active Flows"
          value={formatNumber(activeFlows)}
          subtitle="Bidirectional IP 5-tuple table"
          icon={Network}
          variant="emerald"
        />
        <MetricCard
          title="Worker Pipelines"
          value={activeWorkers}
          subtitle="Multithreaded packet workers"
          icon={Cpu}
          variant="amber"
        />
      </div>

      {/* Live Chart: Throughput */}
      <ChartCard
        title="Live Traffic Velocity (Packets & Bandwidth)"
        subtitle="Dynamic time-series updated over WebSocket"
      >
        <div className="h-72 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={timeline.length > 0 ? timeline : [{ time: "0s", pps: 0, kbps: 0, flows: 0 }]}>
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
              <Line
                type="monotone"
                dataKey="pps"
                name="Packets / Sec"
                stroke="#06b6d4"
                strokeWidth={2}
                dot={false}
              />
              <Line
                type="monotone"
                dataKey="kbps"
                name="Bandwidth (Kbps)"
                stroke="#10b981"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </ChartCard>
    </div>
  )
}
