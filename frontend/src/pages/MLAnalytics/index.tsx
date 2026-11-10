import { useState, useEffect } from "react"
import { Cpu, Brain, Zap, Clock, AlertTriangle, RefreshCw } from "lucide-react"
import { PageHeader } from "../../components/common/PageHeader"
import { MetricCard } from "../../components/dashboard/MetricCard"
import { StatusBadge } from "../../components/common/StatusBadge"
import { LoadingState } from "../../components/common/LoadingState"
import { mlApi } from "../../services/api"
import type { MLStatusResponse } from "../../services/api/types"
import { formatNumber } from "../../utils/cn"

export const MLAnalyticsPage: React.FC = () => {
  const [mlStatus, setMlStatus] = useState<MLStatusResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchMlStatus = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await mlApi.getStatus()
      setMlStatus(res)
    } catch (err: any) {
      setError(err?.message || "Failed to load ML runtime status from backend API")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchMlStatus()
  }, [])

  const metrics = mlStatus?.metrics

  return (
    <div className="space-y-6">
      <PageHeader
        title="Machine Learning Telemetry & Analytics"
        description="Dual-engine threat classification (Random Forest) and behavioral outlier anomaly detection (Isolation Forest)."
        badge={
          <StatusBadge
            status={
              mlStatus?.enabled
                ? mlStatus.random_forest_loaded && mlStatus.isolation_forest_loaded
                  ? "Dual Models Operational"
                  : "Partial Models Loaded"
                : "ML Disabled"
            }
            type={mlStatus?.enabled ? "operational" : "warning"}
          />
        }
        actions={
          <button
            onClick={fetchMlStatus}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
            <span>Refresh</span>
          </button>
        }
      />

      {error && (
        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">
          {error}
        </div>
      )}

      {loading ? (
        <LoadingState message="Loading ML telemetry from backend..." />
      ) : (
        <>
          {/* KPI Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <MetricCard
              title="Inference Latency"
              value={
                metrics?.avg_inference_latency_ms !== undefined
                  ? `${metrics.avg_inference_latency_ms.toFixed(2)} ms`
                  : "N/A"
              }
              subtitle="Non-blocking asynchronous worker"
              icon={Zap}
              variant="cyan"
            />
            <MetricCard
              title="Jobs Processed"
              value={metrics ? formatNumber(metrics.jobs_processed) : "0"}
              subtitle={`Submitted: ${metrics ? formatNumber(metrics.jobs_submitted) : 0}`}
              icon={Cpu}
              variant="blue"
            />
            <MetricCard
              title="Queue Drops"
              value={metrics ? formatNumber(metrics.queue_drops) : "0"}
              subtitle={`Current depth: ${mlStatus?.queue_depth ?? 0} / ${mlStatus?.queue_capacity ?? 1000}`}
              icon={Clock}
              variant={metrics?.queue_drops ? "rose" : "emerald"}
            />
            <MetricCard
              title="Inference Failures"
              value={metrics ? formatNumber(metrics.inference_failures) : "0"}
              subtitle="Worker process exceptions"
              icon={AlertTriangle}
              variant={metrics?.inference_failures ? "rose" : "neutral"}
            />
          </div>

          {/* Model Status Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Random Forest Classifier */}
            <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2.5">
                  <Brain className="w-5 h-5 text-cyan-400" />
                  <div>
                    <h3 className="text-sm font-bold text-slate-100">Supervised Attack Classifier</h3>
                    <span className="text-xs text-slate-400">Random Forest (100 estimators, 42 features)</span>
                  </div>
                </div>
                <StatusBadge
                  status={mlStatus?.random_forest_loaded ? "Model Ready" : "Unloaded"}
                  type={mlStatus?.random_forest_loaded ? "operational" : "warning"}
                />
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded bg-slate-950 border border-slate-800/80">
                  <span className="text-slate-500 block">Classifications</span>
                  <span className="text-base font-bold font-mono text-cyan-400">
                    {formatNumber(metrics?.rf_classifications ?? 0)}
                  </span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800/80">
                  <span className="text-slate-500 block">Target Attacks</span>
                  <span className="text-slate-200 font-mono">DDoS, Scan, Injections</span>
                </div>
              </div>
            </div>

            {/* Isolation Forest Anomaly Detector */}
            <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2.5">
                  <Zap className="w-5 h-5 text-amber-400" />
                  <div>
                    <h3 className="text-sm font-bold text-slate-100">Unsupervised Anomaly Detector</h3>
                    <span className="text-xs text-slate-400">Isolation Forest (Contamination: 0.01)</span>
                  </div>
                </div>
                <StatusBadge
                  status={mlStatus?.isolation_forest_loaded ? "Model Ready" : "Unloaded"}
                  type={mlStatus?.isolation_forest_loaded ? "operational" : "warning"}
                />
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded bg-slate-950 border border-slate-800/80">
                  <span className="text-slate-500 block">Anomalies Detected</span>
                  <span className="text-base font-bold font-mono text-amber-400">
                    {formatNumber(metrics?.if_anomalies ?? 0)}
                  </span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800/80">
                  <span className="text-slate-500 block">Detection Profile</span>
                  <span className="text-slate-200 font-mono">Statistical Outliers</span>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
