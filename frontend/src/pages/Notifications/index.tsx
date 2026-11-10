import { useState, useEffect } from "react"
import { Mail, CheckCircle2, AlertOctagon, Clock, UserCheck, RefreshCw, ShieldAlert } from "lucide-react"
import { PageHeader } from "../../components/common/PageHeader"
import { MetricCard } from "../../components/dashboard/MetricCard"
import { StatusBadge } from "../../components/common/StatusBadge"
import { LoadingState } from "../../components/common/LoadingState"
import { notificationsApi } from "../../services/api"
import type { NotificationStatusResponse } from "../../services/api/types"

export const NotificationsPage: React.FC = () => {
  const [status, setStatus] = useState<NotificationStatusResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchStatus = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await notificationsApi.getStatus()
      setStatus(res)
    } catch (err: any) {
      setError(err?.message || "Failed to load notification system status from backend API")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchStatus()
  }, [])

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Email Notification System"
        description="Automated intrusion alert dispatches, duplicate suppression, and SMTP worker health."
        badge={
          <StatusBadge
            status={
              status?.enabled
                ? status.smtp_status === "configured"
                  ? "Worker Active (SMTP Ready)"
                  : "Worker Active (SMTP Unset)"
                : "Notifications Disabled"
            }
            type={status?.enabled ? "active" : "disabled"}
          />
        }
        actions={
          <button
            onClick={fetchStatus}
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
        <LoadingState message="Fetching notification status from backend..." />
      ) : status ? (
        <>
          {/* KPI Row */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <MetricCard
              title="Emails Delivered"
              value={status.emails_delivered}
              subtitle={`Submitted: ${status.emails_submitted}`}
              icon={CheckCircle2}
              variant="success"
            />
            <MetricCard
              title="Suppressed (Cooldown)"
              value={status.emails_suppressed}
              subtitle={`${status.cooldown_seconds}s window duplicate prevention`}
              icon={Clock}
              variant="blue"
            />
            <MetricCard
              title="Delivery Failures"
              value={status.emails_failed}
              subtitle={`Queue Drops: ${status.queue_full_drops}`}
              icon={AlertOctagon}
              variant={status.emails_failed > 0 ? "rose" : "neutral"}
            />
            <MetricCard
              title="Configured Recipients"
              value={status.recipients_count}
              subtitle="Designated security contacts"
              icon={UserCheck}
              variant="cyan"
            />
          </div>

          {/* Configuration & Safety Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2 border-b border-slate-800 pb-3">
                <Mail className="w-4 h-4 text-cyan-400" />
                Asynchronous Dispatch Queue Status
              </h3>

              <div className="space-y-3 text-xs">
                <div className="flex justify-between items-center py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Queue Depth / Capacity:</span>
                  <span className="font-mono text-slate-200">
                    {status.queue_depth} / {status.queue_capacity}
                  </span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Worker Thread Execution:</span>
                  <span className="font-mono text-emerald-400">Non-blocking background thread</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Duplicate Alert Cooldown:</span>
                  <span className="font-mono text-slate-200">{status.cooldown_seconds} seconds</span>
                </div>
                <div className="flex justify-between items-center py-1.5">
                  <span className="text-slate-400">Queue Full Policy:</span>
                  <span className="font-mono text-amber-400">Drop & Log (Preserves DPI loop)</span>
                </div>
              </div>
            </div>

            <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2 border-b border-slate-800 pb-3">
                <ShieldAlert className="w-4 h-4 text-emerald-400" />
                SMTP Credential Privacy
              </h3>

              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400 leading-relaxed space-y-2">
                <p>
                  <strong className="text-slate-200">Zero-Secret Exposure Contract:</strong> The backend strictly excludes SMTP host addresses, port credentials, usernames, and passwords from all REST responses.
                </p>
                <div className="pt-2 flex items-center gap-2">
                  <span className="text-slate-400">SMTP Server Status:</span>
                  <StatusBadge
                    status={status.smtp_status === "configured" ? "Configured" : "Not Configured"}
                    type={status.smtp_status === "configured" ? "operational" : "warning"}
                  />
                </div>
              </div>
            </div>
          </div>
        </>
      ) : null}
    </div>
  )
}
