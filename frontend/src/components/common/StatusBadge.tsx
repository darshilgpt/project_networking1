import React from "react"
import { cn } from "../../utils/cn"

export type StatusType = "active" | "operational" | "simulated" | "blocked" | "warning" | "error" | "disabled" | "neutral" | "alert"

interface StatusBadgeProps {
  status: string
  type?: StatusType
  className?: string
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, type, className }) => {
  const getStyle = (): string => {
    const s = (type || status).toLowerCase()
    if (s.includes("active") || s.includes("operational") || s.includes("configured") || s === "allow") {
      return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
    }
    if (s.includes("simulat")) {
      return "bg-cyan-500/10 text-cyan-400 border-cyan-500/30"
    }
    if (s.includes("block") || s.includes("fail") || s.includes("error") || s.includes("critical")) {
      return "bg-rose-500/10 text-rose-400 border-rose-500/30"
    }
    if (s.includes("alert") || s.includes("warn") || s.includes("degraded")) {
      return "bg-amber-500/10 text-amber-400 border-amber-500/30"
    }
    if (s.includes("disable") || s.includes("closed") || s.includes("not_configured")) {
      return "bg-slate-800 text-slate-400 border-slate-700"
    }
    return "bg-slate-800/60 text-slate-300 border-slate-700/60"
  }

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border uppercase tracking-wider",
        getStyle(),
        className
      )}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {status}
    </span>
  )
}
