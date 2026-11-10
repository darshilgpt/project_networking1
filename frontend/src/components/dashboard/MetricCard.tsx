import type { ReactNode } from "react"
import type { LucideIcon } from "lucide-react"
import { cn } from "../../utils/cn"

export type MetricVariant =
  | "default"
  | "critical"
  | "warning"
  | "success"
  | "cyan"
  | "blue"
  | "rose"
  | "amber"
  | "emerald"
  | "neutral"

interface MetricCardProps {
  title: string
  value: string | number
  subtitle?: string
  icon?: LucideIcon
  trend?: {
    value: string
    isPositive?: boolean
  }
  variant?: MetricVariant
  className?: string
  children?: ReactNode
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  variant = "default",
  className,
  children,
}) => {
  const borderVariants: Record<MetricVariant, string> = {
    default: "border-slate-800 hover:border-slate-700",
    critical: "border-rose-900/40 hover:border-rose-700/60",
    warning: "border-amber-900/40 hover:border-amber-700/60",
    success: "border-emerald-900/40 hover:border-emerald-700/60",
    cyan: "border-cyan-900/40 hover:border-cyan-700/60",
    blue: "border-blue-900/40 hover:border-blue-700/60",
    rose: "border-rose-900/40 hover:border-rose-700/60",
    amber: "border-amber-900/40 hover:border-amber-700/60",
    emerald: "border-emerald-900/40 hover:border-emerald-700/60",
    neutral: "border-slate-800 hover:border-slate-700",
  }

  const iconColors: Record<MetricVariant, string> = {
    default: "text-slate-400 bg-slate-900",
    critical: "text-rose-400 bg-rose-500/10",
    warning: "text-amber-400 bg-amber-500/10",
    success: "text-emerald-400 bg-emerald-500/10",
    cyan: "text-cyan-400 bg-cyan-500/10",
    blue: "text-blue-400 bg-blue-500/10",
    rose: "text-rose-400 bg-rose-500/10",
    amber: "text-amber-400 bg-amber-500/10",
    emerald: "text-emerald-400 bg-emerald-500/10",
    neutral: "text-slate-400 bg-slate-900",
  }

  return (
    <div
      className={cn(
        "relative p-4 rounded-lg bg-slate-900/70 border backdrop-blur-sm transition-all duration-200",
        borderVariants[variant],
        className
      )}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">{title}</span>
        {Icon && (
          <div className={cn("p-1.5 rounded-md", iconColors[variant])}>
            <Icon className="w-4 h-4" />
          </div>
        )}
      </div>

      <div className="mt-2 flex items-baseline justify-between">
        <span className="text-2xl font-bold tracking-tight text-slate-100">{value}</span>
        {trend && (
          <span
            className={cn(
              "text-xs font-semibold px-1.5 py-0.5 rounded",
              trend.isPositive ? "text-emerald-400 bg-emerald-500/10" : "text-rose-400 bg-rose-500/10"
            )}
          >
            {trend.value}
          </span>
        )}
      </div>

      {subtitle && <p className="mt-1 text-xs text-slate-400 font-mono">{subtitle}</p>}
      {children}
    </div>
  )
}
