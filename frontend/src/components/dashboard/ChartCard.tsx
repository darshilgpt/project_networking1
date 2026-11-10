import type { ReactNode } from "react"
import { cn } from "../../utils/cn"

interface ChartCardProps {
  title: string
  subtitle?: string
  action?: ReactNode
  className?: string
  children: ReactNode
}

export const ChartCard: React.FC<ChartCardProps> = ({ title, subtitle, action, className, children }) => {
  return (
    <div
      className={cn(
        "p-4 rounded-lg bg-slate-900/60 border border-slate-800 backdrop-blur-sm flex flex-col justify-between",
        className
      )}
    >
      <div className="flex items-center justify-between pb-3 mb-2 border-b border-slate-800/80">
        <div>
          <h3 className="text-sm font-semibold tracking-wide text-slate-200 uppercase">{title}</h3>
          {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
        </div>
        {action && <div>{action}</div>}
      </div>
      <div className="flex-1 w-full min-h-[220px]">{children}</div>
    </div>
  )
}
