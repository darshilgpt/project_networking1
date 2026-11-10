import type { ReactNode } from "react"
import type { LucideIcon } from "lucide-react"
import { Inbox } from "lucide-react"

interface EmptyStateProps {
  title?: string
  description?: string
  icon?: LucideIcon
  action?: ReactNode
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title = "No data found",
  description = "No entries match your current search or filter criteria.",
  icon: Icon = Inbox,
  action,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-8 my-4 text-center rounded-lg border border-dashed border-slate-800 bg-slate-900/30">
      <div className="p-3 rounded-full bg-slate-800/60 text-slate-400 mb-3">
        <Icon className="w-6 h-6" />
      </div>
      <h4 className="text-sm font-medium text-slate-200">{title}</h4>
      <p className="text-xs text-slate-400 max-w-sm mt-1">{description}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
