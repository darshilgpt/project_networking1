import type { ReactNode } from "react"

interface PageHeaderProps {
  title: string
  description?: string
  badge?: ReactNode
  actions?: ReactNode
}

export const PageHeader: React.FC<PageHeaderProps> = ({ title, description, badge, actions }) => {
  return (
    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-800/80 mb-6">
      <div>
        <div className="flex items-center gap-3">
          <h1 className="text-xl md:text-2xl font-bold tracking-tight text-slate-100">{title}</h1>
          {badge}
        </div>
        {description && <p className="text-xs md:text-sm text-slate-400 mt-1 max-w-2xl">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2.5 flex-wrap">{actions}</div>}
    </div>
  )
}
