import type { SeverityLevel } from "../../types/security"
import { cn } from "../../utils/cn"

interface SeverityBadgeProps {
  severity: SeverityLevel
  className?: string
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className }) => {
  const styles: Record<SeverityLevel, string> = {
    CRITICAL: "bg-red-500/10 text-red-400 border-red-500/30",
    HIGH: "bg-orange-500/10 text-orange-400 border-orange-500/30",
    MEDIUM: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    LOW: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
  }

  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider border",
        styles[severity] || styles.LOW,
        className
      )}
    >
      {severity}
    </span>
  )
}
