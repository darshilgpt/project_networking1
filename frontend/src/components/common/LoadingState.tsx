import React from "react"
import { Loader2 } from "lucide-react"

interface LoadingStateProps {
  message?: string
}

export const LoadingState: React.FC<LoadingStateProps> = ({ message = "Loading security telemetry..." }) => {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center rounded-lg border border-slate-800 bg-slate-900/30">
      <Loader2 className="w-6 h-6 text-cyan-400 animate-spin mb-3" />
      <p className="text-xs font-medium text-slate-400 tracking-wide uppercase">{message}</p>
    </div>
  )
}

