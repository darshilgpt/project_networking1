import { AlertTriangle } from "lucide-react"

interface ConfirmationDialogProps {
  isOpen: boolean
  title: string
  message: string
  confirmText?: string
  cancelText?: string
  isDestructive?: boolean
  onConfirm: () => void
  onCancel: () => void
}

export const ConfirmationDialog: React.FC<ConfirmationDialogProps> = ({
  isOpen,
  title,
  message,
  confirmText = "Confirm",
  cancelText = "Cancel",
  isDestructive = false,
  onConfirm,
  onCancel,
}) => {
  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden p-6">
        <div className="flex items-start gap-4">
          <div
            className={`p-2.5 rounded-full shrink-0 ${
              isDestructive ? "bg-rose-500/10 text-rose-400" : "bg-cyan-500/10 text-cyan-400"
            }`}
          >
            <AlertTriangle className="w-6 h-6" />
          </div>
          <div className="flex-1">
            <h3 className="text-base font-bold text-slate-100">{title}</h3>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">{message}</p>
          </div>
        </div>

        <div className="mt-6 flex items-center justify-end gap-3">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800 rounded-lg transition-colors"
          >
            {cancelText}
          </button>
          <button
            onClick={onConfirm}
            className={`px-4 py-2 text-xs font-semibold rounded-lg shadow-sm transition-colors ${
              isDestructive
                ? "bg-rose-600 hover:bg-rose-500 text-white"
                : "bg-cyan-600 hover:bg-cyan-500 text-white"
            }`}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  )
}
