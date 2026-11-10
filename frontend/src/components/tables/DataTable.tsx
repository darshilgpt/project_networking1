import type { ReactNode } from "react"

export interface Column<T> {
  header: string
  accessorKey?: keyof T
  cell?: (item: T) => ReactNode
  className?: string
}

interface DataTableProps<T> {
  columns: Column<T>[]
  data: T[]
  keyExtractor?: (item: T) => string | number
  onRowClick?: (item: T) => void
  emptyMessage?: string
}

export function DataTable<T>({
  columns,
  data,
  keyExtractor,
  onRowClick,
  emptyMessage = "No matching records found.",
}: DataTableProps<T>) {
  if (data.length === 0) {
    return (
      <div className="p-8 text-center text-xs text-slate-400 border border-slate-800 rounded-lg bg-slate-900/40">
        {emptyMessage}
      </div>
    )
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900/40">
      <table className="w-full text-left border-collapse text-xs">
        <thead>
          <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-semibold tracking-wider uppercase">
            {columns.map((col, idx) => (
              <th key={idx} className={`py-3 px-3.5 ${col.className || ""}`}>
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60 font-mono">
          {data.map((item, index) => {
            const key = keyExtractor
              ? keyExtractor(item)
              : (item as any)?.alert_id ??
                (item as any)?.flow_id ??
                (item as any)?.packet_id ??
                (item as any)?.rule_id ??
                (item as any)?.id ??
                index

            return (
              <tr
                key={key}
                onClick={() => onRowClick && onRowClick(item)}
                className={`hover:bg-slate-800/30 transition-colors ${
                  onRowClick ? "cursor-pointer" : ""
                }`}
              >
                {columns.map((col, idx) => (
                  <td key={idx} className={`py-2.5 px-3.5 text-slate-300 font-sans ${col.className || ""}`}>
                    {col.cell
                      ? col.cell(item)
                      : col.accessorKey
                      ? String(item[col.accessorKey] ?? "-")
                      : "-"}
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
