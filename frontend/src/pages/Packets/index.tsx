import { useState, useEffect } from "react"
import { ShieldCheck, AlertCircle, RefreshCw } from "lucide-react"
import { PageHeader } from "../../components/common/PageHeader"
import { DataTable, type Column } from "../../components/tables/DataTable"
import { StatusBadge } from "../../components/common/StatusBadge"
import { LoadingState } from "../../components/common/LoadingState"
import { packetsApi } from "../../services/api"
import type { PacketItem } from "../../services/api/types"

export const PacketsPage: React.FC = () => {
  const [packets, setPackets] = useState<PacketItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedPacket, setSelectedPacket] = useState<PacketItem | null>(null)

  const fetchPackets = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await packetsApi.getPackets({ limit: 50 })
      setPackets(res.packets)
    } catch (err: any) {
      setError(err?.message || "Failed to load recent packet metadata from backend API")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchPackets()
  }, [])

  const columns: Column<PacketItem>[] = [
    {
      header: "Packet ID",
      accessorKey: "packet_id",
      className: "w-24 font-mono text-slate-500",
    },
    {
      header: "Timestamp",
      accessorKey: "datetime_str",
      className: "w-24 font-mono text-slate-400",
    },
    {
      header: "Network",
      accessorKey: "network_type",
      className: "font-semibold text-slate-300",
    },
    {
      header: "Source",
      cell: (p) => (
        <span className="font-mono text-slate-200">
          {p.source_ip}{p.source_port ? `:${p.source_port}` : ""}
        </span>
      ),
    },
    {
      header: "Destination",
      cell: (p) => (
        <span className="font-mono text-slate-300">
          {p.destination_ip}{p.destination_port ? `:${p.destination_port}` : ""}
        </span>
      ),
    },
    {
      header: "Transport / L7",
      cell: (p) => (
        <span className="text-xs font-mono text-cyan-400">
          {p.transport_type} {p.application_protocol ? `(${p.application_protocol})` : ""}
        </span>
      ),
    },
    {
      header: "Bytes",
      cell: (p) => <span className="font-mono text-slate-400">{p.packet_length_bytes} B</span>,
    },
    {
      header: "Decision",
      cell: (p) => (
        <StatusBadge
          status={p.decision}
          type={p.decision === "ALLOW" ? "operational" : "blocked"}
        />
      ),
    },
    {
      header: "Inspect",
      cell: (p) => (
        <button
          onClick={() => setSelectedPacket(p)}
          className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-medium"
        >
          View
        </button>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title="Packet Metadata Inspector"
        description="Bounded packet header summaries strictly preserving payload privacy and compliance."
        badge={<StatusBadge status="Payload Obfuscation Active" type="operational" />}
        actions={
          <button
            onClick={fetchPackets}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
            <span>Refresh</span>
          </button>
        }
      />

      {/* Security Privacy Notice */}
      <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 flex items-start gap-3">
        <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-400">
          <span className="font-semibold text-slate-200 block mb-0.5">Zero-Payload Leak Policy</span>
          In strict compliance with DPI data governance standards, raw payload payloads and cryptographic secrets are not transmitted across the REST API. Only bounded L3/L4/L7 metadata headers are visualized.
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">
          {error}
        </div>
      )}

      {loading ? (
        <LoadingState message="Fetching packet metadata from FastAPI backend..." />
      ) : (
        <DataTable
          columns={columns}
          data={packets}
          emptyMessage="No recent packet metadata captured in the ingestion queue."
        />
      )}

      {/* Selected Packet Header Inspector Modal */}
      {selectedPacket && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-cyan-400" />
                Packet Metadata #{selectedPacket.packet_id}
              </h3>
              <button
                onClick={() => setSelectedPacket(null)}
                className="text-slate-400 hover:text-slate-200 text-xs font-semibold px-2 py-1"
              >
                ✕ Close
              </button>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="grid grid-cols-2 gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div>
                  <span className="text-slate-500 block">Ingress Timestamp</span>
                  <span className="text-slate-200">{selectedPacket.datetime_str}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Network Protocol</span>
                  <span className="text-slate-200">{selectedPacket.network_type}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Source Address</span>
                  <span className="text-slate-200">{selectedPacket.source_ip}:{selectedPacket.source_port}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Destination Address</span>
                  <span className="text-slate-200">{selectedPacket.destination_ip}:{selectedPacket.destination_port}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Payload Length</span>
                  <span className="text-slate-200">{selectedPacket.packet_length_bytes} bytes</span>
                </div>
                <div>
                  <span className="text-slate-500 block">TCP Flags</span>
                  <span className="text-slate-200">{selectedPacket.flags || "None"}</span>
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedPacket(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 text-slate-200 text-xs font-medium"
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
