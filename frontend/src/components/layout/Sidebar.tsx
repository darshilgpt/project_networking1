import React from "react"
import { NavLink } from "react-router-dom"
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  GitFork,
  Search,
  Cpu,
  Flame,
  Mail,
  Settings,
  Shield,
  Radio,
} from "lucide-react"

interface NavItem {
  name: string
  path: string
  icon: React.ComponentType<{ className?: string }>
  badge?: string
}

const NAV_ITEMS: NavItem[] = [
  { name: "Overview", path: "/", icon: LayoutDashboard },
  { name: "Live Monitoring", path: "/live", icon: Activity },
  { name: "Security Alerts", path: "/alerts", icon: ShieldAlert, badge: "69" },
  { name: "Network Flows", path: "/flows", icon: GitFork },
  { name: "Packet Inspector", path: "/packets", icon: Search },
  { name: "ML Analytics", path: "/ml", icon: Cpu },
  { name: "Firewall", path: "/firewall", icon: Flame, badge: "Active" },
  { name: "Email Notifications", path: "/notifications", icon: Mail },
  { name: "Settings", path: "/settings", icon: Settings },
]

export const Sidebar: React.FC = () => {
  return (
    <aside className="w-64 shrink-0 bg-slate-950 border-r border-slate-800/80 flex flex-col h-screen select-none">
      {/* Brand Header */}
      <div className="p-4 px-5 border-b border-slate-800/80 flex items-center gap-3">
        <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <span className="font-bold tracking-wider text-sm text-slate-100 flex items-center gap-1.5">
            DPI / NIPS <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 font-mono">SOC</span>
          </span>
          <span className="text-[11px] text-slate-500 block tracking-tight">Intrusion Prevention System</span>
        </div>
      </div>

      {/* Navigation Menu */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
        <div className="text-[10px] font-semibold tracking-wider text-slate-500 uppercase px-3 mb-2">
          Operations Center
        </div>
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              `flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                isActive
                  ? "bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60"
              }`
            }
          >
            <div className="flex items-center gap-3">
              <item.icon className="w-4 h-4 shrink-0" />
              <span>{item.name}</span>
            </div>
            {item.badge && (
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700/60">
                {item.badge}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Engine Status Footer */}
      <div className="p-3.5 mx-3 mb-3 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs text-slate-400">
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-[11px] font-semibold text-slate-300 flex items-center gap-1.5">
            <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
            Detection Engine
          </span>
          <span className="text-[10px] text-emerald-400 font-mono">READY</span>
        </div>
        <p className="text-[10px] text-slate-500 leading-tight">
          Monitoring WireGuard & LAN Subnets with RF/IF ML.
        </p>
      </div>
    </aside>
  )
}

