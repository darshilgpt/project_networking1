import React from "react"
import { Outlet } from "react-router-dom"
import { Sidebar } from "./Sidebar"
import { Topbar } from "./Topbar"

export const Layout: React.FC = () => {
  return (
    <div className="flex h-screen w-screen bg-slate-950 text-slate-100 overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        <Topbar />
        <main className="flex-1 overflow-y-auto p-6 bg-slate-950/60">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

