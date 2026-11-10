import { Routes, Route } from "react-router-dom"
import { SecurityProvider } from "./context/SecurityContext"
import { Layout } from "./components/layout/Layout"
import { OverviewPage } from "./pages/Overview"
import { LiveMonitoringPage } from "./pages/LiveMonitoring"
import { AlertsPage } from "./pages/Alerts"
import { FlowsPage } from "./pages/Flows"
import { PacketsPage } from "./pages/Packets"
import { MLAnalyticsPage } from "./pages/MLAnalytics"
import { FirewallPage } from "./pages/Firewall"
import { NotificationsPage } from "./pages/Notifications"
import { SettingsPage } from "./pages/Settings"

export function App() {
  return (
    <SecurityProvider>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<OverviewPage />} />
          <Route path="live" element={<LiveMonitoringPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="flows" element={<FlowsPage />} />
          <Route path="packets" element={<PacketsPage />} />
          <Route path="ml" element={<MLAnalyticsPage />} />
          <Route path="firewall" element={<FirewallPage />} />
          <Route path="notifications" element={<NotificationsPage />} />
          <Route path="settings" element={<SettingsPage />} />
          {/* Fallback */}
          <Route path="*" element={<OverviewPage />} />
        </Route>
      </Routes>
    </SecurityProvider>
  )
}

export default App
