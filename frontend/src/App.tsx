import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Overview from './pages/Overview'
import DeviceScanner from './pages/DeviceScanner'
import URLProtection from './pages/URLProtection'
import APKScanner from './pages/APKScanner'
import NetworkShield from './pages/NetworkShield'
import EmailSecurity from './pages/EmailSecurity'
import BrowserProtection from './pages/BrowserProtection'
import AppMonitor from './pages/AppMonitor'
import PermissionManager from './pages/PermissionManager'
import RansomwareProtection from './pages/RansomwareProtection'
import VulnerabilityScanner from './pages/VulnerabilityScanner'
import Quarantine from './pages/Quarantine'
import ThreatIntelligence from './pages/ThreatIntelligence'
import DeviceManagement from './pages/DeviceManagement'
import SecurityReports from './pages/SecurityReports'
import Settings from './pages/Settings'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/overview" replace />} />
        <Route path="/overview" element={<Overview />} />
        <Route path="/device-scanner" element={<DeviceScanner />} />
        <Route path="/url-protection" element={<URLProtection />} />
        <Route path="/apk-scanner" element={<APKScanner />} />
        <Route path="/network-shield" element={<NetworkShield />} />
        <Route path="/email-security" element={<EmailSecurity />} />
        <Route path="/browser-protection" element={<BrowserProtection />} />
        <Route path="/app-monitor" element={<AppMonitor />} />
        <Route path="/permission-manager" element={<PermissionManager />} />
        <Route path="/ransomware-protection" element={<RansomwareProtection />} />
        <Route path="/vulnerability-scanner" element={<VulnerabilityScanner />} />
        <Route path="/quarantine" element={<Quarantine />} />
        <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
        <Route path="/device-management" element={<DeviceManagement />} />
        <Route path="/security-reports" element={<SecurityReports />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </Layout>
  )
}

export default App
