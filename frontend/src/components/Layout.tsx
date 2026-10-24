import { ReactNode, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  Shield, Search, Link as LinkIcon, Package, Network, Mail, Globe,
  Activity, Key, FileWarning, AlertTriangle, Archive, Brain,
  Smartphone, FileText, Settings, Menu, X, Bell
} from 'lucide-react'

interface LayoutProps {
  children: ReactNode
}

const navItems = [
  { path: '/overview', icon: Shield, label: 'Overview' },
  { path: '/device-scanner', icon: Search, label: 'Device Scanner' },
  { path: '/url-protection', icon: LinkIcon, label: 'URL Protection' },
  { path: '/apk-scanner', icon: Package, label: 'APK Scanner' },
  { path: '/network-shield', icon: Network, label: 'Network Shield' },
  { path: '/email-security', icon: Mail, label: 'Email Security' },
  { path: '/browser-protection', icon: Globe, label: 'Browser Protection' },
  { path: '/app-monitor', icon: Activity, label: 'App Monitor' },
  { path: '/permission-manager', icon: Key, label: 'Permission Manager' },
  { path: '/ransomware-protection', icon: FileWarning, label: 'Ransomware Protection' },
  { path: '/vulnerability-scanner', icon: AlertTriangle, label: 'Vulnerability Scanner' },
  { path: '/quarantine', icon: Archive, label: 'Quarantine' },
  { path: '/threat-intelligence', icon: Brain, label: 'Threat Intelligence' },
  { path: '/device-management', icon: Smartphone, label: 'Device Management' },
  { path: '/security-reports', icon: FileText, label: 'Security Reports' },
  { path: '/settings', icon: Settings, label: 'Settings' },
]

export default function Layout({ children }: LayoutProps) {
  const location = useLocation()
  const [sidebarOpen, setSidebarOpen] = useState(true)

  return (
    <div className="min-h-screen bg-sentinel-bg flex">
      <aside className={`${sidebarOpen ? 'w-64' : 'w-20'} bg-sentinel-card border-r border-sentinel-border transition-all duration-300 flex flex-col`}>
        <div className="p-4 border-b border-sentinel-border flex items-center justify-between">
          {sidebarOpen && (
            <div className="flex items-center gap-2">
              <Shield className="w-8 h-8 text-sentinel-primary" />
              <span className="text-xl font-bold text-sentinel-primary">SENTINEL X</span>
            </div>
          )}
          <button onClick={() => setSidebarOpen(!sidebarOpen)} className="p-2 hover:bg-sentinel-border rounded">
            {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
        <nav className="flex-1 overflow-y-auto p-2">
          {navItems.map((item) => {
            const Icon = item.icon
            const isActive = location.pathname === item.path
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center gap-3 px-3 py-2 rounded mb-1 transition-colors ${
                  isActive
                    ? 'bg-sentinel-primary/10 text-sentinel-primary border border-sentinel-primary/30'
                    : 'hover:bg-sentinel-border text-gray-300'
                }`}
                title={!sidebarOpen ? item.label : undefined}
              >
                <Icon className="w-5 h-5 flex-shrink-0" />
                {sidebarOpen && <span className="text-sm">{item.label}</span>}
              </Link>
            )
          })}
        </nav>
      </aside>
      <div className="flex-1 flex flex-col">
        <header className="h-16 bg-sentinel-card border-b border-sentinel-border flex items-center justify-between px-6">
          <h1 className="text-lg font-semibold">
            {navItems.find(item => item.path === location.pathname)?.label || 'Dashboard'}
          </h1>
          <div className="flex items-center gap-4">
            <button className="p-2 hover:bg-sentinel-border rounded relative">
              <Bell className="w-5 h-5" />
              <span className="absolute top-1 right-1 w-2 h-2 bg-sentinel-danger rounded-full"></span>
            </button>
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-full bg-sentinel-primary/20 flex items-center justify-center">
                <Shield className="w-5 h-5 text-sentinel-primary" />
              </div>
              <span className="text-sm">User</span>
            </div>
          </div>
        </header>
        <main className="flex-1 p-6 overflow-auto">
          {children}
        </main>
      </div>
    </div>
  )
}
