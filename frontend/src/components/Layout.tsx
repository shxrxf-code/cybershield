import { ReactNode, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  Shield, Search, Link as LinkIcon, Package, Network, Mail, Globe,
  Activity, Key, FileWarning, AlertTriangle, Archive, Brain,
  Smartphone, FileText, Settings, Menu, X, PanelLeftClose, PanelLeftOpen
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
  const [sidebarExpanded, setSidebarExpanded] = useState(true)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const currentPage = navItems.find(item => item.path === location.pathname)

  return (
    <div className="min-h-screen flex">
      {mobileNavOpen && (
        <button
          aria-label="Close navigation"
          className="fixed inset-0 z-40 bg-black/65 backdrop-blur-sm md:hidden"
          onClick={() => setMobileNavOpen(false)}
        />
      )}
      <aside className={`fixed inset-y-0 left-0 z-50 flex w-72 flex-col border-r border-sentinel-border bg-[#0b111a]/95 shadow-2xl shadow-black/30 backdrop-blur-xl transition-transform duration-300 md:sticky md:top-0 md:h-screen md:translate-x-0 md:shadow-none ${mobileNavOpen ? 'translate-x-0' : '-translate-x-full'} ${sidebarExpanded ? 'md:w-64' : 'md:w-[4.5rem]'}`}>
        <div className="flex h-16 items-center justify-between border-b border-sentinel-border px-4">
          <div className="flex min-w-0 items-center gap-2.5">
            <div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-sentinel-primary/25 bg-sentinel-primary/10 shadow-[0_0_24px_rgba(67,240,162,0.12)]">
              <Shield className="h-5 w-5 text-sentinel-primary" />
            </div>
            {(sidebarExpanded || mobileNavOpen) && <span className="truncate text-sm font-bold tracking-[0.16em] text-slate-100">CYBER<span className="text-sentinel-primary">SHIELD</span></span>}
          </div>
          <button
            type="button"
            aria-label={sidebarExpanded ? 'Collapse navigation' : 'Expand navigation'}
            onClick={() => setSidebarExpanded(!sidebarExpanded)}
            className="hidden rounded-lg p-2 text-slate-400 transition hover:bg-white/5 hover:text-white md:inline-flex"
          >
            {sidebarExpanded ? <PanelLeftClose className="h-4 w-4" /> : <PanelLeftOpen className="h-4 w-4" />}
          </button>
          <button
            type="button"
            aria-label="Close navigation"
            onClick={() => setMobileNavOpen(false)}
            className="rounded-lg p-2 text-slate-400 transition hover:bg-white/5 hover:text-white md:hidden"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="px-4 pb-2 pt-5">
          {(sidebarExpanded || mobileNavOpen) && <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-500">Security console</p>}
        </div>
        <nav aria-label="Main navigation" className="flex-1 space-y-1 overflow-y-auto px-2 pb-4">
          {navItems.map((item) => {
            const Icon = item.icon
            const isActive = location.pathname === item.path
            return (
              <Link
                key={item.path}
                to={item.path}
                aria-current={isActive ? 'page' : undefined}
                onClick={() => setMobileNavOpen(false)}
                className={`group relative flex min-h-10 items-center gap-3 rounded-xl border px-3 py-2.5 transition duration-200 ${
                  isActive
                    ? 'border-sentinel-primary/20 bg-sentinel-primary/[0.09] text-sentinel-primary shadow-[inset_0_0_18px_rgba(67,240,162,0.04)]'
                    : 'border-transparent text-slate-400 hover:border-white/[0.06] hover:bg-white/[0.04] hover:text-slate-100'
                }`}
                title={!sidebarExpanded ? item.label : undefined}
              >
                {isActive && <span className="absolute -left-2 h-5 w-0.5 rounded-full bg-sentinel-primary shadow-[0_0_12px_rgba(67,240,162,0.9)]" />}
                <Icon className="h-[18px] w-[18px] shrink-0" />
                {(sidebarExpanded || mobileNavOpen) && <span className="truncate text-[13px] font-medium">{item.label}</span>}
              </Link>
            )
          })}
        </nav>
      </aside>
      <div className="flex min-h-screen min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-sentinel-border bg-[#070a10]/75 px-4 backdrop-blur-xl sm:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <button
              type="button"
              aria-label="Open navigation"
              onClick={() => setMobileNavOpen(true)}
              className="rounded-lg border border-white/10 bg-white/[0.035] p-2 text-slate-300 md:hidden"
            >
              <Menu className="h-4 w-4" />
            </button>
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold text-slate-100">{currentPage?.label || 'Security console'}</p>
              <p className="hidden text-[10px] uppercase tracking-[0.18em] text-slate-500 sm:block">CYBERSHIELD / Security operations</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden items-center gap-2 rounded-full border border-sentinel-primary/15 bg-sentinel-primary/[0.06] px-3 py-1.5 text-[11px] font-medium text-slate-300 sm:inline-flex">
              <span className="h-1.5 w-1.5 rounded-full bg-sentinel-primary shadow-[0_0_9px_rgba(67,240,162,0.85)]" />
              Control center
            </span>
            <div className="grid h-9 w-9 place-items-center rounded-xl border border-white/10 bg-white/[0.035]">
              <Shield className="h-4 w-4 text-sentinel-info" />
            </div>
          </div>
        </header>
        <main className="flex-1 overflow-x-hidden p-4 sm:p-6 lg:p-8">
          <div key={location.pathname} className="mx-auto w-full max-w-[1500px] animate-[page-enter_220ms_ease-out]">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}
