import { useCallback, useEffect, useState } from 'react'
import {
  Activity, AlertTriangle, Archive, CheckCircle, Clock, Network, RefreshCw, Shield,
} from 'lucide-react'
import {
  aiAPI, apkAPI, auditAPI, devicesAPI, emailAPI, networkAPI, permissionsAPI,
  quarantineAPI, reportsAPI, scanAPI, threatsAPI, urlAPI,
} from '../lib/api'
import StatusBadge from '../components/StatusBadge'
import LoadingSpinner from '../components/LoadingSpinner'

type ModuleStatus = { name: string; active: boolean; detail: string }
type SecurityEvent = { id: string; severity: string; message: string; time: string }
type DashboardSnapshot = {
  securityScore: number | null
  threatsDetected: number | null
  threatsBlocked: number | null
  quarantined: number | null
  protectedDevices: number | null
  modules: ModuleStatus[]
  events: SecurityEvent[]
  failures: number
  moduleFailures: number
}

const unavailable = 'Unavailable'

export default function Overview() {
  const [loading, setLoading] = useState(true)
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null)
  const [error, setError] = useState('')

  const refreshData = useCallback(async () => {
    setLoading(true)
    setError('')
    const results = await Promise.allSettled([
      scanAPI.status(),
      urlAPI.status(),
      apkAPI.status(),
      networkAPI.status(),
      emailAPI.status(),
      devicesAPI.status(),
      permissionsAPI.status(),
      threatsAPI.status(),
      reportsAPI.status(),
      aiAPI.status(),
      quarantineAPI.list(),
      threatsAPI.list(),
      devicesAPI.list(),
      auditAPI.logs(),
    ])
    const dataAt = (index: number): any | null =>
      results[index].status === 'fulfilled' ? results[index].value.data : null

    const modules = [
      ['File scanning', dataAt(0)],
      ['URL protection', dataAt(1)],
      ['APK analysis', dataAt(2)],
      ['Network shield', dataAt(3)],
      ['Email security', dataAt(4)],
      ['Device management', dataAt(5)],
      ['Permission monitor', dataAt(6)],
      ['Threat intelligence', dataAt(7)],
      ['Security reports', dataAt(8)],
      ['AI analysis', dataAt(9)],
    ].map(([name, data]) => ({
      name: name as string,
      active: Boolean(data?.enabled && data?.status === 'operational'),
      detail: data ? (data.status === 'operational' ? 'Operational' : String(data.status || 'Status unknown')) : unavailable,
    }))

    const quarantineData = dataAt(10)
    const threatData = dataAt(11)
    const deviceData = dataAt(12)
    const auditData = dataAt(13)
    const devices = Array.isArray(deviceData?.items) ? deviceData.items : []
    const threats = Array.isArray(threatData?.threats) ? threatData.threats : []
    const auditLogs = Array.isArray(auditData?.logs) ? auditData.logs : []
    const events = [
      ...threats.map((threat: any, index: number) => ({
        id: String(threat.id || `threat-${index}`),
        severity: String(threat.severity || 'info').toLowerCase(),
        message: [threat.type, threat.status].filter(Boolean).join(' · ') || 'Threat record',
        time: threat.time && Number.isFinite(Date.parse(threat.time)) ? new Date(threat.time).toLocaleString() : 'Timestamp unavailable',
      })),
      ...auditLogs.map((event: any, index: number) => ({
        id: String(event.id || `audit-${index}`),
        severity: String(event.severity || 'info').toLowerCase(),
        message: String(event.message || event.action || 'Audit event'),
        time: event.time || event.timestamp || 'Timestamp unavailable',
      })),
    ].slice(0, 8)

    const scores = devices
      .map((device: any) => device.security_score)
      .filter((score: unknown): score is number => typeof score === 'number' && Number.isFinite(score))
    const quarantineItems = quarantineData?.items
    const failureCount = results.filter(result => result.status === 'rejected').length
    setSnapshot({
      securityScore: scores.length ? Math.round(scores.reduce((total: number, score: number) => total + score, 0) / scores.length) : null,
      threatsDetected: typeof threatData?.count === 'number' ? threatData.count : threatData ? threats.length : null,
      threatsBlocked: threatData ? threats.filter((threat: any) => String(threat.status).toLowerCase() === 'blocked').length : null,
      quarantined: typeof quarantineData?.count === 'number' ? quarantineData.count : Array.isArray(quarantineItems) ? quarantineItems.length : null,
      protectedDevices: typeof deviceData?.count === 'number' ? deviceData.count : deviceData ? devices.length : null,
      modules,
      events,
      failures: failureCount,
      moduleFailures: results.slice(0, 10).filter(result => result.status === 'rejected').length,
    })
    if (failureCount === results.length) setError('The dashboard could not reach any data services. Check the backend connection.')
    setLoading(false)
  }, [])

  useEffect(() => {
    void refreshData()
    const interval = window.setInterval(() => void refreshData(), 60000)
    return () => window.clearInterval(interval)
  }, [refreshData])

  const operationalModules = snapshot?.modules.filter(module => module.active).length ?? null

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-[0.2em] text-sentinel-primary">Security operations</p>
          <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">Security overview</h2>
          <p className="mt-1 text-sm text-slate-400">Live status from connected CyberShield services.</p>
        </div>
        <button
          type="button"
          onClick={() => void refreshData()}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.035] px-4 py-2.5 text-sm text-slate-200 transition hover:border-sentinel-primary/30 hover:bg-white/[0.07] disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh data
        </button>
      </div>

      {error && <div role="alert" className="rounded-xl border border-sentinel-danger/30 bg-sentinel-danger/10 px-4 py-3 text-sm text-red-200">{error}</div>}
      {snapshot?.failures ? <p className="text-xs text-sentinel-warning">{snapshot.failures} data source{snapshot.failures === 1 ? '' : 's'} could not be reached; unavailable values are shown as —.</p> : null}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <MetricCard title="Security score" value={snapshot?.securityScore == null ? '—' : `${snapshot.securityScore}`} icon={Shield} subtitle="Average device score" accent="primary" />
        <MetricCard title="Threats detected" value={snapshot?.threatsDetected == null ? '—' : String(snapshot.threatsDetected)} icon={AlertTriangle} subtitle="Threat service records" accent="warning" />
        <MetricCard title="Threats blocked" value={snapshot?.threatsBlocked == null ? '—' : String(snapshot.threatsBlocked)} icon={CheckCircle} subtitle="Marked blocked by service" accent="primary" />
        <MetricCard title="Quarantined files" value={snapshot?.quarantined == null ? '—' : String(snapshot.quarantined)} icon={Archive} subtitle="Current quarantine inventory" accent="danger" />
        <MetricCard title="Protected devices" value={snapshot?.protectedDevices == null ? '—' : String(snapshot.protectedDevices)} icon={Network} subtitle="Registered devices" accent="info" />
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[1.15fr_0.85fr]">
        <section className="rounded-2xl border border-sentinel-border bg-sentinel-card p-5 shadow-lg shadow-black/10 sm:p-6">
          <div className="mb-5 flex items-center justify-between gap-3">
            <div>
              <h3 className="flex items-center gap-2 font-semibold"><Activity className="h-4 w-4 text-sentinel-primary" />Protection services</h3>
              <p className="mt-1 text-xs text-slate-500">Reported API health, refreshed every minute</p>
            </div>
            <span className="rounded-full border border-white/10 px-2.5 py-1 text-xs text-slate-400">
              {operationalModules == null ? '—' : `${operationalModules}/${snapshot?.modules.length ?? 0}`} active
            </span>
          </div>
          {loading && !snapshot ? <LoadingSpinner /> : (
            <div className="grid gap-2 sm:grid-cols-2">
              {snapshot?.modules.map(module => (
                <div key={module.name} className="flex min-w-0 items-center justify-between gap-3 rounded-xl border border-white/[0.055] bg-black/20 px-3 py-3">
                  <span className="truncate text-sm text-slate-300">{module.name}</span>
                  <StatusBadge status={module.active ? 'active' : 'inactive'} text={module.detail} />
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="rounded-2xl border border-sentinel-border bg-sentinel-card p-5 shadow-lg shadow-black/10 sm:p-6">
          <div className="mb-5 flex items-center justify-between">
            <div>
              <h3 className="flex items-center gap-2 font-semibold"><Clock className="h-4 w-4 text-sentinel-info" />Recent security events</h3>
              <p className="mt-1 text-xs text-slate-500">Threat and audit records returned by the API</p>
            </div>
          </div>
          {loading && !snapshot ? <LoadingSpinner /> : snapshot?.events.length ? (
            <div className="max-h-80 space-y-1 overflow-y-auto">
              {snapshot.events.map(event => (
                <div key={event.id} className="flex items-start gap-3 rounded-xl px-3 py-3 transition hover:bg-white/[0.025]">
                  <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${event.severity === 'critical' || event.severity === 'high' ? 'bg-sentinel-danger' : event.severity === 'medium' || event.severity === 'warning' ? 'bg-sentinel-warning' : 'bg-sentinel-info'}`} />
                  <div className="min-w-0">
                    <p className="text-sm text-slate-200">{event.message}</p>
                    <p className="mt-1 text-xs text-slate-500">{event.time}</p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="rounded-xl border border-white/[0.06] bg-black/20 px-4 py-8 text-center text-sm text-slate-500">No event records returned by connected services.</p>
          )}
        </section>
      </div>

      <section className="rounded-2xl border border-sentinel-border bg-sentinel-card p-5 shadow-lg shadow-black/10 sm:p-6">
        <div className="mb-4">
          <h3 className="font-semibold">System health</h3>
          <p className="mt-1 text-xs text-slate-500">Service connectivity only; hardware and database health are not exposed by the current API.</p>
        </div>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <HealthItem label="API status sources" value={snapshot ? `${snapshot.modules.length - snapshot.moduleFailures}/${snapshot.modules.length} reachable` : 'Loading'} />
          <HealthItem label="Protection modules" value={operationalModules == null ? 'Loading' : `${operationalModules} operational`} />
          <HealthItem label="Threat feed" value={snapshot?.threatsDetected == null ? 'Unavailable' : 'Connected'} />
          <HealthItem label="Quarantine inventory" value={snapshot?.quarantined == null ? 'Unavailable' : 'Connected'} />
        </div>
      </section>
    </div>
  )
}

function MetricCard({ title, value, icon: Icon, subtitle, accent }: {
  title: string
  value: string
  icon: typeof Shield
  subtitle: string
  accent: 'primary' | 'warning' | 'danger' | 'info'
}) {
  const accentClasses = {
    primary: 'text-sentinel-primary border-sentinel-primary/20 bg-sentinel-primary/[0.08]',
    warning: 'text-sentinel-warning border-sentinel-warning/20 bg-sentinel-warning/[0.08]',
    danger: 'text-sentinel-danger border-sentinel-danger/20 bg-sentinel-danger/[0.08]',
    info: 'text-sentinel-info border-sentinel-info/20 bg-sentinel-info/[0.08]',
  }
  return (
    <div className="rounded-2xl border border-sentinel-border bg-sentinel-card p-4 shadow-lg shadow-black/10 transition duration-200 hover:-translate-y-0.5 hover:border-white/20 sm:p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate text-xs font-medium text-slate-400">{title}</p>
          <p className="mt-3 text-3xl font-semibold tracking-tight text-slate-100">{value}</p>
          <p className="mt-1 truncate text-[11px] text-slate-500">{subtitle}</p>
        </div>
        <span className={`grid h-9 w-9 shrink-0 place-items-center rounded-xl border ${accentClasses[accent]}`}>
          <Icon className="h-4 w-4" />
        </span>
      </div>
    </div>
  )
}

function HealthItem({ label, value }: { label: string; value: string }) {
  const connected = value !== 'Unavailable' && value !== 'Loading'
  return (
    <div className="flex items-center justify-between gap-3 rounded-xl border border-white/[0.055] bg-black/20 px-4 py-3">
      <span className="text-sm text-slate-400">{label}</span>
      <span className={`text-right text-xs font-medium ${connected ? 'text-sentinel-primary' : 'text-slate-500'}`}>{value}</span>
    </div>
  )
}
