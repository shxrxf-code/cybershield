import { useEffect, useState } from 'react'
import type { AxiosResponse } from 'axios'
import { Activity, AlertTriangle, CheckCircle2, Info } from 'lucide-react'
import StatusBadge from './StatusBadge'

interface CapabilityStatusPageProps {
  title: string
  description: string
  limitation: string
  serviceName?: string
  getStatus?: () => Promise<AxiosResponse<Record<string, unknown>>>
}

export default function CapabilityStatusPage({
  title,
  description,
  limitation,
  serviceName,
  getStatus,
}: CapabilityStatusPageProps) {
  const [status, setStatus] = useState<'checking' | 'operational' | 'unavailable' | 'unsupported'>(
    getStatus ? 'checking' : 'unsupported',
  )
  const [details, setDetails] = useState<Record<string, unknown> | null>(null)

  useEffect(() => {
    if (!getStatus) return
    let active = true
    getStatus()
      .then(({ data }) => {
        if (!active) return
        setDetails(data)
        setStatus(data.enabled === true && data.status === 'operational' ? 'operational' : 'unavailable')
      })
      .catch((error: unknown) => {
        console.error(error)
        if (active) setStatus('unavailable')
      })
    return () => { active = false }
  }, [getStatus])

  const badgeStatus = status === 'operational' ? 'active' : status === 'checking' ? 'warning' : 'inactive'
  const statusLabel = status === 'operational'
    ? 'Operational'
    : status === 'checking'
      ? 'Checking'
      : status === 'unavailable'
        ? 'Unavailable'
        : 'Not integrated'
  const StatusIcon = status === 'operational' ? CheckCircle2 : status === 'unavailable' ? AlertTriangle : Info

  return (
    <div className="space-y-6">
      <div>
        <p className="mb-1 text-xs font-semibold uppercase tracking-[0.2em] text-sentinel-info">Security module</p>
        <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">{title}</h2>
        <p className="mt-1 text-sm text-slate-400">{description}</p>
      </div>

      <section className="relative overflow-hidden rounded-2xl border border-sentinel-border bg-sentinel-card p-6 shadow-lg shadow-black/10 sm:p-8">
        <div className="pointer-events-none absolute -right-16 -top-20 h-56 w-56 rounded-full bg-sentinel-info/[0.06] blur-3xl" />
        <div className="relative flex flex-wrap items-start justify-between gap-5">
          <div className="max-w-2xl">
            <div className="mb-4 grid h-11 w-11 place-items-center rounded-xl border border-sentinel-info/20 bg-sentinel-info/[0.08] text-sentinel-info">
              <Activity className="h-5 w-5" />
            </div>
            <h3 className="text-lg font-semibold">{serviceName || title}</h3>
            <p className="mt-2 text-sm leading-6 text-slate-400">{limitation}</p>
          </div>
          <StatusBadge status={badgeStatus} text={statusLabel} />
        </div>

        <div className="relative mt-6 grid gap-3 border-t border-white/[0.08] pt-5 sm:grid-cols-2">
          <div className="rounded-xl border border-white/[0.06] bg-black/20 p-4">
            <p className="text-xs uppercase tracking-wider text-slate-500">Available backend capability</p>
            <div className="mt-2 flex items-center gap-2 text-sm text-slate-200">
              <StatusIcon className={`h-4 w-4 ${status === 'operational' ? 'text-sentinel-primary' : status === 'unavailable' ? 'text-sentinel-warning' : 'text-slate-500'}`} />
              {statusLabel}
            </div>
          </div>
          <div className="rounded-xl border border-white/[0.06] bg-black/20 p-4">
            <p className="text-xs uppercase tracking-wider text-slate-500">Service details</p>
            <p className="mt-2 break-words text-sm text-slate-300">
              {details
                ? Object.entries(details)
                    .filter(([key]) => key !== 'module' && key !== 'status' && key !== 'enabled')
                    .map(([key, value]) => `${key.replace(/_/g, ' ')}: ${String(value)}`)
                    .join(' · ') || 'No additional status details'
                : getStatus ? 'No status response available' : 'No endpoint is configured'}
            </p>
          </div>
        </div>
      </section>
    </div>
  )
}
