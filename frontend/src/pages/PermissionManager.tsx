import { useEffect, useState } from 'react'
import { KeyRound, RefreshCw, ShieldAlert } from 'lucide-react'
import { permissionsAPI } from '../lib/api'
import StatusBadge from '../components/StatusBadge'
import LoadingSpinner from '../components/LoadingSpinner'

type Permission = { name: string; status: string; risk: string; apps: string[] }

export default function PermissionManager() {
  const [permissions, setPermissions] = useState<Permission[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const refresh = async () => {
    setLoading(true)
    setError('')
    try {
      const { data } = await permissionsAPI.list()
      setPermissions(Array.isArray(data.permissions) ? data.permissions : [])
    } catch (requestError) {
      console.error(requestError)
      setError('Permission inventory could not be loaded.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void refresh() }, [])

  const elevatedCount = permissions.filter(permission => ['high', 'critical'].includes(permission.risk.toLowerCase())).length

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-[0.2em] text-sentinel-info">Access visibility</p>
          <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">Permission manager</h2>
          <p className="mt-1 text-sm text-slate-400">Inventory reported by the permission service.</p>
        </div>
        <button type="button" onClick={() => void refresh()} disabled={loading} className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.035] px-4 py-2.5 text-sm text-slate-200 transition hover:bg-white/[0.07] disabled:opacity-50">
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />Refresh
        </button>
      </div>

      {error && <p role="alert" className="rounded-xl border border-sentinel-danger/25 bg-sentinel-danger/10 px-4 py-3 text-sm text-red-200">{error}</p>}
      <div className="grid gap-3 sm:grid-cols-2">
        <Summary label="Permissions reported" value={String(permissions.length)} icon={KeyRound} />
        <Summary label="Elevated risk entries" value={String(elevatedCount)} icon={ShieldAlert} />
      </div>

      <section className="rounded-2xl border border-sentinel-border bg-sentinel-card p-5 shadow-lg shadow-black/10 sm:p-6">
        <h3 className="font-semibold">Permission inventory</h3>
        <p className="mt-1 text-xs leading-5 text-slate-500">Risk and grant states are supplied by the backend. The current API is read-only and does not change device permissions.</p>
        {loading ? <LoadingSpinner /> : permissions.length === 0 ? (
          <p className="py-10 text-center text-sm text-slate-500">No permissions returned by the backend.</p>
        ) : (
          <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {permissions.map(permission => {
              const risk = permission.risk.toLowerCase()
              const riskStatus = risk === 'critical' || risk === 'high' ? 'danger' : risk === 'medium' ? 'warning' : 'active'
              return (
                <article key={permission.name} className="rounded-xl border border-white/[0.07] bg-black/20 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div><h4 className="font-medium text-slate-100">{permission.name}</h4><p className="mt-1 text-xs text-slate-500">{permission.apps.length} app{permission.apps.length === 1 ? '' : 's'} listed</p></div>
                    <StatusBadge status={riskStatus} text={`${permission.risk} risk`} />
                  </div>
                  <div className="mt-4 flex items-center justify-between border-t border-white/[0.06] pt-3">
                    <span className="text-xs uppercase tracking-wider text-slate-500">Grant state</span>
                    <StatusBadge status={permission.status.toLowerCase() === 'granted' ? 'warning' : 'inactive'} text={permission.status} />
                  </div>
                  {permission.apps.length > 0 && <p className="mt-3 truncate text-xs text-slate-400" title={permission.apps.join(', ')}>Apps: {permission.apps.join(', ')}</p>}
                  {riskStatus === 'danger' && <p className="mt-3 text-xs leading-5 text-sentinel-warning">Review whether each listed application requires this high-impact access.</p>}
                </article>
              )
            })}
          </div>
        )}
      </section>
    </div>
  )
}

function Summary({ label, value, icon: Icon }: { label: string; value: string; icon: typeof KeyRound }) {
  return <div className="flex items-center gap-4 rounded-2xl border border-sentinel-border bg-sentinel-card p-4"><span className="grid h-10 w-10 place-items-center rounded-xl border border-sentinel-info/20 bg-sentinel-info/[0.08] text-sentinel-info"><Icon className="h-5 w-5" /></span><div><p className="text-xs text-slate-500">{label}</p><p className="mt-1 text-xl font-semibold">{value}</p></div></div>
}
