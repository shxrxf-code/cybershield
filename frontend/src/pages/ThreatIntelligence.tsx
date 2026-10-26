import { useEffect, useState } from 'react'
import { BrainCircuit, RefreshCw, ShieldAlert } from 'lucide-react'
import { threatsAPI } from '../lib/api'
import StatusBadge from '../components/StatusBadge'
import LoadingSpinner from '../components/LoadingSpinner'

type Threat = { id: string; type: string; severity: string; status: string; time: string }

export default function ThreatIntelligence() {
  const [threats, setThreats] = useState<Threat[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const refresh = async () => {
    setLoading(true)
    setError('')
    try {
      const { data } = await threatsAPI.list()
      setThreats(Array.isArray(data.threats) ? data.threats : [])
    } catch (requestError) {
      console.error(requestError)
      setError('Threat records could not be loaded.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void refresh() }, [])
  const criticalCount = threats.filter(threat => ['critical', 'high'].includes(threat.severity.toLowerCase())).length

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-[0.2em] text-sentinel-info">Threat intelligence</p>
          <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">Threat activity</h2>
          <p className="mt-1 text-sm text-slate-400">Threat records returned by the connected intelligence service.</p>
        </div>
        <button type="button" onClick={() => void refresh()} disabled={loading} className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.035] px-4 py-2.5 text-sm text-slate-200 transition hover:bg-white/[0.07] disabled:opacity-50">
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />Refresh feed
        </button>
      </div>

      {error && <p role="alert" className="rounded-xl border border-sentinel-danger/25 bg-sentinel-danger/10 px-4 py-3 text-sm text-red-200">{error}</p>}
      <div className="grid gap-3 sm:grid-cols-2">
        <Summary label="Threat records" value={String(threats.length)} icon={BrainCircuit} />
        <Summary label="High / critical severity" value={String(criticalCount)} icon={ShieldAlert} />
      </div>
      <section className="overflow-hidden rounded-2xl border border-sentinel-border bg-sentinel-card shadow-lg shadow-black/10">
        <div className="border-b border-white/[0.08] px-5 py-4 sm:px-6">
          <h3 className="font-semibold">Threat history</h3>
          <p className="mt-1 text-xs text-slate-500">No local sample records are used.</p>
        </div>
        {loading ? <LoadingSpinner /> : threats.length === 0 ? <p className="px-6 py-12 text-center text-sm text-slate-500">No threat records returned.</p> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[620px] text-left">
              <thead className="bg-black/20 text-xs uppercase tracking-wider text-slate-500"><tr><th className="px-5 py-3 font-medium">Threat</th><th className="px-5 py-3 font-medium">Severity</th><th className="px-5 py-3 font-medium">Disposition</th><th className="px-5 py-3 font-medium">Reported</th></tr></thead>
              <tbody>
                {threats.map(threat => {
                  const severity = threat.severity.toLowerCase()
                  const status = severity === 'critical' || severity === 'high' ? 'danger' : severity === 'medium' ? 'warning' : 'active'
                  return <tr key={threat.id} className="border-t border-white/[0.06] text-sm"><td className="px-5 py-4"><p className="font-medium text-slate-200">{threat.type}</p><p className="mt-1 text-xs text-slate-500">{threat.id}</p></td><td className="px-5 py-4"><StatusBadge status={status} text={threat.severity} /></td><td className="px-5 py-4 capitalize text-slate-300">{threat.status}</td><td className="px-5 py-4 text-xs text-slate-400">{threat.time ? new Date(threat.time).toLocaleString() : '—'}</td></tr>
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}

function Summary({ label, value, icon: Icon }: { label: string; value: string; icon: typeof BrainCircuit }) {
  return <div className="flex items-center gap-4 rounded-2xl border border-sentinel-border bg-sentinel-card p-4"><span className="grid h-10 w-10 place-items-center rounded-xl border border-sentinel-info/20 bg-sentinel-info/[0.08] text-sentinel-info"><Icon className="h-5 w-5" /></span><div><p className="text-xs text-slate-500">{label}</p><p className="mt-1 text-xl font-semibold">{value}</p></div></div>
}
