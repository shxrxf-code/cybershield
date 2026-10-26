import { useCallback, useEffect, useState } from 'react'
import { Monitor, RefreshCw, Smartphone, Wifi } from 'lucide-react'
import { devicesAPI } from '../lib/api'
import StatusBadge from '../components/StatusBadge'
import LoadingSpinner from '../components/LoadingSpinner'

type Device = {
  id: string
  name: string
  platform?: string
  os_version?: string
  status?: string
  protection?: string
  security_score?: number
  last_seen?: string
}

export default function DeviceManagement() {
  const [devices, setDevices] = useState<Device[]>([])
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  const loadDevices = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const { data } = await devicesAPI.list()
      setDevices(Array.isArray(data.items) ? data.items : [])
    } catch (requestError) {
      console.error(requestError)
      setError('Device inventory could not be loaded.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void loadDevices() }, [loadDevices])

  const syncDevices = async () => {
    setSyncing(true)
    setMessage('')
    setError('')
    try {
      const { data } = await devicesAPI.sync()
      if (data.synced) {
        setMessage('Device synchronization completed.')
        await loadDevices()
      } else {
        setError('The backend did not confirm device synchronization.')
      }
    } catch (requestError) {
      console.error(requestError)
      setError('Device synchronization failed.')
    } finally {
      setSyncing(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-[0.2em] text-sentinel-info">Fleet security</p>
          <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">Device management</h2>
          <p className="mt-1 text-sm text-slate-400">Registered devices and reported protection state.</p>
        </div>
        <button type="button" onClick={() => void syncDevices()} disabled={syncing || loading} className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.035] px-4 py-2.5 text-sm text-slate-200 transition hover:border-sentinel-info/30 hover:bg-white/[0.07] disabled:opacity-50">
          <RefreshCw className={`h-4 w-4 ${syncing ? 'animate-spin' : ''}`} />
          {syncing ? 'Syncing…' : 'Sync devices'}
        </button>
      </div>

      {error && <p role="alert" className="rounded-xl border border-sentinel-danger/25 bg-sentinel-danger/10 px-4 py-3 text-sm text-red-200">{error}</p>}
      {message && <p role="status" className="rounded-xl border border-sentinel-primary/20 bg-sentinel-primary/[0.07] px-4 py-3 text-sm text-sentinel-primary">{message}</p>}

      <div className="grid gap-3 sm:grid-cols-3">
        <Summary label="Registered devices" value={String(devices.length)} icon={Smartphone} />
        <Summary label="Online" value={String(devices.filter(device => device.status?.toLowerCase() === 'online').length)} icon={Wifi} />
        <Summary label="Protection active" value={String(devices.filter(device => device.protection?.toLowerCase() === 'active').length)} icon={Monitor} />
      </div>

      <section className="overflow-hidden rounded-2xl border border-sentinel-border bg-sentinel-card shadow-lg shadow-black/10">
        <div className="border-b border-white/[0.08] px-5 py-4 sm:px-6">
          <h3 className="font-semibold">Device inventory</h3>
          <p className="mt-1 text-xs text-slate-500">Values supplied by the devices API.</p>
        </div>
        {loading ? <LoadingSpinner /> : devices.length === 0 ? (
          <p className="px-6 py-12 text-center text-sm text-slate-500">No devices returned by the backend.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-left">
              <thead className="bg-black/20 text-xs uppercase tracking-wider text-slate-500">
                <tr>{['Device', 'Platform', 'Connection', 'Protection', 'Security score', 'Last seen'].map(label => <th key={label} className="px-5 py-3 font-medium">{label}</th>)}</tr>
              </thead>
              <tbody>
                {devices.map(device => (
                  <tr key={device.id} className="border-t border-white/[0.06] text-sm">
                    <td className="px-5 py-4"><p className="font-medium text-slate-200">{device.name}</p><p className="mt-0.5 text-xs text-slate-500">{device.id}</p></td>
                    <td className="px-5 py-4 text-slate-400">{[device.platform, device.os_version].filter(Boolean).join(' · ') || '—'}</td>
                    <td className="px-5 py-4"><StatusBadge status={device.status?.toLowerCase() === 'online' ? 'active' : 'inactive'} text={device.status || 'Unknown'} /></td>
                    <td className="px-5 py-4"><StatusBadge status={device.protection?.toLowerCase() === 'active' ? 'active' : 'warning'} text={device.protection || 'Unknown'} /></td>
                    <td className="px-5 py-4 font-medium text-slate-200">{typeof device.security_score === 'number' ? `${device.security_score}/100` : '—'}</td>
                    <td className="px-5 py-4 text-xs text-slate-400">{device.last_seen ? new Date(device.last_seen).toLocaleString() : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}

function Summary({ label, value, icon: Icon }: { label: string; value: string; icon: typeof Monitor }) {
  return (
    <div className="flex items-center gap-4 rounded-2xl border border-sentinel-border bg-sentinel-card p-4">
      <span className="grid h-10 w-10 place-items-center rounded-xl border border-sentinel-info/20 bg-sentinel-info/[0.08] text-sentinel-info"><Icon className="h-5 w-5" /></span>
      <div><p className="text-xs text-slate-500">{label}</p><p className="mt-1 text-xl font-semibold text-slate-100">{value}</p></div>
    </div>
  )
}
