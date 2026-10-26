import { useState, useEffect } from 'react'
import { Activity, ShieldAlert, RefreshCw, AlertTriangle, XCircle, PauseCircle, CheckCircle, Search } from 'lucide-react'
import axios from 'axios'

interface ProcessItem {
  pid: number
  name: string
  user: string
  cpu_percent: number
  memory_percent: number
  status: string
  executable: string
  risk_score: number
  risk_level: 'low' | 'moderate' | 'high' | 'critical'
  is_suspicious: boolean
  reasons: string[]
}

export default function AppMonitor() {
  const [processes, setProcesses] = useState<ProcessItem[]>([])
  const [loading, setLoading] = useState(false)
  const [actionLoading, setActionLoading] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [feedback, setFeedback] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [filterSuspiciousOnly, setFilterSuspiciousOnly] = useState(false)
  const [selectedProc, setSelectedProc] = useState<ProcessItem | null>(null)

  const fetchProcesses = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await axios.get('/api/v1/apps/?limit=100')
      setProcesses(res.data.processes || [])
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to fetch active process telemetry')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchProcesses()
    const interval = setInterval(fetchProcesses, 15000)
    return () => clearInterval(interval)
  }, [])

  const handleTerminate = async (pid: number, name: string) => {
    if (!window.confirm(`Are you sure you want to terminate process ${name} (PID ${pid})?`)) return
    setActionLoading(pid)
    setError(null)
    try {
      const res = await axios.post('/api/v1/apps/terminate', { pid })
      setFeedback(res.data.message || `Process ${pid} terminated successfully.`)
      fetchProcesses()
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to terminate process')
    } finally {
      setActionLoading(null)
    }
  }

  const handleIsolate = async (pid: number) => {
    setActionLoading(pid)
    setError(null)
    try {
      const res = await axios.post('/api/v1/apps/isolate', { pid })
      setFeedback(res.data.message || `Process ${pid} suspended and isolated.`)
      fetchProcesses()
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to isolate process')
    } finally {
      setActionLoading(null)
    }
  }

  const filtered = processes.filter(p => {
    const matchesSearch = p.name.toLowerCase().includes(search.toLowerCase()) || String(p.pid).includes(search)
    return filterSuspiciousOnly ? matchesSearch && p.is_suspicious : matchesSearch
  })

  const suspiciousCount = processes.filter(p => p.is_suspicious).length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-[0.2em] text-cyber-info">Module D / Runtime Telemetry</p>
          <h2 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">Application & Process Monitor</h2>
          <p className="mt-1 text-sm text-slate-400">Continuous runtime inspection, resource anomaly detection, and authorized process containment.</p>
        </div>
        <button
          type="button"
          onClick={fetchProcesses}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-4 py-2.5 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.08] disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin text-cyber-primary' : ''}`} />
          Refresh telemetry
        </button>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="flex items-center gap-4 rounded-2xl border border-cyber-border bg-cyber-card p-5">
          <div className="grid h-12 w-12 place-items-center rounded-xl border border-cyber-info/20 bg-cyber-info/10 text-cyber-info">
            <Activity className="h-6 w-6" />
          </div>
          <div>
            <p className="text-xs uppercase tracking-wider text-slate-400">Active Processes</p>
            <p className="mt-1 text-2xl font-bold text-white">{processes.length}</p>
          </div>
        </div>

        <div className="flex items-center gap-4 rounded-2xl border border-cyber-border bg-cyber-card p-5">
          <div className={`grid h-12 w-12 place-items-center rounded-xl border ${suspiciousCount > 0 ? 'border-cyber-danger/30 bg-cyber-danger/10 text-cyber-danger' : 'border-cyber-primary/20 bg-cyber-primary/10 text-cyber-primary'}`}>
            {suspiciousCount > 0 ? <AlertTriangle className="h-6 w-6" /> : <CheckCircle className="h-6 w-6" />}
          </div>
          <div>
            <p className="text-xs uppercase tracking-wider text-slate-400">Suspicious Anomalies</p>
            <p className={`mt-1 text-2xl font-bold ${suspiciousCount > 0 ? 'text-cyber-danger' : 'text-cyber-primary'}`}>
              {suspiciousCount}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4 rounded-2xl border border-cyber-border bg-cyber-card p-5">
          <div className="grid h-12 w-12 place-items-center rounded-xl border border-white/10 bg-white/[0.04] text-slate-300">
            <ShieldAlert className="h-6 w-6" />
          </div>
          <div>
            <p className="text-xs uppercase tracking-wider text-slate-400">Protection Shield</p>
            <p className="mt-1 text-xl font-bold text-emerald-400">Live Guard Active</p>
          </div>
        </div>
      </div>

      {feedback && (
        <div className="rounded-xl border border-cyber-primary/30 bg-cyber-primary/10 px-4 py-3 text-sm text-emerald-300">
          {feedback}
        </div>
      )}

      {error && (
        <div role="alert" className="rounded-xl border border-cyber-danger/30 bg-cyber-danger/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Controls & Search */}
      <div className="flex flex-col gap-3 rounded-2xl border border-cyber-border bg-cyber-card p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative flex-1">
          <Search className="absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search processes by name or PID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-xl border border-white/10 bg-[#070a10]/80 py-2.5 pl-10 pr-4 text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyber-info focus:outline-none"
          />
        </div>
        <button
          type="button"
          onClick={() => setFilterSuspiciousOnly(!filterSuspiciousOnly)}
          className={`rounded-xl border px-4 py-2.5 text-xs font-semibold uppercase tracking-wider transition ${
            filterSuspiciousOnly
              ? 'border-cyber-danger/40 bg-cyber-danger/15 text-cyber-danger'
              : 'border-white/10 bg-white/[0.03] text-slate-400 hover:text-white'
          }`}
        >
          {filterSuspiciousOnly ? 'Showing Suspicious Only' : 'Filter Suspicious'}
        </button>
      </div>

      {/* Processes Table */}
      <div className="overflow-hidden rounded-2xl border border-cyber-border bg-cyber-card">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="border-b border-cyber-border bg-[#070a10]/60 text-xs uppercase tracking-wider text-slate-400">
              <tr>
                <th className="px-5 py-3.5 font-semibold">PID</th>
                <th className="px-5 py-3.5 font-semibold">Process Name</th>
                <th className="px-5 py-3.5 font-semibold">User</th>
                <th className="px-5 py-3.5 font-semibold">CPU</th>
                <th className="px-5 py-3.5 font-semibold">Memory</th>
                <th className="px-5 py-3.5 font-semibold">Risk Level</th>
                <th className="px-5 py-3.5 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-5 py-8 text-center text-slate-500">
                    No active processes matching current filter criteria.
                  </td>
                </tr>
              ) : (
                filtered.map((proc) => (
                  <tr key={proc.pid} className="transition hover:bg-white/[0.02]">
                    <td className="px-5 py-3.5 font-mono text-xs text-slate-400">{proc.pid}</td>
                    <td className="px-5 py-3.5">
                      <div className="font-semibold text-slate-200">{proc.name}</div>
                      {proc.reasons.length > 0 && (
                        <p className="mt-0.5 text-xs text-cyber-warning">{proc.reasons[0]}</p>
                      )}
                    </td>
                    <td className="px-5 py-3.5 text-xs text-slate-400">{proc.user}</td>
                    <td className="px-5 py-3.5 text-xs">
                      <span className={proc.cpu_percent > 50 ? 'text-cyber-warning font-semibold' : 'text-slate-300'}>
                        {proc.cpu_percent.toFixed(1)}%
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-xs text-slate-300">{proc.memory_percent.toFixed(1)}%</td>
                    <td className="px-5 py-3.5">
                      <span
                        className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                          proc.risk_level === 'critical'
                            ? 'bg-cyber-danger/20 text-cyber-danger border border-cyber-danger/30'
                            : proc.risk_level === 'high'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : proc.risk_level === 'moderate'
                            ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                            : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        }`}
                      >
                        {proc.risk_level.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          type="button"
                          onClick={() => setSelectedProc(proc)}
                          className="rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1 text-xs text-slate-300 transition hover:bg-white/[0.08]"
                        >
                          Inspect
                        </button>
                        <button
                          type="button"
                          title="Suspend and Isolate"
                          disabled={actionLoading === proc.pid || proc.pid <= 1}
                          onClick={() => handleIsolate(proc.pid)}
                          className="rounded-lg border border-amber-500/20 bg-amber-500/10 p-1 text-amber-400 transition hover:bg-amber-500/20 disabled:opacity-40"
                        >
                          <PauseCircle className="h-4 w-4" />
                        </button>
                        <button
                          type="button"
                          title="Terminate Process"
                          disabled={actionLoading === proc.pid || proc.pid <= 1}
                          onClick={() => handleTerminate(proc.pid, proc.name)}
                          className="rounded-lg border border-cyber-danger/20 bg-cyber-danger/10 p-1 text-cyber-danger transition hover:bg-cyber-danger/20 disabled:opacity-40"
                        >
                          <XCircle className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Inspect Modal */}
      {selectedProc && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-2xl border border-cyber-border bg-[#0d1420] p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-cyber-border pb-4">
              <h3 className="text-lg font-bold text-white">Process Inspection (PID {selectedProc.pid})</h3>
              <button
                type="button"
                onClick={() => setSelectedProc(null)}
                className="rounded-lg p-1 text-slate-400 hover:bg-white/10 hover:text-white"
              >
                ✕
              </button>
            </div>
            <div className="mt-4 space-y-3 text-sm text-slate-300">
              <div>
                <p className="text-xs uppercase text-slate-500">Binary Name</p>
                <p className="font-mono text-white">{selectedProc.name}</p>
              </div>
              <div>
                <p className="text-xs uppercase text-slate-500">Executable Path</p>
                <p className="font-mono text-xs break-all text-slate-300">{selectedProc.executable || 'Unavailable (System Worker)'}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-xs uppercase text-slate-500">CPU Usage</p>
                  <p className="font-semibold text-white">{selectedProc.cpu_percent.toFixed(1)}%</p>
                </div>
                <div>
                  <p className="text-xs uppercase text-slate-500">Memory Usage</p>
                  <p className="font-semibold text-white">{selectedProc.memory_percent.toFixed(1)}%</p>
                </div>
              </div>
              {selectedProc.reasons.length > 0 && (
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3">
                  <p className="text-xs font-semibold text-amber-400">Suspicious Indicators:</p>
                  <ul className="mt-1 list-inside list-disc text-xs text-amber-200">
                    {selectedProc.reasons.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
            <div className="mt-6 flex justify-end gap-3 border-t border-cyber-border pt-4">
              <button
                type="button"
                onClick={() => setSelectedProc(null)}
                className="rounded-xl border border-white/10 px-4 py-2 text-sm text-slate-400 hover:bg-white/5"
              >
                Close
              </button>
              <button
                type="button"
                onClick={() => {
                  const pid = selectedProc.pid
                  const name = selectedProc.name
                  setSelectedProc(null)
                  handleTerminate(pid, name)
                }}
                className="rounded-xl bg-cyber-danger px-4 py-2 text-sm font-semibold text-white hover:brightness-110"
              >
                Terminate Process
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
