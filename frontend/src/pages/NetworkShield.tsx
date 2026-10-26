import { useEffect, useState } from 'react'
import { Activity, AlertTriangle, Search, Shield, Wifi } from 'lucide-react'
import { networkAPI } from '../lib/api'
import StatusBadge from '../components/StatusBadge'

type Analysis = {
  id: number
  destination: string
  protocol: string
  score: number
  level: string
  suspicious: boolean
  action: string
  reasons: string[]
}

export default function NetworkShield() {
  const [destination, setDestination] = useState('')
  const [port, setPort] = useState('')
  const [protocol, setProtocol] = useState('TCP')
  const [status, setStatus] = useState<'checking' | 'operational' | 'unavailable'>('checking')
  const [analysis, setAnalysis] = useState<Analysis | null>(null)
  const [history, setHistory] = useState<Analysis[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    networkAPI.status()
      .then(({ data }) => setStatus(data.enabled && data.status === 'operational' ? 'operational' : 'unavailable'))
      .catch((requestError: unknown) => {
        console.error(requestError)
        setStatus('unavailable')
      })
  }, [])

  const analyzeConnection = async (event: React.FormEvent) => {
    event.preventDefault()
    const portNumber = Number(port)
    if (!destination.trim() || !Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
      setError('Enter a destination IP and a port between 1 and 65535.')
      return
    }
    setError('')
    setLoading(true)
    setAnalysis(null)
    try {
      const { data } = await networkAPI.analyze({ dst_ip: destination.trim(), dst_port: portNumber, protocol })
      const record: Analysis = {
        id: Date.now(),
        destination: `${destination.trim()}:${portNumber}`,
        protocol,
        score: data.risk.score,
        level: data.risk.level,
        suspicious: Boolean(data.suspicious),
        action: data.action,
        reasons: Array.isArray(data.reasons) ? data.reasons : [],
      }
      setAnalysis(record)
      setHistory(current => [record, ...current])
    } catch (requestError) {
      console.error(requestError)
      setError('Connection analysis failed. Check the backend connection and try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-[0.2em] text-sentinel-info">Network defense</p>
          <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">Network shield</h2>
          <p className="mt-1 text-sm text-slate-400">Analyze a destination using the configured network risk engine.</p>
        </div>
        <StatusBadge status={status === 'operational' ? 'active' : status === 'checking' ? 'warning' : 'inactive'} text={status === 'operational' ? 'Analysis API online' : status === 'checking' ? 'Checking service' : 'Service unavailable'} />
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_300px]">
        <section className="rounded-2xl border border-sentinel-border bg-sentinel-card p-5 shadow-lg shadow-black/10 sm:p-6">
          <h3 className="flex items-center gap-2 font-semibold"><Search className="h-4 w-4 text-sentinel-info" />Analyze destination</h3>
          <form onSubmit={analyzeConnection} className="mt-5 grid gap-4 sm:grid-cols-2">
            <label className="text-sm text-slate-300 sm:col-span-2">
              Destination IP
              <input value={destination} onChange={event => setDestination(event.target.value)} placeholder="203.0.113.10" className="mt-2 w-full rounded-xl border border-white/10 bg-[#070a10]/80 px-4 py-3 text-sm text-slate-100 placeholder:text-slate-600 focus:border-sentinel-info/50 focus:outline-none" required />
            </label>
            <label className="text-sm text-slate-300">
              Destination port
              <input type="number" min="1" max="65535" step="1" value={port} onChange={event => setPort(event.target.value)} placeholder="443" className="mt-2 w-full rounded-xl border border-white/10 bg-[#070a10]/80 px-4 py-3 text-sm text-slate-100 placeholder:text-slate-600 focus:border-sentinel-info/50 focus:outline-none" required />
            </label>
            <label className="text-sm text-slate-300">
              Protocol
              <select value={protocol} onChange={event => setProtocol(event.target.value)} className="mt-2 w-full rounded-xl border border-white/10 bg-[#070a10]/80 px-4 py-3 text-sm text-slate-100 focus:border-sentinel-info/50 focus:outline-none">
                <option>TCP</option><option>UDP</option><option>ICMP</option>
              </select>
            </label>
            <button type="submit" disabled={loading} className="inline-flex items-center justify-center gap-2 rounded-xl bg-sentinel-info px-5 py-3 text-sm font-semibold text-slate-950 transition hover:brightness-110 disabled:opacity-50 sm:col-span-2 sm:justify-self-start">
              <Activity className="h-4 w-4" />{loading ? 'Analyzing…' : 'Analyze connection'}
            </button>
          </form>
          {error && <p role="alert" className="mt-4 rounded-xl border border-sentinel-danger/25 bg-sentinel-danger/10 px-4 py-3 text-sm text-red-200">{error}</p>}
        </section>

        <section className="rounded-2xl border border-sentinel-border bg-sentinel-card p-5 shadow-lg shadow-black/10 sm:p-6">
          <h3 className="flex items-center gap-2 font-semibold"><Wifi className="h-4 w-4 text-sentinel-primary" />Integration status</h3>
          <div className="mt-5 space-y-3">
            <StatusRow label="Connection analysis" active={status === 'operational'} value={status === 'checking' ? 'Checking' : status === 'operational' ? 'Available' : 'Unavailable'} />
            <StatusRow label="Live traffic capture" active={false} value="Not provided by API" />
            <StatusRow label="Blocking controls" active={false} value="Not provided by API" />
          </div>
          <p className="mt-4 text-xs leading-5 text-slate-500">The service returns a recommended action; this dashboard cannot enforce network blocks or display live connection telemetry.</p>
        </section>
      </div>

      {analysis && (
        <section className="rounded-2xl border border-sentinel-border bg-sentinel-card p-5 sm:p-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <h3 className="flex items-center gap-2 font-semibold">{analysis.suspicious ? <AlertTriangle className="h-4 w-4 text-sentinel-warning" /> : <Shield className="h-4 w-4 text-sentinel-primary" />}Analysis result</h3>
            <StatusBadge status={analysis.action === 'block' ? 'danger' : analysis.action === 'warn' ? 'warning' : 'active'} text={`Recommended: ${analysis.action}`} />
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            <ResultValue label="Destination" value={`${analysis.destination} · ${analysis.protocol}`} />
            <ResultValue label="Risk score" value={`${analysis.score}/100 · ${analysis.level}`} />
            <ResultValue label="Suspicious" value={analysis.suspicious ? 'Yes' : 'No'} />
          </div>
          {analysis.reasons.length > 0 && <ul className="mt-4 space-y-2 text-sm text-slate-300">{analysis.reasons.map((reason, index) => <li key={index} className="flex gap-2"><span className="text-sentinel-warning">•</span>{reason}</li>)}</ul>}
        </section>
      )}

      <section className="rounded-2xl border border-sentinel-border bg-sentinel-card p-5 sm:p-6">
        <h3 className="font-semibold">Analysis history</h3>
        <p className="mt-1 text-xs text-slate-500">Results from this screen instance; history is not persisted.</p>
        {history.length === 0 ? <p className="py-8 text-center text-sm text-slate-500">No destinations analyzed on this screen yet.</p> : (
          <div className="mt-4 overflow-x-auto">
            <table className="w-full min-w-[620px] text-left text-sm">
              <thead className="text-xs uppercase tracking-wider text-slate-500"><tr><th className="py-3 pr-4">Destination</th><th className="py-3 pr-4">Risk</th><th className="py-3 pr-4">Verdict</th><th className="py-3">Recommendation</th></tr></thead>
              <tbody>{history.map(item => <tr key={item.id} className="border-t border-white/[0.06]"><td className="py-3 pr-4 text-slate-300">{item.destination} · {item.protocol}</td><td className="py-3 pr-4">{item.score} · {item.level}</td><td className="py-3 pr-4">{item.suspicious ? 'Suspicious' : 'No indicator'}</td><td className="py-3 capitalize text-slate-300">{item.action}</td></tr>)}</tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}

function StatusRow({ label, value, active }: { label: string; value: string; active: boolean }) {
  return <div className="flex items-center justify-between gap-3 rounded-xl border border-white/[0.06] bg-black/20 px-3 py-3"><span className="text-sm text-slate-400">{label}</span><span className={`text-right text-xs ${active ? 'text-sentinel-primary' : 'text-slate-500'}`}>{value}</span></div>
}

function ResultValue({ label, value }: { label: string; value: string }) {
  return <div className="rounded-xl border border-white/[0.06] bg-black/20 p-4"><p className="text-xs text-slate-500">{label}</p><p className="mt-2 break-words text-sm font-medium text-slate-100">{value}</p></div>
}
