import { useEffect, useState } from 'react'
import { FileText, RefreshCw, ScrollText } from 'lucide-react'
import { reportsAPI } from '../lib/api'
import StatusBadge from '../components/StatusBadge'
import LoadingSpinner from '../components/LoadingSpinner'

type Report = { id: string; type: string; date: string; format: string; status: string }
type GeneratedReport = { report_id: string; type: string; format: string }

export default function SecurityReports() {
  const [reports, setReports] = useState<Report[]>([])
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState('')
  const [generated, setGenerated] = useState<GeneratedReport | null>(null)

  const refresh = async () => {
    setLoading(true)
    setError('')
    try {
      const { data } = await reportsAPI.list()
      setReports(Array.isArray(data.reports) ? data.reports : [])
    } catch (requestError) {
      console.error(requestError)
      setError('Reports could not be loaded.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void refresh() }, [])

  const generateReport = async () => {
    setGenerating(true)
    setError('')
    setGenerated(null)
    try {
      const { data } = await reportsAPI.generate('summary')
      if (data.generated) setGenerated({ report_id: data.report_id, type: data.type, format: data.format })
      else setError('The backend did not confirm report generation.')
    } catch (requestError) {
      console.error(requestError)
      setError('Report generation failed.')
    } finally {
      setGenerating(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-[0.2em] text-sentinel-info">Audit & insights</p>
          <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">Security reports</h2>
          <p className="mt-1 text-sm text-slate-400">Reports listed by and generated through the reporting API.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => void refresh()} disabled={loading} className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.035] px-4 py-2.5 text-sm text-slate-200 transition hover:bg-white/[0.07] disabled:opacity-50"><RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />Refresh</button>
          <button type="button" onClick={() => void generateReport()} disabled={generating} className="inline-flex items-center gap-2 rounded-xl bg-sentinel-primary px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:brightness-110 disabled:opacity-50"><FileText className="h-4 w-4" />{generating ? 'Generating…' : 'Generate summary'}</button>
        </div>
      </div>

      {error && <p role="alert" className="rounded-xl border border-sentinel-danger/25 bg-sentinel-danger/10 px-4 py-3 text-sm text-red-200">{error}</p>}
      {generated && <div role="status" className="rounded-xl border border-sentinel-primary/20 bg-sentinel-primary/[0.07] px-4 py-3 text-sm text-sentinel-primary">Generation confirmed: {generated.type} ({generated.format}), ID {generated.report_id}. The current API does not provide a download endpoint.</div>}
      <section className="overflow-hidden rounded-2xl border border-sentinel-border bg-sentinel-card shadow-lg shadow-black/10">
        <div className="flex items-center justify-between gap-3 border-b border-white/[0.08] px-5 py-4 sm:px-6">
          <div><h3 className="font-semibold">Available reports</h3><p className="mt-1 text-xs text-slate-500">{reports.length} records returned by the service</p></div>
          <span className="grid h-9 w-9 place-items-center rounded-xl border border-sentinel-info/20 bg-sentinel-info/[0.08] text-sentinel-info"><ScrollText className="h-4 w-4" /></span>
        </div>
        {loading ? <LoadingSpinner /> : reports.length === 0 ? <p className="px-6 py-12 text-center text-sm text-slate-500">No reports returned by the backend.</p> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[600px] text-left">
              <thead className="bg-black/20 text-xs uppercase tracking-wider text-slate-500"><tr><th className="px-5 py-3 font-medium">Report</th><th className="px-5 py-3 font-medium">Date</th><th className="px-5 py-3 font-medium">Format</th><th className="px-5 py-3 font-medium">Status</th></tr></thead>
              <tbody>{reports.map(report => <tr key={report.id} className="border-t border-white/[0.06] text-sm"><td className="px-5 py-4"><p className="font-medium text-slate-200">{report.type}</p><p className="mt-1 text-xs text-slate-500">{report.id}</p></td><td className="px-5 py-4 text-slate-400">{report.date}</td><td className="px-5 py-4 text-slate-300">{report.format}</td><td className="px-5 py-4"><StatusBadge status={report.status.toLowerCase() === 'available' ? 'active' : 'inactive'} text={report.status} /></td></tr>)}</tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
