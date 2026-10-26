import { useEffect, useState } from 'react'
import { AlertTriangle, CheckCircle, Search, Clock } from 'lucide-react'
import { urlAPI } from '../lib/api'
import StatusBadge from '../components/StatusBadge'

export default function URLProtection() {
  const [url, setUrl] = useState('')
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [history, setHistory] = useState<Array<{ id: number; url: string; status: string; risk: number; time: string }>>([])
  const [protectionStatus, setProtectionStatus] = useState<string>('Checking')
  const [error, setError] = useState('')

  useEffect(() => {
    urlAPI.status()
      .then(({ data }) => setProtectionStatus(data.status === 'operational' && data.enabled ? 'Operational' : 'Unavailable'))
      .catch((requestError: unknown) => {
        console.error(requestError)
        setProtectionStatus('Unavailable')
      })
  }, [])

  const scanURL = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url.trim()) return

    try {
      new URL(url)
    } catch {
      setError('Enter a valid URL including its scheme, such as https://example.com.')
      return
    }

    setScanning(true)
    setResult(null)
    setError('')
    try {
      const response = await urlAPI.scan(url)
      setResult(response.data)
      setHistory(history => [{
        id: Date.now(),
        url: url,
        status: response.data.action === 'block' ? 'blocked' : response.data.action === 'warn' ? 'warning' : 'safe',
        risk: response.data.risk.score,
        time: 'Just now'
      }, ...history])
    } catch (requestError) {
      console.error(requestError)
      setError('URL analysis failed. Check the backend connection and try again.')
    } finally {
      setScanning(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">URL Protection</h2>
        <p className="text-gray-400 text-sm">Real-time phishing and malicious URL detection</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Search className="w-5 h-5" />
              Scan URL
            </h3>
            <form onSubmit={scanURL} className="flex gap-3 mb-4">
              <label htmlFor="url-analysis-input" className="sr-only">URL to analyze</label>
              <input
                id="url-analysis-input"
                type="url"
                value={url}
                onChange={(e) => { setUrl(e.target.value); setError('') }}
                placeholder="https://example.com"
                className="flex-1 px-4 py-2 bg-sentinel-bg border border-sentinel-border rounded focus:outline-none focus:border-sentinel-primary"
                required
              />
              <button
                type="submit"
                disabled={scanning}
                className="px-6 py-2 bg-sentinel-primary text-black font-medium rounded hover:bg-sentinel-primary/90 transition-colors disabled:opacity-50"
              >
                {scanning ? 'Scanning...' : 'Scan URL'}
              </button>
            </form>
            {error && <p role="alert" className="mb-3 rounded-lg border border-sentinel-danger/25 bg-sentinel-danger/10 px-3 py-2 text-sm text-red-200">{error}</p>}
            <p className="text-xs text-gray-500">Enter any URL to check for phishing, malware, or suspicious content</p>
          </div>

          {result && (
            <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                {result.action === 'block' ? (
                  <AlertTriangle className="w-5 h-5 text-sentinel-danger" />
                ) : result.action === 'warn' ? (
                  <AlertTriangle className="w-5 h-5 text-sentinel-warning" />
                ) : (
                  <CheckCircle className="w-5 h-5 text-sentinel-primary" />
                )}
                Scan Results
              </h3>
              <div className="space-y-4">
                <div className="p-3 bg-sentinel-bg rounded break-all">
                  <div className="text-xs text-gray-400 mb-1">URL</div>
                  <div className="text-sm">{result.url}</div>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="p-3 bg-sentinel-bg rounded text-center">
                    <div className={`text-2xl font-bold ${result.risk.score >= 70 ? 'text-sentinel-danger' : result.risk.score >= 40 ? 'text-sentinel-warning' : 'text-sentinel-primary'}`}>
                      {result.risk.score}
                    </div>
                    <div className="text-xs text-gray-400">Risk Score</div>
                  </div>
                  <div className="p-3 bg-sentinel-bg rounded text-center">
                    <div className="text-sm font-medium capitalize">{result.risk.level}</div>
                    <div className="text-xs text-gray-400">Risk Level</div>
                  </div>
                  <div className="p-3 bg-sentinel-bg rounded text-center">
                    <div className={`text-sm font-medium ${result.action === 'block' ? 'text-sentinel-danger' : result.action === 'warn' ? 'text-sentinel-warning' : 'text-sentinel-primary'}`}>
                      {result.action.toUpperCase()}
                    </div>
                    <div className="text-xs text-gray-400">Action</div>
                  </div>
                  <div className="p-3 bg-sentinel-bg rounded text-center">
                    <div className="text-sm font-medium">{result.is_phishing ? 'Yes' : 'No'}</div>
                    <div className="text-xs text-gray-400">Phishing</div>
                  </div>
                </div>
                {result.reasons && result.reasons.length > 0 && (
                  <div className="p-4 bg-sentinel-bg rounded">
                    <div className="text-sm font-medium mb-2">Detection Reasons</div>
                    <ul className="space-y-1">
                      {result.reasons.map((reason: string, i: number) => (
                        <li key={i} className="text-sm text-gray-300 flex items-start gap-2">
                          <span className="text-sentinel-warning mt-1">•</span>
                          {reason}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {result.risk.explainability && Object.keys(result.risk.explainability).length > 0 && (
                  <div className="p-4 bg-sentinel-bg rounded">
                    <div className="text-sm font-medium mb-2">Risk Breakdown</div>
                    <div className="space-y-2">
                      {Object.entries(result.risk.explainability).map(([key, value]: [string, any]) => (
                        <div key={key} className="flex items-center justify-between text-sm">
                          <span className="text-gray-400 capitalize">{key.replace(/_/g, ' ')}</span>
                          <span className="text-sentinel-warning">+{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Clock className="w-5 h-5" />
              Scan History
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-sentinel-border">
                    <th className="text-left text-sm font-medium text-gray-400 pb-2">URL</th>
                    <th className="text-left text-sm font-medium text-gray-400 pb-2">Status</th>
                    <th className="text-left text-sm font-medium text-gray-400 pb-2">Risk</th>
                    <th className="text-left text-sm font-medium text-gray-400 pb-2">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {history.length === 0 ? <tr><td colSpan={4} className="py-6 text-center text-sm text-slate-500">No URLs analyzed on this screen yet.</td></tr> : history.map((item) => (
                    <tr key={item.id} className="border-b border-sentinel-border/50">
                      <td className="py-3 text-sm truncate max-w-xs">{item.url}</td>
                      <td className="py-3">
                        <StatusBadge
                          status={item.status === 'safe' ? 'ok' : item.status === 'warning' ? 'warning' : 'danger'}
                          text={item.status.toUpperCase()}
                        />
                      </td>
                      <td className="py-3 text-sm">{item.risk}</td>
                      <td className="py-3 text-sm text-gray-400">{item.time}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
        <h3 className="text-lg font-semibold mb-4">Analysis service</h3>
        <div className="space-y-3">
          <div className="flex items-center justify-between p-3 bg-sentinel-bg rounded">
            <span className="text-sm">URL analysis API</span>
            <StatusBadge status={protectionStatus === 'Operational' ? 'active' : protectionStatus === 'Checking' ? 'warning' : 'inactive'} text={protectionStatus} />
          </div>
          <p className="text-xs leading-5 text-slate-500">Results are based on the connected analysis engine. This screen does not enforce browser-wide blocking or maintain server-side allow/block lists.</p>
        </div>
          </div>
        </div>
      </div>
    </div>
  )
}
