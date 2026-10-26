import { useState, useEffect } from 'react'
import { Globe, Shield, Download, Puzzle, Search, ShieldCheck } from 'lucide-react'
import axios from 'axios'

export default function BrowserProtection() {
  const [stats, setStats] = useState({
    urls_inspected: 1420,
    threats_blocked: 38,
    phishing_prevented: 24,
    dangerous_downloads_halted: 7,
  })

  // URL test state
  const [urlInput, setUrlInput] = useState('http://paypal-security-update.fake-portal.com/login')
  const [hasPassword, setHasPassword] = useState(true)
  const [isHttps, setIsHttps] = useState(false)
  const [urlLoading, setUrlLoading] = useState(false)
  const [urlResult, setUrlResult] = useState<any>(null)

  // Download test state
  const [downloadFilename, setDownloadFilename] = useState('invoice_october.pdf.exe')
  const [downloadUrl, setDownloadUrl] = useState('http://185.120.34.12/payload')
  const [downloadLoading, setDownloadLoading] = useState(false)
  const [downloadResult, setDownloadResult] = useState<any>(null)

  // Extension analysis state
  const [extensionJson, setExtensionJson] = useState(`{
  "name": "WebEnhancer Pro",
  "version": "2.1",
  "permissions": ["<all_urls>", "webRequestBlocking", "cookies", "management"]
}`)
  const [extLoading, setExtLoading] = useState(false)
  const [extResult, setExtResult] = useState<any>(null)

  const [error, setError] = useState<string | null>(null)

  const fetchStats = async () => {
    try {
      const res = await axios.get('/api/v1/browser/stats')
      setStats(res.data)
    } catch (e) {
      // Use initial state as baseline
    }
  }

  useEffect(() => {
    fetchStats()
  }, [])

  const handleTestUrl = async (e: React.FormEvent) => {
    e.preventDefault()
    setUrlLoading(true)
    setError(null)
    setUrlResult(null)
    try {
      const res = await axios.post('/api/v1/browser/check-url', {
        url: urlInput,
        has_password_field: hasPassword,
        is_https: isHttps,
      })
      setUrlResult(res.data)
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to inspect URL')
    } finally {
      setUrlLoading(false)
    }
  }

  const handleTestDownload = async (e: React.FormEvent) => {
    e.preventDefault()
    setDownloadLoading(true)
    setError(null)
    setDownloadResult(null)
    try {
      const res = await axios.post('/api/v1/browser/check-download', {
        filename: downloadFilename,
        source_url: downloadUrl,
      })
      setDownloadResult(res.data)
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to analyze download safety')
    } finally {
      setDownloadLoading(false)
    }
  }

  const handleAnalyzeExtension = async (e: React.FormEvent) => {
    e.preventDefault()
    setExtLoading(true)
    setError(null)
    setExtResult(null)
    try {
      const parsed = JSON.parse(extensionJson)
      const res = await axios.post('/api/v1/browser/analyze-extension', {
        manifest: parsed,
      })
      setExtResult(res.data)
    } catch (err: any) {
      setError(err.message || 'Invalid JSON format in extension manifest')
    } finally {
      setExtLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-[0.2em] text-cyber-info">Module F / Web Security</p>
          <h2 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">Browser Protection & Extension Guard</h2>
          <p className="mt-1 text-sm text-slate-400">Real-time anti-phishing, fake credential harvesting prevention, malicious download blocking, and extension privilege auditing.</p>
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <div className="rounded-2xl border border-cyber-border bg-cyber-card p-4">
          <p className="text-xs uppercase text-slate-400">Inspected Pages</p>
          <p className="mt-1 text-2xl font-bold text-white">{stats.urls_inspected}</p>
        </div>
        <div className="rounded-2xl border border-cyber-border bg-cyber-card p-4">
          <p className="text-xs uppercase text-slate-400">Threats Blocked</p>
          <p className="mt-1 text-2xl font-bold text-cyber-danger">{stats.threats_blocked}</p>
        </div>
        <div className="rounded-2xl border border-cyber-border bg-cyber-card p-4">
          <p className="text-xs uppercase text-slate-400">Phishing Thwarted</p>
          <p className="mt-1 text-2xl font-bold text-cyber-warning">{stats.phishing_prevented}</p>
        </div>
        <div className="rounded-2xl border border-cyber-border bg-cyber-card p-4">
          <p className="text-xs uppercase text-slate-400">Dangerous Downloads</p>
          <p className="mt-1 text-2xl font-bold text-cyber-info">{stats.dangerous_downloads_halted}</p>
        </div>
      </div>

      {error && (
        <div role="alert" className="rounded-xl border border-cyber-danger/30 bg-cyber-danger/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Main Grid: URL Analyzer & Download Analyzer */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* URL / Fake Login Checker */}
        <div className="rounded-2xl border border-cyber-border bg-cyber-card p-5 sm:p-6">
          <div className="flex items-center gap-2">
            <Globe className="h-5 w-5 text-cyber-info" />
            <h3 className="font-semibold text-white">Browser URL & Phishing Inspector</h3>
          </div>
          <p className="mt-1 text-xs text-slate-400">Simulate browser page navigation and test brand impersonation detection.</p>

          <form onSubmit={handleTestUrl} className="mt-4 space-y-4">
            <div>
              <label className="text-xs font-semibold uppercase text-slate-400">Destination URL</label>
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                className="mt-1.5 w-full rounded-xl border border-white/10 bg-[#070a10]/80 px-4 py-2.5 text-sm text-white focus:border-cyber-info focus:outline-none"
                required
              />
            </div>

            <div className="flex items-center gap-6">
              <label className="flex items-center gap-2 text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={hasPassword}
                  onChange={(e) => setHasPassword(e.target.checked)}
                  className="rounded border-white/20 bg-[#070a10] text-cyber-info focus:ring-0"
                />
                Contains password input
              </label>

              <label className="flex items-center gap-2 text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={isHttps}
                  onChange={(e) => setIsHttps(e.target.checked)}
                  className="rounded border-white/20 bg-[#070a10] text-cyber-info focus:ring-0"
                />
                Enforce HTTPS
              </label>
            </div>

            <button
              type="submit"
              disabled={urlLoading}
              className="inline-flex items-center gap-2 rounded-xl bg-cyber-info px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-slate-950 transition hover:brightness-110 disabled:opacity-50"
            >
              <Search className="h-4 w-4" />
              {urlLoading ? 'Inspecting...' : 'Analyze Page Safety'}
            </button>
          </form>

          {urlResult && (
            <div className={`mt-5 rounded-xl border p-4 ${
              urlResult.action === 'block'
                ? 'border-cyber-danger/30 bg-cyber-danger/10'
                : urlResult.action === 'warn'
                ? 'border-cyber-warning/30 bg-cyber-warning/10'
                : 'border-cyber-primary/30 bg-cyber-primary/10'
            }`}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider">Verdict: {urlResult.action.toUpperCase()}</span>
                <span className="font-mono text-sm font-bold">Score: {urlResult.risk_score}/100</span>
              </div>
              <p className="mt-2 text-xs text-slate-300">Domain: <span className="font-mono text-white">{urlResult.domain}</span></p>
              {urlResult.reasons.length > 0 && (
                <ul className="mt-2 list-inside list-disc text-xs text-slate-300 space-y-1">
                  {urlResult.reasons.map((r: string, i: number) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>

        {/* Download Safety Analyzer */}
        <div className="rounded-2xl border border-cyber-border bg-cyber-card p-5 sm:p-6">
          <div className="flex items-center gap-2">
            <Download className="h-5 w-5 text-cyber-primary" />
            <h3 className="font-semibold text-white">Download Safety Analyzer</h3>
          </div>
          <p className="mt-1 text-xs text-slate-400">Detect deceptive double extensions, executable droppers, and raw IP origins.</p>

          <form onSubmit={handleTestDownload} className="mt-4 space-y-4">
            <div>
              <label className="text-xs font-semibold uppercase text-slate-400">Download Filename</label>
              <input
                type="text"
                value={downloadFilename}
                onChange={(e) => setDownloadFilename(e.target.value)}
                className="mt-1.5 w-full rounded-xl border border-white/10 bg-[#070a10]/80 px-4 py-2.5 text-sm text-white focus:border-cyber-primary focus:outline-none"
                required
              />
            </div>

            <div>
              <label className="text-xs font-semibold uppercase text-slate-400">Source URL</label>
              <input
                type="text"
                value={downloadUrl}
                onChange={(e) => setDownloadUrl(e.target.value)}
                className="mt-1.5 w-full rounded-xl border border-white/10 bg-[#070a10]/80 px-4 py-2.5 text-sm text-white focus:border-cyber-primary focus:outline-none"
                required
              />
            </div>

            <button
              type="submit"
              disabled={downloadLoading}
              className="inline-flex items-center gap-2 rounded-xl bg-cyber-primary px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-slate-950 transition hover:brightness-110 disabled:opacity-50"
            >
              <Shield className="h-4 w-4" />
              {downloadLoading ? 'Scanning...' : 'Verify Download'}
            </button>
          </form>

          {downloadResult && (
            <div className={`mt-5 rounded-xl border p-4 ${
              downloadResult.is_dangerous
                ? 'border-cyber-danger/30 bg-cyber-danger/10'
                : 'border-cyber-primary/30 bg-cyber-primary/10'
            }`}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider">
                  {downloadResult.is_dangerous ? 'HIGH RISK PAYLOAD DETECTED' : 'DOWNLOAD VERIFIED SAFE'}
                </span>
                <span className="font-mono text-sm font-bold">Score: {downloadResult.risk_score}/100</span>
              </div>
              {downloadResult.reasons.length > 0 && (
                <ul className="mt-2 list-inside list-disc text-xs text-slate-300 space-y-1">
                  {downloadResult.reasons.map((r: string, i: number) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Extension Permission Risk Inspector */}
      <div className="rounded-2xl border border-cyber-border bg-cyber-card p-5 sm:p-6">
        <div className="flex items-center gap-2">
          <Puzzle className="h-5 w-5 text-amber-400" />
          <h3 className="font-semibold text-white">Browser Extension Permission Assessor</h3>
        </div>
        <p className="mt-1 text-xs text-slate-400">Paste an extension manifest.json to detect excessive permissions (e.g. webRequestBlocking, session cookie interception).</p>

        <form onSubmit={handleAnalyzeExtension} className="mt-4 space-y-4">
          <textarea
            rows={5}
            value={extensionJson}
            onChange={(e) => setExtensionJson(e.target.value)}
            className="w-full rounded-xl border border-white/10 bg-[#070a10]/80 p-3 font-mono text-xs text-slate-200 focus:border-amber-400 focus:outline-none"
          />

          <button
            type="submit"
            disabled={extLoading}
            className="inline-flex items-center gap-2 rounded-xl border border-amber-400/40 bg-amber-400/10 px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-amber-300 transition hover:bg-amber-400/20 disabled:opacity-50"
          >
            <ShieldCheck className="h-4 w-4" />
            {extLoading ? 'Auditing Manifest...' : 'Audit Extension Permissions'}
          </button>
        </form>

        {extResult && (
          <div className="mt-5 rounded-xl border border-white/10 bg-black/30 p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-bold text-white">{extResult.name} v{extResult.version}</p>
                <p className="text-xs text-slate-400">Risk Assessment: <span className="font-semibold uppercase text-amber-400">{extResult.risk_level}</span></p>
              </div>
              <span className="font-mono text-lg font-bold text-amber-400">{extResult.risk_score}/100</span>
            </div>

            {extResult.reasons.length > 0 && (
              <div className="mt-3 space-y-1">
                {extResult.reasons.map((r: string, i: number) => (
                  <p key={i} className="text-xs text-amber-200">• {r}</p>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
