import { useState, useEffect } from 'react'
import { Shield, CheckCircle, RefreshCw, Zap, Binary, Lock } from 'lucide-react'
import axios from 'axios'

export default function RansomwareProtection() {
  const [status, setStatus] = useState<any>(null)
  const [, setLoading] = useState(false)
  const [actionLoading, setActionLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [feedback, setFeedback] = useState<string | null>(null)

  // Entropy calculator state
  const [entropyInput, setEntropyInput] = useState('Confidential financial statements and plaintext customer records for quarterly evaluation.')
  const [entropyResult, setEntropyResult] = useState<any>(null)
  const [entropyLoading, setEntropyLoading] = useState(false)

  const fetchStatus = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await axios.get('/api/v1/ransomware/status')
      setStatus(res.data)
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to query ransomware shield telemetry')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchStatus()
  }, [])

  const handleDeployCanaries = async () => {
    setActionLoading(true)
    setFeedback(null)
    setError(null)
    try {
      const res = await axios.post('/api/v1/ransomware/deploy-canaries')
      setFeedback(`Successfully deployed ${res.data.deployed_count} honeypot canary tokens.`)
      fetchStatus()
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to deploy canaries')
    } finally {
      setActionLoading(false)
    }
  }

  const handleTestTripwire = async () => {
    setActionLoading(true)
    setFeedback(null)
    setError(null)
    try {
      const res = await axios.post('/api/v1/ransomware/test-tripwire')
      setFeedback(`Tripwire self-test successful! All ${res.data.result?.intact_canaries} canaries intact.`)
      fetchStatus()
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to run tripwire test')
    } finally {
      setActionLoading(false)
    }
  }

  const handleCheckEntropy = async (e: React.FormEvent) => {
    e.preventDefault()
    setEntropyLoading(true)
    try {
      const res = await axios.post('/api/v1/ransomware/check-entropy', { sample_text: entropyInput })
      setEntropyResult(res.data)
    } catch (err: any) {
      setError('Failed to compute Shannon entropy')
    } finally {
      setEntropyLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-[0.2em] text-cyber-danger">Module H / Behavioral Shield</p>
          <h2 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">Ransomware Protection & Canary Watcher</h2>
          <p className="mt-1 text-sm text-slate-400">Decoy canary tokens, Shannon entropy anomaly spikes, mass file alteration trips, and process isolation.</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleDeployCanaries}
            disabled={actionLoading}
            className="inline-flex items-center gap-2 rounded-xl bg-cyber-primary px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-slate-950 transition hover:brightness-110 disabled:opacity-50"
          >
            <Zap className="h-4 w-4" />
            Deploy Canaries
          </button>
          <button
            type="button"
            onClick={handleTestTripwire}
            disabled={actionLoading}
            className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-slate-200 transition hover:bg-white/[0.08] disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${actionLoading ? 'animate-spin' : ''}`} />
            Self-Test Tripwire
          </button>
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

      {/* Status Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="rounded-2xl border border-cyber-border bg-cyber-card p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase text-slate-400">Tripwire Status</span>
            <span className="flex h-2.5 w-2.5 rounded-full bg-cyber-primary shadow-[0_0_8px_#43f0a2]" />
          </div>
          <p className="mt-2 text-2xl font-bold text-white">
            {status?.canary_status === 'secure' ? 'Secure & Armed' : 'Monitoring'}
          </p>
          <p className="mt-1 text-xs text-slate-400">
            {status?.intact_canaries || 3} of {status?.total_canaries || 3} honeypot canaries intact
          </p>
        </div>

        <div className="rounded-2xl border border-cyber-border bg-cyber-card p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase text-slate-400">Entropy Inspector</span>
            <Binary className="h-4 w-4 text-cyber-info" />
          </div>
          <p className="mt-2 text-2xl font-bold text-white">Shannon Analysis</p>
          <p className="mt-1 text-xs text-slate-400">Flags encrypted payloads exceeding 7.2 bits/byte</p>
        </div>

        <div className="rounded-2xl border border-cyber-border bg-cyber-card p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase text-slate-400">Mass File Guard</span>
            <Lock className="h-4 w-4 text-amber-400" />
          </div>
          <p className="mt-2 text-2xl font-bold text-white">Rate Throttling</p>
          <p className="mt-1 text-xs text-slate-400">Monitors abnormal write bursts in watched directories</p>
        </div>
      </div>

      {/* Monitored Folders & Interactive Entropy Checker */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Protected Folders */}
        <div className="rounded-2xl border border-cyber-border bg-cyber-card p-5 sm:p-6">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-cyber-primary" />
            <h3 className="font-semibold text-white">Protected Directories & Canary Traps</h3>
          </div>
          <p className="mt-1 text-xs text-slate-400">Decoy files are placed in these folders. Any unauthenticated tampering immediately alerts the response engine.</p>

          <div className="mt-4 space-y-2.5">
            {[
              { path: './quarantine/.canaries', status: 'Honeypot Trap Root', armed: true },
              { path: '/home/user/Documents', status: 'User Documents Shield', armed: true },
              { path: '/home/user/Downloads', status: 'Download Staging Folder', armed: true },
              { path: '/etc/cybershield/canaries', status: 'System Root Tripwire', armed: true },
            ].map((dir, i) => (
              <div key={i} className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-black/20 p-3">
                <div>
                  <p className="font-mono text-xs text-slate-200">{dir.path}</p>
                  <p className="text-[11px] text-slate-500">{dir.status}</p>
                </div>
                <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-cyber-primary">
                  <CheckCircle className="h-3.5 w-3.5" />
                  Armed
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Live Shannon Entropy Simulator */}
        <div className="rounded-2xl border border-cyber-border bg-cyber-card p-5 sm:p-6">
          <div className="flex items-center gap-2">
            <Binary className="h-5 w-5 text-cyber-info" />
            <h3 className="font-semibold text-white">Shannon Entropy Anomaly Tester</h3>
          </div>
          <p className="mt-1 text-xs text-slate-400">Test how encrypted files jump in entropy compared to human text or source code.</p>

          <form onSubmit={handleCheckEntropy} className="mt-4 space-y-3">
            <textarea
              rows={3}
              value={entropyInput}
              onChange={(e) => setEntropyInput(e.target.value)}
              className="w-full rounded-xl border border-white/10 bg-[#070a10]/80 p-3 font-mono text-xs text-slate-200 focus:border-cyber-info focus:outline-none"
            />

            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setEntropyInput('Standard English plaintext message with predictable character frequencies.')}
                className="rounded-lg border border-white/10 px-2.5 py-1 text-[11px] text-slate-400 hover:text-white"
              >
                Sample Plaintext
              </button>
              <button
                type="button"
                onClick={() => setEntropyInput('7f#9x!@Q%mK^8vL&2*pZ(1)0wE+oR=4[tY]6{uI}|;aS:dF,gH.jK/lZ~`cxB-n_m+')}
                className="rounded-lg border border-white/10 px-2.5 py-1 text-[11px] text-slate-400 hover:text-white"
              >
                Sample Encrypted/Ciphertext
              </button>
            </div>

            <button
              type="submit"
              disabled={entropyLoading}
              className="inline-flex items-center gap-2 rounded-xl bg-cyber-info px-4 py-2 text-xs font-semibold uppercase tracking-wider text-slate-950 transition hover:brightness-110 disabled:opacity-50"
            >
              {entropyLoading ? 'Calculating...' : 'Compute Shannon Entropy'}
            </button>
          </form>

          {entropyResult && (
            <div className="mt-4 rounded-xl border border-cyber-info/30 bg-cyber-info/10 p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase text-slate-400">Calculated Entropy</span>
                <span className="font-mono text-lg font-bold text-cyber-info">{entropyResult.entropy} / {entropyResult.max_entropy}</span>
              </div>
              <p className="mt-1 text-xs text-slate-300">{entropyResult.assessment}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
