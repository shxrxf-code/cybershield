import { useState, useEffect } from 'react'
import { Shield, Sliders, Save, RotateCcw, Plus, ShieldCheck, Zap, Lock, EyeOff, Gamepad2, Wrench } from 'lucide-react'
import axios from 'axios'

export default function Settings() {
  const [settings, setSettings] = useState<any>({
    protection_mode: 'smart',
    real_time_url_protection: true,
    file_monitor_enabled: true,
    network_shield_enabled: true,
    ransomware_shield_enabled: true,
    app_permission_monitor_enabled: true,
    auto_quarantine_critical: true,
    scan_schedule: 'daily',
    trusted_domains: ['google.com', 'microsoft.com', 'github.com', 'apple.com'],
    blocked_domains: ['malware-payload-drop.org', 'fake-phish-bank.xyz', 'cryptostealer-c2.net'],
  })

  const [, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [feedback, setFeedback] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const [newTrustedDomain, setNewTrustedDomain] = useState('')
  const [newBlockedDomain, setNewBlockedDomain] = useState('')

  const fetchSettings = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await axios.get('/api/v1/settings/')
      setSettings(res.data)
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to fetch settings')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchSettings()
  }, [])

  const handleSave = async () => {
    setSaving(true)
    setFeedback(null)
    setError(null)
    try {
      const res = await axios.put('/api/v1/settings/', settings)
      setFeedback(res.data.message || 'Security settings successfully saved.')
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to save settings')
    } finally {
      setSaving(false)
    }
  }

  const handleModeChange = async (mode: string) => {
    try {
      const res = await axios.post(`/api/v1/settings/mode/${mode}`)
      setSettings(res.data.settings)
      setFeedback(`Active protection mode set to ${mode.toUpperCase()}`)
    } catch (err: any) {
      setError('Failed to switch protection mode')
    }
  }

  const handleReset = async () => {
    if (!window.confirm('Reset all security settings to factory baseline defaults?')) return
    try {
      const res = await axios.post('/api/v1/settings/reset')
      setSettings(res.data.settings)
      setFeedback('Settings restored to baseline.')
    } catch (err: any) {
      setError('Failed to reset settings')
    }
  }

  const addTrustedDomain = () => {
    if (!newTrustedDomain.trim()) return
    const domain = newTrustedDomain.trim().toLowerCase()
    if (!settings.trusted_domains.includes(domain)) {
      setSettings({ ...settings, trusted_domains: [...settings.trusted_domains, domain] })
    }
    setNewTrustedDomain('')
  }

  const removeTrustedDomain = (domain: string) => {
    setSettings({
      ...settings,
      trusted_domains: settings.trusted_domains.filter((d: string) => d !== domain),
    })
  }

  const addBlockedDomain = () => {
    if (!newBlockedDomain.trim()) return
    const domain = newBlockedDomain.trim().toLowerCase()
    if (!settings.blocked_domains.includes(domain)) {
      setSettings({ ...settings, blocked_domains: [...settings.blocked_domains, domain] })
    }
    setNewBlockedDomain('')
  }

  const removeBlockedDomain = (domain: string) => {
    setSettings({
      ...settings,
      blocked_domains: settings.blocked_domains.filter((d: string) => d !== domain),
    })
  }

  const modes = [
    { id: 'smart', label: 'Smart Protection', icon: ShieldCheck, desc: 'Balanced AI & heuristic defense with minimal resource impact' },
    { id: 'deep', label: 'Deep Scan', icon: Zap, desc: 'Maximum sensitivity, hourly background checks, strict inspection' },
    { id: 'network_shield', label: 'Network Shield', icon: Lock, desc: 'Focuses on DNS threat blocking and MITM defense' },
    { id: 'privacy', label: 'Privacy Mode', icon: EyeOff, desc: 'Strict application permission auditing and tracker isolation' },
    { id: 'gaming', label: 'Gaming Mode', icon: Gamepad2, desc: 'Suppresses non-critical notifications and background scans' },
    { id: 'manual', label: 'Manual Control', icon: Wrench, desc: 'Requires explicit user authorization before any quarantine or block' },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-[0.2em] text-cyber-primary">Section 5 / User Control</p>
          <h2 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">Security Settings & Protection Modes</h2>
          <p className="mt-1 text-sm text-slate-400">Configure operational modes, real-time threat response triggers, and network access lists.</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleReset}
            className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-slate-300 hover:bg-white/[0.08]"
          >
            <RotateCcw className="h-4 w-4" />
            Reset Baseline
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={saving}
            className="inline-flex items-center gap-2 rounded-xl bg-cyber-primary px-5 py-2.5 text-xs font-semibold uppercase tracking-wider text-slate-950 transition hover:brightness-110 disabled:opacity-50"
          >
            <Save className="h-4 w-4" />
            {saving ? 'Saving...' : 'Save Settings'}
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

      {/* Protection Modes Selection */}
      <div className="rounded-2xl border border-cyber-border bg-cyber-card p-5 sm:p-6">
        <h3 className="font-semibold text-white flex items-center gap-2">
          <Shield className="h-4 w-4 text-cyber-primary" />
          Operating Protection Mode
        </h3>
        <p className="mt-1 text-xs text-slate-400">Select active policy behavior profile across all monitored security categories.</p>

        <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {modes.map((m) => {
            const Icon = m.icon
            const isSelected = settings.protection_mode === m.id
            return (
              <button
                type="button"
                key={m.id}
                onClick={() => handleModeChange(m.id)}
                className={`flex flex-col text-left rounded-xl border p-4 transition ${
                  isSelected
                    ? 'border-cyber-primary/50 bg-cyber-primary/[0.08] shadow-[0_0_15px_rgba(67,240,162,0.1)]'
                    : 'border-white/10 bg-black/20 hover:border-white/20'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className={`grid h-8 w-8 place-items-center rounded-lg ${
                    isSelected ? 'bg-cyber-primary text-slate-950' : 'bg-white/5 text-slate-300'
                  }`}>
                    <Icon className="h-4 w-4" />
                  </div>
                  {isSelected && (
                    <span className="text-[11px] font-bold uppercase tracking-wider text-cyber-primary">Active</span>
                  )}
                </div>
                <p className="mt-3 text-sm font-bold text-white">{m.label}</p>
                <p className="mt-1 text-xs text-slate-400">{m.desc}</p>
              </button>
            )
          })}
        </div>
      </div>

      {/* Category Toggles & Scan Frequency */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Real-Time Toggles */}
        <div className="rounded-2xl border border-cyber-border bg-cyber-card p-5 sm:p-6">
          <h3 className="font-semibold text-white flex items-center gap-2">
            <Sliders className="h-4 w-4 text-cyber-info" />
            Monitoring Category Toggles
          </h3>
          <p className="mt-1 text-xs text-slate-400">Enable or disable specific security monitoring modules.</p>

          <div className="mt-4 space-y-3">
            {[
              { key: 'real_time_url_protection', label: 'Real-Time URL & Phishing Shield', desc: 'Inspects web navigation and blocks malicious sites' },
              { key: 'file_monitor_enabled', label: 'Continuous File & Malware Scanner', desc: 'ClamAV and YARA background inspection' },
              { key: 'network_shield_enabled', label: 'Network Shield & DNS Filter', desc: 'Filters outbound connections and inspects DNS' },
              { key: 'ransomware_shield_enabled', label: 'Ransomware Canary Tripwires', desc: 'Monitors honeypot files and entropy anomalies' },
              { key: 'app_permission_monitor_enabled', label: 'App Permission & Privacy Monitor', desc: 'Alerts on excessive background camera/mic/storage access' },
              { key: 'auto_quarantine_critical', label: 'Automatic Critical Threat Quarantine', desc: 'Isolates confirmed malware signatures automatically' },
            ].map((toggle) => (
              <label key={toggle.key} className="flex items-start justify-between gap-4 rounded-xl border border-white/[0.05] bg-black/20 p-3 cursor-pointer hover:bg-black/30">
                <div>
                  <p className="text-sm font-semibold text-white">{toggle.label}</p>
                  <p className="text-xs text-slate-400">{toggle.desc}</p>
                </div>
                <input
                  type="checkbox"
                  checked={Boolean(settings[toggle.key])}
                  onChange={(e) => setSettings({ ...settings, [toggle.key]: e.target.checked })}
                  className="mt-1 h-4 w-4 rounded border-white/20 bg-[#070a10] text-cyber-primary focus:ring-0"
                />
              </label>
            ))}
          </div>
        </div>

        {/* Scan Schedule & Domain Whitelists */}
        <div className="space-y-6">
          {/* Scan Schedule */}
          <div className="rounded-2xl border border-cyber-border bg-cyber-card p-5 sm:p-6">
            <h3 className="font-semibold text-white">Scheduled Security Scans</h3>
            <p className="mt-1 text-xs text-slate-400">Configure automated full-system background scan interval.</p>

            <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
              {['manual', 'hourly', 'daily', 'weekly'].map((sched) => (
                <button
                  type="button"
                  key={sched}
                  onClick={() => setSettings({ ...settings, scan_schedule: sched })}
                  className={`rounded-xl border py-2 text-xs font-semibold uppercase tracking-wider transition ${
                    settings.scan_schedule === sched
                      ? 'border-cyber-primary bg-cyber-primary/10 text-cyber-primary'
                      : 'border-white/10 bg-black/20 text-slate-400 hover:text-white'
                  }`}
                >
                  {sched}
                </button>
              ))}
            </div>
          </div>

          {/* Trusted Domains */}
          <div className="rounded-2xl border border-cyber-border bg-cyber-card p-5 sm:p-6">
            <h3 className="font-semibold text-white">Trusted Domains (Whitelist)</h3>
            <p className="mt-1 text-xs text-slate-400">Domains exempted from network and URL filtering.</p>

            <div className="mt-3 flex gap-2">
              <input
                type="text"
                placeholder="example.com"
                value={newTrustedDomain}
                onChange={(e) => setNewTrustedDomain(e.target.value)}
                className="flex-1 rounded-xl border border-white/10 bg-[#070a10]/80 px-3 py-2 text-xs text-white focus:border-cyber-primary focus:outline-none"
              />
              <button
                type="button"
                onClick={addTrustedDomain}
                className="rounded-xl bg-cyber-primary px-3 py-2 text-xs font-bold text-slate-950"
              >
                <Plus className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-3 flex flex-wrap gap-2">
              {settings.trusted_domains?.map((d: string) => (
                <span key={d} className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1 text-xs text-slate-200">
                  {d}
                  <button type="button" onClick={() => removeTrustedDomain(d)} className="text-slate-400 hover:text-cyber-danger">
                    ✕
                  </button>
                </span>
              ))}
            </div>
          </div>

          {/* Blocked Domains */}
          <div className="rounded-2xl border border-cyber-border bg-cyber-card p-5 sm:p-6">
            <h3 className="font-semibold text-white">Blocked Threat Domains (Blacklist)</h3>
            <p className="mt-1 text-xs text-slate-400">Confirmed malicious domains instantly blocked across all platforms.</p>

            <div className="mt-3 flex gap-2">
              <input
                type="text"
                placeholder="malicious-site.org"
                value={newBlockedDomain}
                onChange={(e) => setNewBlockedDomain(e.target.value)}
                className="flex-1 rounded-xl border border-white/10 bg-[#070a10]/80 px-3 py-2 text-xs text-white focus:border-cyber-danger focus:outline-none"
              />
              <button
                type="button"
                onClick={addBlockedDomain}
                className="rounded-xl bg-cyber-danger px-3 py-2 text-xs font-bold text-white"
              >
                <Plus className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-3 flex flex-wrap gap-2">
              {settings.blocked_domains?.map((d: string) => (
                <span key={d} className="inline-flex items-center gap-1.5 rounded-lg border border-cyber-danger/30 bg-cyber-danger/10 px-2.5 py-1 text-xs text-red-200">
                  {d}
                  <button type="button" onClick={() => removeBlockedDomain(d)} className="text-red-400 hover:text-white">
                    ✕
                  </button>
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
