import { useEffect, useState } from 'react'
import { Mail, Send, AlertTriangle, CheckCircle, Link, User } from 'lucide-react'
import { emailAPI } from '../lib/api'
import StatusBadge from '../components/StatusBadge'

export default function EmailSecurity() {
  const [formData, setFormData] = useState({
    sender: '',
    subject: '',
    body: '',
    urls: ''
  })
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [history, setHistory] = useState<Array<{ id: number; sender: string; subject: string; status: string; risk: number; time: string }>>([])
  const [serviceStatus, setServiceStatus] = useState<{ operational: boolean; oauthConfigured: boolean } | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    emailAPI.status()
      .then(({ data }) => setServiceStatus({
        operational: data.status === 'operational' && Boolean(data.enabled),
        oauthConfigured: Boolean(data.oauth_configured),
      }))
      .catch((requestError: unknown) => {
        console.error(requestError)
        setServiceStatus({ operational: false, oauthConfigured: false })
      })
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setScanning(true)
    setResult(null)
    setError('')
    try {
      const urls = formData.urls.split(',').map(u => u.trim()).filter(u => u)
      const response = await emailAPI.scan({
        sender: formData.sender,
        subject: formData.subject,
        body: formData.body,
        urls
      })
      setResult(response.data)
      setHistory(history => [{
        id: Date.now(),
        sender: formData.sender,
        subject: formData.subject,
        status: response.data.is_phishing ? 'phishing' : response.data.risk.score >= 40 ? 'suspicious' : 'safe',
        risk: response.data.risk.score,
        time: 'Just now'
      }, ...history])
    } catch (requestError) {
      console.error(requestError)
      setError('Email analysis failed. Check the backend connection and try again.')
    } finally {
      setScanning(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">Email Security</h2>
        <p className="text-gray-400 text-sm">Phishing detection and email threat analysis</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Mail className="w-5 h-5" />
              Analyze Email
            </h3>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label htmlFor="email-sender" className="block text-sm font-medium mb-2">Sender Email</label>
                <div className="relative">
                  <User className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                  <input
                    id="email-sender"
                    type="email"
                    value={formData.sender}
                    onChange={(e) => setFormData({...formData, sender: e.target.value})}
                    placeholder="sender@example.com"
                    className="w-full pl-10 pr-4 py-2 bg-sentinel-bg border border-sentinel-border rounded focus:outline-none focus:border-sentinel-primary"
                    required
                  />
                </div>
              </div>
              <div>
                <label htmlFor="email-subject" className="block text-sm font-medium mb-2">Subject</label>
                <input
                  id="email-subject"
                  type="text"
                  value={formData.subject}
                  onChange={(e) => setFormData({...formData, subject: e.target.value})}
                  placeholder="Email subject"
                  className="w-full px-4 py-2 bg-sentinel-bg border border-sentinel-border rounded focus:outline-none focus:border-sentinel-primary"
                />
              </div>
              <div>
                <label htmlFor="email-body" className="block text-sm font-medium mb-2">Email Body</label>
                <textarea
                  id="email-body"
                  value={formData.body}
                  onChange={(e) => setFormData({...formData, body: e.target.value})}
                  placeholder="Paste email content here..."
                  rows={6}
                  className="w-full px-4 py-2 bg-sentinel-bg border border-sentinel-border rounded focus:outline-none focus:border-sentinel-primary resize-none"
                />
              </div>
              <div>
                <label htmlFor="email-urls" className="block text-sm font-medium mb-2">URLs (comma separated)</label>
                <div className="relative">
                  <Link className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                  <input
                    id="email-urls"
                    type="text"
                    value={formData.urls}
                    onChange={(e) => setFormData({...formData, urls: e.target.value})}
                    placeholder="https://example.com, https://another.com"
                    className="w-full pl-10 pr-4 py-2 bg-sentinel-bg border border-sentinel-border rounded focus:outline-none focus:border-sentinel-primary"
                  />
                </div>
              </div>
              <button
                type="submit"
                disabled={scanning}
                className="flex items-center gap-2 px-6 py-2 bg-sentinel-primary text-black font-medium rounded hover:bg-sentinel-primary/90 transition-colors disabled:opacity-50"
              >
                <Send className="w-4 h-4" />
                {scanning ? 'Analyzing...' : 'Analyze Email'}
              </button>
            </form>
            <p className="mt-3 text-xs leading-5 text-slate-500">This analyzer accepts sender, subject, body and URLs. Attachments are not accepted or analyzed by the current API.</p>
            {error && <p role="alert" className="mt-4 rounded-lg border border-sentinel-danger/25 bg-sentinel-danger/10 px-4 py-3 text-sm text-red-200">{error}</p>}
          </div>

          {result && (
            <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                {result.is_phishing ? (
                  <AlertTriangle className="w-5 h-5 text-sentinel-danger" />
                ) : result.risk.score >= 40 ? (
                  <AlertTriangle className="w-5 h-5 text-sentinel-warning" />
                ) : (
                  <CheckCircle className="w-5 h-5 text-sentinel-primary" />
                )}
                Analysis Result
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                <div className="p-3 bg-sentinel-bg rounded text-center">
                  <div className={`text-2xl font-bold ${result.risk.score >= 70 ? 'text-sentinel-danger' : result.risk.score >= 40 ? 'text-sentinel-warning' : 'text-sentinel-primary'}`}>
                    {result.risk.score}
                  </div>
                  <div className="text-xs text-gray-400">Risk Score</div>
                </div>
                <div className="p-3 bg-sentinel-bg rounded text-center">
                  <div className="text-sm font-medium">{result.is_phishing ? 'YES' : 'NO'}</div>
                  <div className="text-xs text-gray-400">Phishing</div>
                </div>
                <div className="p-3 bg-sentinel-bg rounded text-center">
                  <div className="text-sm font-medium">{result.spoof_detected ? 'YES' : 'NO'}</div>
                  <div className="text-xs text-gray-400">Spoofing</div>
                </div>
                <div className="p-3 bg-sentinel-bg rounded text-center">
                  <div className={`text-sm font-medium ${result.action === 'block' ? 'text-sentinel-danger' : result.action === 'warn' ? 'text-sentinel-warning' : 'text-sentinel-primary'}`}>
                    {result.action.toUpperCase()}
                  </div>
                  <div className="text-xs text-gray-400">Action</div>
                </div>
              </div>
              {result.reasons && result.reasons.length > 0 && (
                <div className="p-4 bg-sentinel-bg rounded">
                  <div className="text-sm font-medium mb-2">Threat Indicators</div>
                  <ul className="space-y-1">
                    {result.reasons.map((reason: string, i: number) => (
                      <li key={i} className="text-sm text-gray-300 flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 text-sentinel-warning mt-0.5 flex-shrink-0" />
                        {reason}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="space-y-6">
          <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4">Email Protection</h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 bg-sentinel-bg rounded">
                <span className="text-sm">Phishing Detection</span>
                <StatusBadge status={serviceStatus?.operational ? 'active' : serviceStatus ? 'inactive' : 'warning'} text={serviceStatus?.operational ? 'Operational' : serviceStatus ? 'Unavailable' : 'Checking'} />
              </div>
              <div className="flex items-center justify-between p-3 bg-sentinel-bg rounded">
                <span className="text-sm">Spoof Detection</span>
                <StatusBadge status={serviceStatus?.operational ? 'active' : serviceStatus ? 'inactive' : 'warning'} text={serviceStatus?.operational ? 'API enabled' : serviceStatus ? 'Unavailable' : 'Checking'} />
              </div>
              <div className="flex items-center justify-between p-3 bg-sentinel-bg rounded">
                <span className="text-sm">URL Analysis</span>
                <StatusBadge status={serviceStatus?.operational ? 'active' : serviceStatus ? 'inactive' : 'warning'} text={serviceStatus?.operational ? 'API enabled' : serviceStatus ? 'Unavailable' : 'Checking'} />
              </div>
              <div className="flex items-center justify-between p-3 bg-sentinel-bg rounded">
                <span className="text-sm">OAuth Integration</span>
                <StatusBadge status={serviceStatus?.oauthConfigured ? 'active' : 'warning'} text={serviceStatus?.oauthConfigured ? 'Configured' : 'Not configured'} />
              </div>
            </div>
          </div>

          <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4">Scan History</h3>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {history.length === 0 ? <p className="py-4 text-sm text-slate-500">No emails analyzed on this screen yet.</p> : history.map((item) => (
                <div key={item.id} className="p-3 bg-sentinel-bg rounded">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium truncate max-w-[150px]">{item.sender}</span>
                    <StatusBadge
                      status={item.status === 'safe' ? 'ok' : item.status === 'suspicious' ? 'warning' : 'danger'}
                      text={item.status.toUpperCase()}
                    />
                  </div>
                  <p className="text-xs text-gray-400 mb-1 truncate">{item.subject || '(No subject)'}</p>
                  <div className="flex items-center justify-between text-xs text-gray-500">
                    <span>Risk: {item.risk}</span>
                    <span>{item.time}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
